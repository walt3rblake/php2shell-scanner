#!/usr/bin/env python3
"""
Passive, non-destructive version scanner for CVE-2026-109618 / CVE-2026-109619
(PHP core memory-corruption pair, "longjmp OOM" / "stale global state" RCE,
fixed in PHP 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12 — advisories GHSA-w8hw-w9fx-j79w
and GHSA-6wmf-4rv5-p3rp).

WHAT THIS DOES
--------------
Sends ordinary GET requests (homepage + a nonexistent-path 404, since some
stacks only leak version headers on one or the other) and reads whatever
version information the target server *already* discloses:
  - Server / X-Powered-By response headers, on both the homepage and a
    guaranteed-404 page
  - optionally, an accidentally-exposed phpinfo() page at a few common paths
It compares any PHP version found against the fixed versions from the
advisory and reports a best-effort classification. It never uploads
oversized payloads, never aborts workers, never sends anything other than
GET, and never attempts to trigger the OOM/memory-corruption condition
itself. Targets are processed strictly one at a time, in order, with a
delay between them — there is no concurrency flag and none will be added,
by design, so a scan can't hammer a client's site.

WHAT THIS DELIBERATELY DOES NOT DO
-----------------------------------
It does not confirm the bug is actually exploitable on hosts that hide their
PHP version (which is most hardened production servers). That requires an
active probe that intentionally forces an OOM condition on the target
process — which risks crashing a production PHP-FPM/worker pool. That is
out of scope for this script by design. Hosts reported as UNKNOWN need
either (a) the client to tell you their PHP version directly, or (b) a
scoped, authorized active test against a staging/cloned environment with
rollback and monitoring in place — not a scan run against production from
a target list.

Because this is passive-only, treat every non-UNKNOWN result as high
confidence and every UNKNOWN result as "needs a second channel to confirm,"
never as "probably fine."

USAGE
-----
    python php_cve_2026_109618_109619_scanner.py urls.txt
    python php_cve_2026_109618_109619_scanner.py urls.txt --json report.json
    python php_cve_2026_109618_109619_scanner.py https://example.com --check-phpinfo

urls.txt: one URL per line (comments with # allowed, blank lines ignored).

Only point this at hosts you own or are explicitly authorized to test.
"""

import argparse
import json
import random
import re
import string
import sys
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from urllib.parse import urljoin

import requests

# Fixed versions per advisory, keyed by minor branch.
FIXED_VERSIONS = {
    (8, 2): (8, 2, 35),
    (8, 3): (8, 3, 36),
    (8, 4): (8, 4, 27),
    (8, 5): (8, 5, 12),
}

# Branches that are EOL and will never receive a backport for this bug.
EOL_BRANCHES = {(7, 0), (7, 1), (7, 2), (7, 3), (7, 4), (8, 0), (8, 1)}

VERSION_RE = re.compile(r"PHP/(\d+)\.(\d+)\.(\d+)", re.IGNORECASE)
PHPINFO_VERSION_RE = re.compile(r"PHP Version\s*</td><td[^>]*>\s*([\d.]+)", re.IGNORECASE)

DEFAULT_TIMEOUT = 10
MAX_RETRIES = 2  # transient-network-error retries per request, not per target
RETRY_BACKOFF_BASE = 2.0  # seconds, doubles each retry
DEFAULT_UA = "cve-2026-109618-109619-passive-scanner/1.1 (authorized-security-review)"

COMMON_PHPINFO_PATHS = [
    "/phpinfo.php",
    "/info.php",
    "/test.php",
    "/_phpinfo.php",
]


@dataclass
class ScanResult:
    url: str
    status: str  # VULNERABLE, PATCHED, EOL_UNPATCHED, UNKNOWN, ERROR
    php_version: str | None = None
    source: str | None = None  # where the version string came from
    detail: str = ""
    http_status: int | None = None
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


def get_with_retry(session: requests.Session, url: str, timeout: int) -> requests.Response:
    """GET with a couple of retries on transient network errors only.
    Never retries on an HTTP error status (4xx/5xx) — those are a real
    answer from the server, not a transient failure, and retrying them
    adds load for no benefit."""
    last_exc: Exception | None = None
    for attempt in range(MAX_RETRIES + 1):
        try:
            return session.get(
                url, timeout=timeout, allow_redirects=True,
                headers={"User-Agent": DEFAULT_UA},
            )
        except requests.RequestException as e:
            last_exc = e
            if attempt < MAX_RETRIES:
                time.sleep(RETRY_BACKOFF_BASE * (attempt + 1))
    assert last_exc is not None
    raise last_exc


def parse_version(v: str) -> tuple[int, int, int] | None:
    m = re.match(r"(\d+)\.(\d+)\.(\d+)", v)
    if not m:
        return None
    return tuple(int(x) for x in m.groups())  # type: ignore


def classify(version: tuple[int, int, int]) -> tuple[str, str]:
    major, minor, patch = version
    branch = (major, minor)
    if branch in EOL_BRANCHES:
        return "EOL_UNPATCHED", (
            f"PHP {major}.{minor}.x is end-of-life and will not receive a fix for "
            f"this bug class. Upgrade to a supported branch (8.2.35+/8.3.36+/"
            f"8.4.27+/8.5.12+) regardless of exploitability."
        )
    if branch in FIXED_VERSIONS:
        fixed = FIXED_VERSIONS[branch]
        if version < fixed:
            return "VULNERABLE", (
                f"PHP {major}.{minor}.{patch} is below the fixed version "
                f"{'.'.join(map(str, fixed))} for this branch."
            )
        return "PATCHED", (
            f"PHP {major}.{minor}.{patch} is at or above the fixed version "
            f"{'.'.join(map(str, fixed))}."
        )
    # Newer/unknown branch not covered by the advisory at all.
    return "UNKNOWN", f"PHP {major}.{minor}.{patch} is not a branch covered by this advisory."


def extract_version_from_headers(headers) -> tuple[str, str] | None:
    for header_name in ("X-Powered-By", "Server"):
        value = headers.get(header_name, "")
        m = VERSION_RE.search(value)
        if m:
            return f"{m.group(1)}.{m.group(2)}.{m.group(3)}", header_name
    return None


def random_404_path() -> str:
    token = "".join(random.choices(string.ascii_lowercase + string.digits, k=16))
    return f"/__scan404_{token}__"


def try_phpinfo(session: requests.Session, base_url: str, timeout: int) -> tuple[str, str] | None:
    for path in COMMON_PHPINFO_PATHS:
        probe_url = urljoin(base_url, path)
        try:
            resp = get_with_retry(session, probe_url, timeout)
        except requests.RequestException:
            continue
        lowered = resp.text.lower()
        if resp.status_code == 200 and ("phpinfo()" in lowered or "php version" in lowered):
            m = PHPINFO_VERSION_RE.search(resp.text)
            if m:
                return m.group(1), f"exposed phpinfo page ({path})"
    return None


def scan_one(url: str, session: requests.Session, timeout: int, check_phpinfo: bool) -> ScanResult:
    # Data point 1: the homepage.
    try:
        home_resp = get_with_retry(session, url, timeout)
    except requests.RequestException as e:
        return ScanResult(url=url, status="ERROR", detail=f"Request failed after retries: {e}")

    found = extract_version_from_headers(home_resp.headers)
    http_status = home_resp.status_code

    # Data point 2: a guaranteed-404 page. Some stacks only emit
    # X-Powered-By on error pages (or only on real ones), so check both
    # before concluding there's nothing to find. Still a plain GET.
    if not found:
        try:
            probe_404_url = urljoin(url, random_404_path())
            resp_404 = get_with_retry(session, probe_404_url, timeout)
            found = extract_version_from_headers(resp_404.headers)
            if found:
                found = (found[0], f"{found[1]} header on 404 page")
        except requests.RequestException:
            pass  # non-fatal; we already have the homepage result

    # Data point 3 (optional, explicit opt-in): accidental phpinfo exposure.
    if not found and check_phpinfo:
        found = try_phpinfo(session, url, timeout)

    if not found:
        return ScanResult(
            url=url,
            status="UNKNOWN",
            detail=(
                "No PHP version disclosed via Server/X-Powered-By headers on "
                "either the homepage or a 404 page"
                + (", nor via an exposed phpinfo page" if check_phpinfo else "")
                + ". This does NOT mean the host is safe — it means passive "
                "detection is inconclusive. Ask the client directly for their "
                "PHP version, or run a scoped active test against a "
                "staging/cloned copy with explicit authorization."
            ),
            http_status=http_status,
        )

    version_str, source = found
    version = parse_version(version_str)
    if not version:
        return ScanResult(
            url=url, status="UNKNOWN",
            detail=f"Found version-like string '{version_str}' but could not parse it.",
            http_status=http_status,
        )

    status, detail = classify(version)
    return ScanResult(
        url=url, status=status, php_version=version_str, source=source,
        detail=detail, http_status=http_status,
    )


def load_urls(path_or_url: str) -> list[str]:
    if path_or_url.startswith("http://") or path_or_url.startswith("https://"):
        return [path_or_url]
    urls = []
    with open(path_or_url, "r", encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if not line.startswith("http"):
                line = "https://" + line
            urls.append(line)
    return urls


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("target", help="A single URL, or a path to a file with one URL per line.")
    parser.add_argument("--json", metavar="FILE", help="Write full results as JSON to FILE.")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Per-request timeout in seconds.")
    parser.add_argument(
        "--delay", type=float, default=1.5,
        help="Delay in seconds between targets (politeness/rate-limit safety). Targets are "
             "always processed one at a time, in file order; there is no concurrency option.",
    )
    parser.add_argument(
        "--check-phpinfo", action="store_true",
        help="Also GET a few common phpinfo()-exposure paths as a passive fallback.",
    )
    args = parser.parse_args()

    urls = load_urls(args.target)
    if not urls:
        print("No URLs to scan.", file=sys.stderr)
        sys.exit(1)

    session = requests.Session()
    results: list[ScanResult] = []

    for i, url in enumerate(urls):
        print(f"[{i + 1}/{len(urls)}] Scanning {url} ...")
        result = scan_one(url, session, args.timeout, args.check_phpinfo)
        results.append(result)
        marker = {
            "VULNERABLE": "[VULNERABLE]",
            "EOL_UNPATCHED": "[EOL/UNPATCHED]",
            "PATCHED": "[PATCHED]",
            "UNKNOWN": "[UNKNOWN]",
            "ERROR": "[ERROR]",
        }[result.status]
        print(f"{marker:17} {url}")
        if result.php_version:
            print(f"                  PHP {result.php_version} (via {result.source})")
        print(f"                  {result.detail}")
        if i < len(urls) - 1 and args.delay:
            time.sleep(args.delay)

    vulnerable = [r for r in results if r.status in ("VULNERABLE", "EOL_UNPATCHED")]
    unknown = [r for r in results if r.status == "UNKNOWN"]
    print("\n--- Summary ---")
    print(f"Scanned: {len(results)}")
    print(f"Confirmed vulnerable / EOL (needs patch regardless): {len(vulnerable)}")
    print(f"Confirmed patched: {len([r for r in results if r.status == 'PATCHED'])}")
    print(f"Unknown / needs manual follow-up: {len(unknown)}")
    print(f"Errors: {len([r for r in results if r.status == 'ERROR'])}")
    if unknown:
        print("\nFollow up manually on UNKNOWN targets before telling anyone they're safe:")
        for r in unknown:
            print(f"  - {r.url}")

    if args.json:
        with open(args.json, "w", encoding="utf-8") as f:
            json.dump([asdict(r) for r in results], f, indent=2)
        print(f"\nFull results written to {args.json}")


if __name__ == "__main__":
    main()
