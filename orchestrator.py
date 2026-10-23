#!/usr/bin/env python3
"""
php2shell orchestrator — small-scale, single-purpose scanner for
CVE-2026-109618 / CVE-2026-109619 (PHP core memory-corruption RCE pair,
fixed in 8.2.35 / 8.3.36 / 8.4.27 / 8.5.12).

Identifies the PHP version as reliably as possible using multiple
independent, well-known, passive/non-destructive tools, then cross-checks
their answers against each other before concluding anything. No
exploitation, no OOM triggers, no payload injection.

Runs six layers against each target, strictly one target at a time:

  1. version_check     — scanner.py's own header/404/phpinfo PHP-version
                          checks (our code, simplest layer)
  2. webtech            — Wappalyzer-database passive tech fingerprinting
  3. wapiti (wapp module only) — Wapiti's own Wappalyzer-based fingerprint
                          + its bundled CVE cross-reference. Only the
                          passive `wapp` module is run — never Wapiti's
                          crawling/injection modules.
  4. nmap -sV            — service/version detection
  5. nmap vulners+vulscan — CVE correlation against the detected
                          service/version (vulners = live API against
                          vulners.com/NVD; vulscan = offline CSVs, DB is
                          stale since its refresh step needs Kali, which
                          this setup doesn't touch)
  6. cmseek (light-scan) — identifies the CMS (WordPress/Joomla/Drupal/
                          180+ others) and its OWN core version. This
                          does NOT detect the PHP interpreter version —
                          CMSeeK has no concept of that — but it feeds
                          detected_technologies, which is what lets
                          reconcile() recognize "this is WordPress, which
                          implies PHP" even when webtech/wapiti's own
                          fingerprint databases didn't tag it. Always run
                          as --light-scan (CMS + version ID, ~1 request)
                          by default; CMSeeK's deep scan (plugin/theme/
                          user enumeration, backup-file finder, admin-page
                          finder, config-leak detection) is opt-in only
                          via --cmseek-deepscan, since it actively probes
                          many paths per target.

All five produce a PHP version independently where possible. If any two
of them disagree on the version seen for the same target, that's flagged
explicitly in the report (`version_agreement`) rather than silently
picking one — the whole point of running several tools is to catch that
kind of disagreement, not paper over it.

WHY NOT NIKTO, AND WHY WAPITI IS LIMITED TO ONE MODULE
--------------------------------------------------------
Nikto and Wapiti's attack modules (sqli/xss/backup-file-brute/etc.) are
signature/attack-pattern-driven. This CVE pair is too new for any public
tool to have specific rules for it, so running those modules adds load
and risk (this session's own safety layer also blocks firing Nikto, or
likely Wapiti's attack modules, at live targets) without adding detection
value for *this* bug. Wapiti's `wapp` module is the exception: it's a
passive fingerprint, same risk profile as webtech, just a second
independent implementation worth cross-checking against the first.

If you have Nikto or Wapiti installed and want broader vulnerability
scanning for a target, run them separately and deliberately — neither is
invoked by this script beyond Wapiti's one `wapp` module. Same reasoning
applies to CMSeeK's deep scan: it's fully capable of plugin/theme/user
enumeration, but that's not this script's default behavior either.

USAGE
-----
    python orchestrator.py urls.txt --json report.json

Processes targets strictly sequentially (no concurrency, ever) with a
delay between them. Only point this at hosts you own or are explicitly
authorized to test.
"""

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from urllib.parse import urlparse

sys.path.insert(0, str(__file__.rsplit("\\", 1)[0] if "\\" in __file__ else "."))
import scanner as version_scanner  # our existing passive PHP-version scanner


def _resolve_tool_path(env_var: str, which_names: list[str], windows_fallbacks: list[str] = None) -> str | None:
    """Resolve an external tool's path with this priority:
    1. Explicit environment variable override (documented in README) —
       always wins, so anyone can point this at a non-standard install
       without editing the script.
    2. PATH lookup (shutil.which) — works out of the box after a normal
       `pip install` / package-manager install on most systems.
    3. A short list of common Windows install locations, since several of
       these tools (nmap, wapiti, webtech) don't always land on PATH after
       a Windows install even when step 2 would find them on Linux/macOS.
    Returns None — not a guessed path — if nothing matches, so the
    pre-flight check can report MISSING honestly instead of silently
    pointing at a path that doesn't exist on this machine."""
    override = os.environ.get(env_var)
    if override:
        return override
    for name in which_names:
        found = shutil.which(name)
        if found:
            return found
    if platform.system() == "Windows":
        for path in windows_fallbacks or []:
            if os.path.isfile(path):
                return path
    return None


NMAP_PATH = _resolve_tool_path(
    "PHP2SHELL_NMAP_PATH", ["nmap"],
    windows_fallbacks=[r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"],
)
WAPITI_PATH = _resolve_tool_path("PHP2SHELL_WAPITI_PATH", ["wapiti"])
WEBTECH_PATH = _resolve_tool_path("PHP2SHELL_WEBTECH_PATH", ["webtech"])
CMSEEK_PATH = os.environ.get("PHP2SHELL_CMSEEK_PATH")  # no PATH lookup — it's a cloned script, not an installed binary
CMSEEK_DIR = os.path.dirname(CMSEEK_PATH) if CMSEEK_PATH else None
VULSCAN_NSE_PATH = os.environ.get("PHP2SHELL_VULSCAN_NSE_PATH")  # see README: Windows needs the full .nse path, not the bare script name

# Every external tool this script calls, by full path, so a tool missing
# from PATH in whatever shell this is run from fails loudly at startup
# instead of silently-fast mid-scan (this bit us once during testing: a
# throwaway shell without PATH set made webtech fail in ~30ms, which looked
# exactly like a real-but-too-fast scan if you weren't checking stderr).
REQUIRED_TOOLS = {
    "nmap": (NMAP_PATH, "PHP2SHELL_NMAP_PATH"),
    "wapiti": (WAPITI_PATH, "PHP2SHELL_WAPITI_PATH"),
    "webtech": (WEBTECH_PATH, "PHP2SHELL_WEBTECH_PATH"),
    "cmseek": (CMSEEK_PATH, "PHP2SHELL_CMSEEK_PATH"),
}


def preflight_check_tools(skip_nmap: bool, skip_wapiti: bool, skip_cmseek: bool) -> bool:
    print("--- Tool pre-flight check ---")
    all_ok = True
    for name, (path, env_var) in REQUIRED_TOOLS.items():
        if name == "nmap" and skip_nmap:
            print(f"  [SKIP] {name} (--skip-nmap)")
            continue
        if name == "wapiti" and skip_wapiti:
            print(f"  [SKIP] {name} (--skip-wapiti)")
            continue
        if name == "cmseek" and skip_cmseek:
            print(f"  [SKIP] {name} (--skip-cmseek)")
            continue
        ok = bool(path) and os.path.isfile(path)
        if ok:
            print(f"  [OK] {name} -> {path}")
        else:
            print(f"  [MISSING] {name} -> not found on PATH. Set the {env_var} environment "
                  f"variable to its full path, or install it and ensure it's on PATH. See README.md.")
        all_ok = all_ok and ok
    print("")
    return all_ok

WEBTECH_TIMEOUT = 20
WAPITI_TIMEOUT = 150  # CDN-fronted sites (CloudFront etc.) can be noticeably slower; 90s timed out in practice
NMAP_TIMEOUT = 90
CMSEEK_TIMEOUT = 60  # light-scan is 1-3 requests, should be fast; generous margin for slow targets

# Info-gathering + CVE-correlation scripts, built dynamically. This matters
# for portability: nmap doesn't skip an unresolvable script name in a
# --script list, it fails the ENTIRE invocation (we hit this exact failure
# mode with a bare "vulscan" on Windows — "QUITTING!", not a partial skip).
# vulners/vulscan are optional installs (see README), so detect what's
# actually available and only request those, instead of hardcoding them and
# breaking the whole nmap layer for anyone who hasn't installed them.
def _detect_nmap_scripts() -> str:
    base = "http-server-header,http-title,http-generator,ssl-cert"  # ship with every nmap install
    if not NMAP_PATH or not os.path.isfile(NMAP_PATH):
        return base
    extra = []
    try:
        r = subprocess.run([NMAP_PATH, "--script-help", "vulners"], capture_output=True, text=True, timeout=10)
        if "vulners" in (r.stdout or "").lower():
            extra.append("vulners")
    except Exception:
        pass
    if VULSCAN_NSE_PATH and os.path.isfile(VULSCAN_NSE_PATH):
        try:
            r = subprocess.run([NMAP_PATH, "--script-help", VULSCAN_NSE_PATH], capture_output=True, text=True, timeout=10)
            if "vulscan" in (r.stdout or "").lower():
                extra.append(VULSCAN_NSE_PATH)
        except Exception:
            pass
    return base + ("," + ",".join(extra) if extra else "")


NMAP_SCRIPTS = _detect_nmap_scripts()


@dataclass
class TargetReport:
    url: str
    host: str
    version_check: dict = field(default_factory=dict)
    webtech: dict = field(default_factory=dict)
    wapiti: dict = field(default_factory=dict)
    nmap: dict = field(default_factory=dict)
    cmseek: dict = field(default_factory=dict)
    php_versions_seen: dict = field(default_factory=dict)  # source -> version string
    detected_technologies: dict = field(default_factory=dict)  # source -> [{name, version}, ...]
    version_agreement: str = "N/A"  # AGREE, DISAGREE, SINGLE_SOURCE, NO_VERSION_FOUND
    overall_status: str = "UNKNOWN"
    client_summary: str = ""  # plain-English, for sharing with a non-technical client
    sapi_priority: str = "N/A"  # HIGH_PRIORITY/MEDIUM_PRIORITY/LOWER_PRIORITY/N/A — see SAPI_RISK_TABLE
    checked_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ---------------------------------------------------------------------------
# Layer 1: our own version_check (scanner.py)
# ---------------------------------------------------------------------------

def run_version_check(url: str, check_phpinfo: bool) -> dict:
    import requests
    session = requests.Session()
    start = time.perf_counter()
    try:
        result = version_scanner.scan_one(url, session, version_scanner.DEFAULT_TIMEOUT, check_phpinfo)
        out = asdict(result)
        out["elapsed_seconds"] = round(time.perf_counter() - start, 2)
        return out
    except Exception as e:
        return {"status": "ERROR", "detail": f"version_check crashed: {e}",
                 "elapsed_seconds": round(time.perf_counter() - start, 2)}


# ---------------------------------------------------------------------------
# Layer 2: webtech
# ---------------------------------------------------------------------------

def run_webtech(url: str) -> dict:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            [WEBTECH_PATH, "-u", url, "--json"],
            capture_output=True, text=True, timeout=WEBTECH_TIMEOUT,
        )
        elapsed = round(time.perf_counter() - start, 2)
        out = proc.stdout.strip()
        idx = out.find("{")
        if idx == -1:
            return {"status": "ERROR", "detail": "webtech produced no JSON",
                     "raw": out[-500:], "stderr": proc.stderr[-500:], "elapsed_seconds": elapsed}
        parsed = json.loads(out[idx:])
        return {"status": "OK", "technologies": parsed, "elapsed_seconds": elapsed}
    except subprocess.TimeoutExpired:
        return {"status": "ERROR", "detail": f"webtech timed out after {WEBTECH_TIMEOUT}s",
                 "elapsed_seconds": round(time.perf_counter() - start, 2)}
    except Exception as e:
        return {"status": "ERROR", "detail": f"webtech failed: {e}",
                 "elapsed_seconds": round(time.perf_counter() - start, 2)}


def extract_php_version_from_webtech(webtech_result: dict) -> str | None:
    techs = webtech_result.get("technologies", {})
    for _url, data in techs.items():
        for tech in data.get("tech", []):
            if tech.get("name", "").lower() == "php" and tech.get("version"):
                return tech["version"]
    return None


def extract_all_tech_from_webtech(webtech_result: dict) -> list[dict]:
    """All detected technologies (not just PHP) — same shape as
    extract_all_tech_from_wapiti so the two can be merged for reporting."""
    out = []
    techs = webtech_result.get("technologies", {})
    for _url, data in techs.items():
        for tech in data.get("tech", []):
            out.append({"name": tech.get("name"), "version": tech.get("version")})
    return out


# ---------------------------------------------------------------------------
# Layer 3: wapiti (wapp module ONLY — passive fingerprint, no attack modules)
# ---------------------------------------------------------------------------

def run_wapiti_wapp(url: str) -> dict:
    tmp_path = os.path.join(tempfile.gettempdir(), f"wapiti_{abs(hash(url))}.json")
    env = dict(os.environ)
    env["PYTHONUTF8"] = "1"
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            [WAPITI_PATH, "-u", url, "-m", "wapp", "--flush-session",
             "-f", "json", "-o", tmp_path],
            capture_output=True, text=True, timeout=WAPITI_TIMEOUT, env=env,
        )
        elapsed = round(time.perf_counter() - start, 2)
        if not os.path.exists(tmp_path):
            return {"status": "ERROR", "detail": "wapiti produced no JSON report",
                     "stderr": proc.stderr[-500:], "elapsed_seconds": elapsed}
        with open(tmp_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        os.remove(tmp_path)
        return {"status": "OK", "report": data, "elapsed_seconds": elapsed}
    except subprocess.TimeoutExpired:
        return {"status": "ERROR", "detail": f"wapiti timed out after {WAPITI_TIMEOUT}s",
                 "elapsed_seconds": round(time.perf_counter() - start, 2)}
    except Exception as e:
        return {"status": "ERROR", "detail": f"wapiti failed: {e}",
                 "elapsed_seconds": round(time.perf_counter() - start, 2)}


def _iter_wapiti_fingerprints(wapiti_result: dict):
    """Fingerprint entries show up under a couple of different category
    names depending on how wapp classified them (web technology / web
    server / web application framework) — check all three rather than
    assuming one."""
    report = wapiti_result.get("report", {})
    for category in ("additionals", "vulnerabilities"):
        bucket = report.get(category, {})
        for key in ("Fingerprint web technology", "Fingerprint web server",
                    "Fingerprint web application framework"):
            for entry in bucket.get(key, []):
                try:
                    yield json.loads(entry.get("info", "{}"))
                except json.JSONDecodeError:
                    continue


def extract_php_version_from_wapiti(wapiti_result: dict) -> str | None:
    for info in _iter_wapiti_fingerprints(wapiti_result):
        if info.get("name", "").lower() == "php" and info.get("versions"):
            return info["versions"][0]
    return None


def extract_all_tech_from_wapiti(wapiti_result: dict) -> list[dict]:
    seen = set()
    out = []
    for info in _iter_wapiti_fingerprints(wapiti_result):
        name = info.get("name")
        versions = info.get("versions") or [None]
        key = (name, versions[0])
        if name and key not in seen:
            seen.add(key)
            out.append({"name": name, "version": versions[0]})
    return out


# ---------------------------------------------------------------------------
# Layer 4 + 5: nmap -sV + vulners/vulscan CVE correlation
# ---------------------------------------------------------------------------

def run_nmap(host: str) -> dict:
    start = time.perf_counter()
    try:
        proc = subprocess.run(
            [NMAP_PATH, "-Pn", "-p", "80,443", "-sV", "--script", NMAP_SCRIPTS, host],
            capture_output=True, text=True, timeout=NMAP_TIMEOUT,
        )
        return {"status": "OK", "raw_output": proc.stdout,
                "elapsed_seconds": round(time.perf_counter() - start, 2)}
    except subprocess.TimeoutExpired:
        return {"status": "ERROR", "detail": f"nmap timed out after {NMAP_TIMEOUT}s",
                 "elapsed_seconds": round(time.perf_counter() - start, 2)}
    except Exception as e:
        return {"status": "ERROR", "detail": f"nmap failed: {e}",
                 "elapsed_seconds": round(time.perf_counter() - start, 2)}


def extract_php_version_from_nmap(nmap_result: dict) -> str | None:
    m = re.search(r"PHP/(\d+\.\d+\.\d+)", nmap_result.get("raw_output", ""), re.IGNORECASE)
    return m.group(1) if m else None


# ---------------------------------------------------------------------------
# Layer 6: CMSeeK — CMS identification + version (NOT PHP interpreter
# version; this confirms WordPress/Joomla/Drupal/etc. core version via its
# own detection methods, which feeds the PHP_IMPLYING_TECH check in
# reconcile() so a CMS that implies PHP is caught even if webtech/wapiti
# missed it). Always run with --light-scan: CMS + version detection only,
# a single request in practice — never CMSeeK's deep scan (plugin/theme/
# user enumeration, backup-file finder, admin-page finder, config-leak
# detection), which actively probes many paths and is a meaningfully
# bigger action than anything else in this pipeline. That's available as
# an explicit opt-in (--cmseek-deepscan) for one target at a time, never
# as this script's default behavior.
# ---------------------------------------------------------------------------

def _cmseek_result_dir_name(url: str) -> str:
    """Exactly replicates CMSeeK's own cmseekdb/basic.py init_result_dir()
    sanitization so we can find its output file without guessing."""
    u = url
    if "http://" in u:
        u = u.replace("http://", "")
    elif "https://" in u:
        u = u.replace("https://", "")
    if u.endswith("/"):
        u = u[:-1]
    for ch in "/!?#@&%\\*:":
        u = u.replace(ch, "_")
    return u


def run_cmseek(url: str, deep_scan: bool = False) -> dict:
    target = url if url.endswith("/") else url + "/"
    result_dir_name = _cmseek_result_dir_name(target)
    json_path = os.path.join(CMSEEK_DIR, "Result", result_dir_name, "cms.json")
    start = time.perf_counter()
    args = [sys.executable, CMSEEK_PATH, "-u", target, "--batch"]
    if not deep_scan:
        args.append("--light-scan")
    try:
        proc = subprocess.run(
            args, capture_output=True, text=True, timeout=CMSEEK_TIMEOUT, cwd=CMSEEK_DIR,
        )
        elapsed = round(time.perf_counter() - start, 2)
        if not os.path.isfile(json_path):
            return {"status": "ERROR", "detail": "cmseek produced no cms.json",
                     "stderr": proc.stderr[-500:], "elapsed_seconds": elapsed}
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not data.get("cms_id"):
            return {"status": "OK", "cms_detected": False, "elapsed_seconds": elapsed}
        return {"status": "OK", "cms_detected": True, "report": data, "elapsed_seconds": elapsed}
    except subprocess.TimeoutExpired:
        return {"status": "ERROR", "detail": f"cmseek timed out after {CMSEEK_TIMEOUT}s",
                 "elapsed_seconds": round(time.perf_counter() - start, 2)}
    except Exception as e:
        return {"status": "ERROR", "detail": f"cmseek failed: {e}",
                 "elapsed_seconds": round(time.perf_counter() - start, 2)}


def extract_tech_from_cmseek(cmseek_result: dict) -> list[dict]:
    if not cmseek_result.get("cms_detected"):
        return []
    report = cmseek_result.get("report", {})
    name = report.get("cms_name")
    version = report.get("cms_version") or None
    if not name:
        return []
    return [{"name": name, "version": version if version != "0" else None}]


# ---------------------------------------------------------------------------
# Cross-check all sources instead of trusting any single one
# ---------------------------------------------------------------------------

# Software that IS PHP (built on it / requires it to run), even though its
# own name isn't "PHP" — a tech-fingerprint DB tags "WordPress", not "PHP",
# even though WordPress cannot run without PHP. Missing this caused a real
# bug: a WordPress/WooCommerce/WPBakery site got classified NOT_PHP and the
# client summary said it was "not vulnerable... since those only affect
# PHP" — which was simply wrong. This list has to be checked BEFORE ever
# concluding NOT_PHP, not after.
PHP_IMPLYING_TECH = {
    # CMS
    "wordpress", "wordpress block editor", "joomla", "drupal", "typo3",
    "concrete5", "concrete cms", "modx", "silverstripe", "craft cms",
    "expressionengine", "contao", "xoops", "e107", "textpattern",
    # E-commerce
    "magento", "woocommerce", "prestashop", "opencart", "oscommerce",
    "zen cart", "shopware",
    # Forums / community
    "phpbb", "vbulletin", "smf", "simple machines forum", "mybb",
    "invision community", "ips community suite",
    # Frameworks
    "laravel", "symfony", "codeigniter", "cakephp", "yii", "yii framework",
    "zend framework", "laminas", "phalcon", "slim", "fuelphp",
    # Other well-known PHP applications
    "phpmyadmin", "roundcube", "squirrelmail", "matomo", "piwik",
    "nextcloud", "owncloud", "mautic", "suitecrm", "sugarcrm", "vtiger",
    "osticket", "mantisbt", "limesurvey", "dolibarr", "mediawiki", "moodle",
    # Common WordPress/PHP-ecosystem plugins — detecting these without the
    # parent CMS tag is itself still strong PHP evidence
    "wpbakery", "elementor", "elementor pro", "yoast seo", "wp rocket",
    "wp super cache", "w3 total cache", "contact form 7", "gravity forms",
    "wpforms", "jetpack", "all in one seo", "rank math", "advanced custom fields",
    "buddypress", "bbpress",
}

# Confidently-different backend platforms. NOT_PHP is only returned when
# one of THESE is seen — not merely "PHP wasn't in the list", which is too
# weak a signal (see PHP_IMPLYING_TECH above for why).
NON_PHP_BACKEND_TECH = {
    "asp.net", "asp.net core", ".net", ".net core", "iis",
    "express", "express.js", "node.js", "nodejs", "next.js", "nuxt.js",
    "django", "flask", "fastapi", "ruby on rails", "rails",
    "spring", "spring boot", "tomcat", "jsp", "java servlet", "java",
    "coldfusion", "lotus domino", "play framework",
}

# Sourced directly from the two PHP security advisories' own "affected
# configurations / SAPIs" sections (GHSA-w8hw-w9fx-j79w, GHSA-6wmf-4rv5-p3rp)
# — NOT a guess. Both advisories explicitly state there is no safe,
# non-crashing way to confirm vulnerability remotely beyond comparing the
# version number, and explicitly warn against crafting requests that would
# test the real condition. This table does NOT confirm or rule out
# vulnerability — it only tells you which hidden-version sites are running
# the configuration the advisories call more directly exposed, so you can
# prioritize which ones to chase a PHP version for first.
#
# Matched against the lowercased web-server tech name (substring match).
# (substring, priority, note-for-the-client)
SAPI_RISK_TABLE = [
    ("apache", "HIGH_PRIORITY",
     "This site's web server is Apache. Per the PHP security advisory, "
     "Apache/mod_php is the configuration CONFIRMED as most directly "
     "exposed to this bug (its shutdown path runs even when request "
     "startup fails) — worth prioritizing for manual PHP-version "
     "confirmation ahead of other hidden-version sites."),
    ("nginx", "MEDIUM_PRIORITY",
     "This site's web server is nginx, which typically fronts PHP-FPM. "
     "The advisory calls FPM only CONDITIONALLY exposed (depends on "
     "specific frontend configuration) — lower urgency than a confirmed "
     "Apache/mod_php site, but still needs the PHP version confirmed."),
    ("litespeed", "MEDIUM_PRIORITY",
     "This site's web server is LiteSpeed (LSAPI). The advisory treats "
     "this as conditionally exposed by analogy to PHP-FPM, though it "
     "wasn't independently validated."),
    ("frankenphp", "LOWER_PRIORITY",
     "This site runs FrankenPHP. The advisory found no early-consumer "
     "exposure path in its default configuration — lower priority, "
     "though the advisory does not call this configuration immune."),
]


def sapi_risk_note(detected_technologies: dict) -> tuple[str, str] | None:
    """Returns (priority_label, note) if a known web-server stack was
    fingerprinted, else None. Only meaningful when PHP is known/implied
    but its version is hidden — this is a triage aid, not a verdict."""
    all_names = set()
    for tech_list in detected_technologies.values():
        for tech in tech_list:
            name = (tech.get("name") or "").lower()
            if name:
                all_names.add(name)
    for substring, priority, note in SAPI_RISK_TABLE:
        if any(substring in name for name in all_names):
            return priority, note
    return None


def reconcile(versions_seen: dict, detected_technologies: dict) -> tuple[str, str]:
    """versions_seen: {source_name: version_string_or_None}.
    detected_technologies: {source_name: [{name, version}, ...]} — the FULL
    tech stack each tool saw, not just PHP, used to tell "definitely not
    running PHP" apart from "might be PHP, just didn't disclose a version".
    Returns (overall_status, agreement_label)."""
    found = {src: v for src, v in versions_seen.items() if v}

    if found:
        distinct = set(found.values())
        if len(distinct) > 1:
            # Sources disagree — do not guess. Report every version seen
            # and let a human resolve it instead of silently picking one.
            return "UNKNOWN", f"DISAGREE: {found}"

        version_str = distinct.pop()
        parsed = version_scanner.parse_version(version_str)
        if not parsed:
            return "UNKNOWN", f"UNPARSEABLE_VERSION: {version_str}"

        status, _ = version_scanner.classify(parsed)
        agreement = "AGREE" if len(found) > 1 else "SINGLE_SOURCE"
        return status, agreement

    # No version string anywhere. Figure out what IS known before
    # concluding anything.
    all_tech_names = set()
    for tech_list in detected_technologies.values():
        for tech in tech_list:
            name = (tech.get("name") or "").lower()
            if name:
                all_tech_names.add(name)

    php_implied = all_tech_names & PHP_IMPLYING_TECH
    if "php" in all_tech_names or php_implied:
        label = "php" if "php" in all_tech_names else sorted(php_implied)
        return "UNKNOWN", f"PHP_DETECTED_VERSION_HIDDEN: {label}"

    non_php_backend = all_tech_names & NON_PHP_BACKEND_TECH
    if non_php_backend:
        # Positive evidence of a DIFFERENT backend platform — this is the
        # only case allowed to produce NOT_PHP.
        return "NOT_PHP", f"OTHER_BACKEND_DETECTED: {sorted(non_php_backend)}"

    if all_tech_names:
        # Something was fingerprinted, but it's all frontend/CDN/analytics
        # noise (Google Tag Manager, Cloudflare, HSTS, ...) — that tells us
        # NOTHING about the backend language. Do not guess NOT_PHP from
        # silence; this was the exact shape of the WordPress bug.
        return "UNKNOWN", f"NO_BACKEND_SIGNAL: {sorted(all_tech_names)}"

    return "UNKNOWN", "NO_VERSION_FOUND"


# ---------------------------------------------------------------------------
# Plain-English summary — this is the line meant for a non-technical client,
# not the technical status code.
# ---------------------------------------------------------------------------

# Names that show up in tech fingerprints but aren't useful to lead with
# when describing "what stack is this" to a client (OS, CDN, generic infra).
_GENERIC_TECH_NAMES = {
    "ubuntu", "debian", "centos", "red hat", "windows server", "alpine linux",
    "bunny", "cloudflare", "akamai", "fastly", "amazon web services", "aws",
    "google cloud", "azure", "hsts", "varnish",
}


def _matching_tech_names(detected_technologies: dict, lowercase_set: set) -> list[str]:
    """Original-casing display names from detected_technologies whose
    lowercased form is in lowercase_set, de-duplicated."""
    names = []
    seen_lower = set()
    for tech_list in detected_technologies.values():
        for tech in tech_list:
            name = tech.get("name")
            if not name or name.lower() in seen_lower or name.lower() not in lowercase_set:
                continue
            seen_lower.add(name.lower())
            names.append(name)
    return sorted(names)


def pick_primary_tech_name(detected_technologies: dict) -> str:
    """Fallback generic picker — not used for NOT_PHP anymore (that now
    uses the NON_PHP_BACKEND_TECH match directly), kept for any status
    where we just want *something* descriptive to show."""
    names = []
    seen_lower = set()
    for tech_list in detected_technologies.values():
        for tech in tech_list:
            name = tech.get("name")
            if not name or name.lower() in seen_lower:
                continue
            seen_lower.add(name.lower())
            names.append(name)
    specific = [n for n in names if n.lower() not in _GENERIC_TECH_NAMES]
    chosen = specific or names
    return ", ".join(sorted(chosen)) if chosen else "an unidentified technology"


def build_client_summary(status: str, agreement: str, php_versions_seen: dict,
                          detected_technologies: dict) -> str:
    """One plain-English sentence for a non-technical client — this is the
    field meant to be read aloud or pasted into an email, not the status
    code or the raw tool output."""
    found = {k: v for k, v in php_versions_seen.items() if v}
    version_str = next(iter(found.values()), None)

    if status == "VULNERABLE":
        return (
            f"This site is running PHP {version_str}, which IS VULNERABLE to "
            f"CVE-2026-109618 / CVE-2026-109619 (a critical PHP security flaw). "
            f"Recommend upgrading PHP to a patched version as soon as possible."
        )
    if status == "PATCHED":
        return (
            f"This site is running PHP {version_str}, which is already "
            f"patched against CVE-2026-109618 / CVE-2026-109619. No action "
            f"needed for this specific issue."
        )
    if status == "EOL_UNPATCHED":
        return (
            f"This site is running PHP {version_str}, a version that is no "
            f"longer supported and will NOT receive a fix for "
            f"CVE-2026-109618 / CVE-2026-109619. Recommend upgrading to a "
            f"supported PHP version regardless of this specific issue."
        )
    if status == "NOT_PHP":
        backend_names = _matching_tech_names(detected_technologies, NON_PHP_BACKEND_TECH)
        tech_name = ", ".join(backend_names) if backend_names else "a non-PHP technology"
        return (
            f"This site appears to be running {tech_name}, not PHP. It is "
            f"NOT VULNERABLE to CVE-2026-109618 / CVE-2026-109619, since "
            f"those only affect PHP."
        )
    if status == "UNKNOWN":
        if agreement.startswith("PHP_DETECTED_VERSION_HIDDEN"):
            cms_names = [n for n in _matching_tech_names(detected_technologies, PHP_IMPLYING_TECH)]
            if cms_names:
                cms_str = ", ".join(cms_names)
                base = (
                    f"This site is running {cms_str}, which runs on PHP, but "
                    f"the specific PHP version could not be confirmed "
                    f"remotely. Recommend asking the client (or their host) "
                    f"to check the PHP version and update it if it's below "
                    f"the patched release."
                )
            else:
                base = (
                    "This site is running PHP, but the specific version could "
                    "not be confirmed remotely (the server hides that detail, "
                    "which is itself good practice). Recommend asking the "
                    "client to check their PHP version directly and update it "
                    "if it's below the patched release."
                )
            risk = sapi_risk_note(detected_technologies)
            if risk:
                base = base + " " + risk[1]
            return base
        if agreement.startswith("DISAGREE"):
            return (
                "Different scanning tools reported different PHP versions "
                "for this site — results conflict and should not be trusted "
                "as-is. Needs manual verification before advising the "
                "client either way."
            )
        if agreement.startswith("NO_BACKEND_SIGNAL"):
            return (
                "Some technologies were detected on this site (CDN, "
                "analytics, etc.), but nothing that reveals the backend "
                "language — it could still be PHP underneath. Recommend "
                "asking the client directly rather than assuming either way."
            )
        return (
            "Could not confidently identify the technology running on this "
            "site from the outside. Recommend asking the client directly, "
            "or a closer manual check."
        )
    if status == "ERROR":
        return (
            "The scan could not reach this site (connection, DNS, or "
            "timeout error) — this is a scan/connectivity problem, not a "
            "security finding. Verify the URL and try again."
        )
    return "Unable to generate a summary for this result."


def scan_target(url: str, check_phpinfo: bool, skip_nmap: bool, skip_wapiti: bool,
                 skip_cmseek: bool, cmseek_deepscan: bool) -> TargetReport:
    host = urlparse(url).hostname or url
    report = TargetReport(url=url, host=host)

    print("  -> version_check (scanner.py) ...")
    report.version_check = run_version_check(url, check_phpinfo)
    print(f"     done in {report.version_check.get('elapsed_seconds', '?')}s, status={report.version_check.get('status')}")

    print("  -> webtech ...")
    report.webtech = run_webtech(url)
    print(f"     done in {report.webtech.get('elapsed_seconds', '?')}s, status={report.webtech.get('status')}")

    if skip_wapiti:
        report.wapiti = {"status": "SKIPPED"}
    else:
        print("  -> wapiti (wapp module only) ...")
        report.wapiti = run_wapiti_wapp(url)
        print(f"     done in {report.wapiti.get('elapsed_seconds', '?')}s, status={report.wapiti.get('status')}")

    if skip_nmap:
        report.nmap = {"status": "SKIPPED"}
    else:
        print("  -> nmap -sV + vulners/vulscan ...")
        report.nmap = run_nmap(host)
        print(f"     done in {report.nmap.get('elapsed_seconds', '?')}s, status={report.nmap.get('status')}")

    if skip_cmseek:
        report.cmseek = {"status": "SKIPPED"}
    else:
        label = "deep scan" if cmseek_deepscan else "light scan"
        print(f"  -> cmseek ({label}) ...")
        report.cmseek = run_cmseek(url, deep_scan=cmseek_deepscan)
        print(f"     done in {report.cmseek.get('elapsed_seconds', '?')}s, status={report.cmseek.get('status')}")

    report.php_versions_seen = {
        "version_check": report.version_check.get("php_version"),
        "webtech": extract_php_version_from_webtech(report.webtech),
        "wapiti": extract_php_version_from_wapiti(report.wapiti) if report.wapiti.get("status") == "OK" else None,
        "nmap": extract_php_version_from_nmap(report.nmap) if report.nmap.get("status") == "OK" else None,
        # cmseek deliberately omitted — it detects CMS core version, never the
        # PHP interpreter version, so it has nothing to contribute here.
    }
    report.detected_technologies = {
        "webtech": extract_all_tech_from_webtech(report.webtech) if report.webtech.get("status") == "OK" else [],
        "wapiti": extract_all_tech_from_wapiti(report.wapiti) if report.wapiti.get("status") == "OK" else [],
        "cmseek": extract_tech_from_cmseek(report.cmseek) if report.cmseek.get("status") == "OK" else [],
    }

    report.overall_status, report.version_agreement = reconcile(
        report.php_versions_seen, report.detected_technologies
    )
    report.client_summary = build_client_summary(
        report.overall_status, report.version_agreement,
        report.php_versions_seen, report.detected_technologies,
    )
    if report.overall_status == "UNKNOWN" and report.version_agreement.startswith("PHP_DETECTED_VERSION_HIDDEN"):
        risk = sapi_risk_note(report.detected_technologies)
        report.sapi_priority = risk[0] if risk else "N/A"
    return report


def load_urls(path: str) -> list[str]:
    urls = []
    with open(path, "r", encoding="utf-8") as f:
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
    parser.add_argument("urls_file", help="Path to urls.txt (one target per line).")
    parser.add_argument("--json", metavar="FILE", default="report.json", help="Write full results as JSON to FILE.")
    parser.add_argument("--delay", type=float, default=3.0, help="Seconds between targets. Always sequential.")
    parser.add_argument("--check-phpinfo", action="store_true", help="Also probe common phpinfo-exposure paths.")
    parser.add_argument("--skip-nmap", action="store_true", help="Skip the nmap layer.")
    parser.add_argument("--skip-wapiti", action="store_true", help="Skip the wapiti wapp-module layer.")
    parser.add_argument("--skip-cmseek", action="store_true", help="Skip the cmseek CMS-identification layer.")
    parser.add_argument(
        "--cmseek-deepscan", action="store_true",
        help="Use cmseek's deep scan (plugin/theme/user enumeration, backup-file finder, "
             "admin-page finder, config-leak detection) instead of light-scan. This actively "
             "probes many paths per target — a meaningfully bigger action than the rest of "
             "this pipeline. Consider running it one target at a time instead of across a "
             "full client list.",
    )
    args = parser.parse_args()

    if not preflight_check_tools(args.skip_nmap, args.skip_wapiti, args.skip_cmseek):
        print("One or more required tools are missing at their expected path.", file=sys.stderr)
        print("Fix the path (or pass --skip-nmap / --skip-wapiti / --skip-cmseek) before", file=sys.stderr)
        print("scanning real targets — a missing tool fails fast and silently otherwise,", file=sys.stderr)
        print("which looks like a completed scan if you're not watching for it.", file=sys.stderr)
        sys.exit(1)

    urls = load_urls(args.urls_file)
    if not urls:
        print("No URLs to scan.", file=sys.stderr)
        sys.exit(1)

    reports: list[TargetReport] = []
    for i, url in enumerate(urls):
        print(f"\n[{i + 1}/{len(urls)}] {url}")
        report = scan_target(url, args.check_phpinfo, args.skip_nmap, args.skip_wapiti,
                              args.skip_cmseek, args.cmseek_deepscan)
        reports.append(report)

        # version_agreement's short label (before the first ':') is enough
        # for the console — the full detail it carries (tech lists etc.)
        # is the same thing client_summary already says in plain English
        # right below it; printing both was pure duplication. The full
        # value is still in the JSON for anyone who wants to grep/filter.
        agreement_label = report.version_agreement.split(":", 1)[0]
        print(f"  RESULT: {report.overall_status}  [{agreement_label}]")
        print(f"    {report.client_summary}")

        if i < len(urls) - 1 and args.delay:
            time.sleep(args.delay)

    summary = {}
    for r in reports:
        summary[r.overall_status] = summary.get(r.overall_status, 0) + 1

    print("\n--- Summary ---")
    for status, count in sorted(summary.items()):
        print(f"{status}: {count}")

    disagreements = [r for r in reports if r.version_agreement.startswith("DISAGREE")]
    if disagreements:
        print(f"\n{len(disagreements)} target(s) had disagreeing version reports between tools — review manually:")
        for r in disagreements:
            print(f"  - {r.url}: {r.php_versions_seen}")

    with open(args.json, "w", encoding="utf-8") as f:
        json.dump([asdict(r) for r in reports], f, indent=2)
    print(f"\nFull results written to {args.json}")


if __name__ == "__main__":
    main()
