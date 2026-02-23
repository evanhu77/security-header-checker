#!/usr/bin/env python3
"""
Attack Inference Engine
-----------------------
Takes combined findings from header_checker, cookie_checker, and
subdomain_enum and maps them to realistic attack vectors with
confidence levels and suggested next steps.

This is a prioritization layer — it tells you where to focus manual
testing effort based on what the passive recon found.

Can be used standalone (pass JSON findings file) or imported as a module.

Usage:
  python attack_inference.py --findings report.json
"""

import argparse
import json
from datetime import datetime


# ─── Attack Vector Definitions ───────────────────────────────────────────────

# Each rule: condition function + resulting attack vector metadata
# Conditions receive the full findings dict for a single target

INFERENCE_RULES = [

    # ── XSS ──────────────────────────────────────────────────────────────────
    {
        "id": "xss_no_csp",
        "attack": "Cross-Site Scripting (XSS)",
        "confidence": "HIGH",
        "condition": lambda f: _missing_header(f, "Content-Security-Policy"),
        "rationale": "No Content-Security-Policy means XSS payloads won't be blocked by the browser.",
        "next_steps": [
            "Identify all input fields and URL parameters",
            "Test for reflected XSS: inject <script>alert(1)</script>",
            "Test for stored XSS in any user-controlled persistent fields",
            "Use Burp Suite's scanner or manual payloads from PayloadsAllTheThings",
        ],
        "severity": "HIGH",
    },
    {
        "id": "xss_weak_csp",
        "attack": "Cross-Site Scripting (XSS) — CSP Bypass",
        "confidence": "MEDIUM",
        "condition": lambda f: _has_csp_warning(f, "unsafe-inline") and not _missing_header(f, "Content-Security-Policy"),
        "rationale": "CSP exists but contains unsafe-inline, which weakens or eliminates XSS protection depending on context.",
        "next_steps": [
            "Review the full CSP policy for bypasses (unsafe-inline, unsafe-eval, wildcard sources)",
            "Check if nonces are properly rotated per request",
            "Test JSONP endpoints listed in script-src that could be abused",
            "Look for CSP bypass via trusted third-party scripts (supply chain angle)",
        ],
        "severity": "MEDIUM",
    },

    # ── Session Hijacking ─────────────────────────────────────────────────────
    {
        "id": "session_hijack_httponly",
        "attack": "Session Hijacking via XSS",
        "confidence": "HIGH",
        "condition": lambda f: _cookie_missing_flag(f, "HttpOnly", session_only=True),
        "rationale": "Session cookie lacks HttpOnly — if any XSS exists, document.cookie exposes the session token directly.",
        "next_steps": [
            "Confirm which cookie is the actual session token (look for names like sessionid, auth, token)",
            "If XSS is found anywhere on the domain, demonstrate cookie theft as impact escalation",
            "Check if the cookie is scoped broadly (Path=/) which maximizes exposure",
        ],
        "severity": "HIGH",
    },

    # ── CSRF ─────────────────────────────────────────────────────────────────
    {
        "id": "csrf_no_samesite",
        "attack": "Cross-Site Request Forgery (CSRF)",
        "confidence": "MEDIUM",
        "condition": lambda f: _cookie_missing_flag(f, "SameSite"),
        "rationale": "Cookies without SameSite are sent on cross-site requests, enabling CSRF if no other token-based protection exists.",
        "next_steps": [
            "Check if state-changing endpoints (POST/PUT/DELETE) validate a CSRF token",
            "Test by crafting a cross-origin form submission to a state-changing action",
            "Check if the app relies solely on cookies for auth (no Authorization header)",
            "Higher impact on endpoints like: change email, change password, fund transfers",
        ],
        "severity": "MEDIUM",
    },

    # ── Clickjacking ─────────────────────────────────────────────────────────
    {
        "id": "clickjacking",
        "attack": "Clickjacking",
        "confidence": "HIGH",
        "condition": lambda f: (
            _missing_header(f, "X-Frame-Options")
            and not _csp_has_frame_ancestors(f)
        ),
        "rationale": "No X-Frame-Options and no CSP frame-ancestors — the page can be embedded in an iframe on an attacker-controlled site.",
        "next_steps": [
            "Verify with: <iframe src='https://target.com'></iframe> in a local HTML file",
            "Look for sensitive actions on the page that could be tricked via overlaid UI",
            "Higher impact on: login pages, account settings, payment flows",
        ],
        "severity": "MEDIUM",
    },

    # ── SSL / Transport ───────────────────────────────────────────────────────
    {
        "id": "ssl_stripping",
        "attack": "SSL Stripping / Cookie Interception",
        "confidence": "HIGH",
        "condition": lambda f: _cookie_missing_flag(f, "Secure", session_only=True),
        "rationale": "Session cookie lacks the Secure flag — it can be transmitted over HTTP and intercepted.",
        "next_steps": [
            "Verify whether the site redirects HTTP → HTTPS (check subdomain_enum http_to_https flag)",
            "If HTTP is served at all, the cookie is exposed",
            "Test by requesting http:// version and checking if cookie is sent",
        ],
        "severity": "HIGH",
    },
    {
        "id": "hsts_missing",
        "attack": "Protocol Downgrade / HSTS Bypass",
        "confidence": "MEDIUM",
        "condition": lambda f: _missing_header(f, "Strict-Transport-Security"),
        "rationale": "No HSTS header — browsers won't remember to enforce HTTPS, leaving users vulnerable to downgrade attacks on first visit.",
        "next_steps": [
            "Verify if HTTP traffic is served at all",
            "Check if subdomains also lack HSTS (includeSubDomains is important)",
            "Combined with missing Secure cookie flag, this is a stronger finding",
        ],
        "severity": "MEDIUM",
    },

    # ── Information Disclosure ────────────────────────────────────────────────
    {
        "id": "tech_disclosure_php",
        "attack": "Version-Targeted Attack (PHP CVEs)",
        "confidence": "MEDIUM",
        "condition": lambda f: _leaks_header_containing(f, "x-powered-by", "php"),
        "rationale": "PHP version exposed. Depending on version, known CVEs may apply.",
        "next_steps": [
            "Note the exact PHP version from X-Powered-By header",
            "Search CVE databases for that version: https://www.cvedetails.com/",
            "Check for deserialization, RCE, or path traversal CVEs specific to that version",
        ],
        "severity": "MEDIUM",
    },
    {
        "id": "tech_disclosure_server",
        "attack": "Version-Targeted Attack (Server CVEs)",
        "confidence": "LOW",
        "condition": lambda f: _leaks_specific_server_version(f),
        "rationale": "Server software and version exposed. May reveal vulnerable software version.",
        "next_steps": [
            "Note the exact server version from the Server header",
            "Search for CVEs: https://www.cvedetails.com/",
            "Check Shodan/Censys for other exposed services on the same IP",
        ],
        "severity": "LOW",
    },

    # ── MIME / Content Sniffing ───────────────────────────────────────────────
    {
        "id": "mime_sniffing",
        "attack": "MIME Confusion Attack",
        "confidence": "LOW",
        "condition": lambda f: _missing_header(f, "X-Content-Type-Options"),
        "rationale": "Without nosniff, browsers may interpret responses as a different content type, enabling content injection.",
        "next_steps": [
            "Find file upload endpoints and test uploading HTML/JS with wrong content-type",
            "Check if user-uploaded content is served from the same domain",
        ],
        "severity": "LOW",
    },

    # ── Interesting Subdomains ────────────────────────────────────────────────
    {
        "id": "interesting_subdomains",
        "attack": "Expanded Attack Surface (Subdomains)",
        "confidence": "INFO",
        "condition": lambda f: _has_interesting_subdomains(f),
        "rationale": "Interesting subdomains discovered — dev/staging/admin/API endpoints often have weaker security than production.",
        "next_steps": [
            "Run full header + cookie scan against each interesting subdomain",
            "Dev/staging environments sometimes expose debug info, verbose errors, or weaker auth",
            "Admin panels may have default credentials or authentication bypasses",
            "API subdomains often have looser CORS policies worth testing",
        ],
        "severity": "INFO",
    },
]


# ─── Condition Helpers ────────────────────────────────────────────────────────

def _missing_header(findings: dict, header_name: str) -> bool:
    headers = findings.get("headers") or {}
    missing = headers.get("missing") or []
    return any(h["header"] == header_name for h in missing)


def _has_csp_warning(findings: dict, keyword: str) -> bool:
    headers = findings.get("headers") or {}
    warnings = headers.get("warnings") or []
    return any(keyword in w.get("warning", "") for w in warnings)


def _csp_has_frame_ancestors(findings: dict) -> bool:
    headers = findings.get("headers") or {}
    present = headers.get("present") or []
    for h in present:
        if h["header"] == "Content-Security-Policy":
            return "frame-ancestors" in h.get("value", "")
    return False


def _cookie_missing_flag(findings: dict, flag: str, session_only: bool = False) -> bool:
    cookies = findings.get("cookies") or {}
    cookie_list = cookies.get("cookies") or []
    for cookie in cookie_list:
        if session_only and not cookie.get("is_session_cookie"):
            continue
        issues = cookie.get("issues") or []
        if any(i["flag"] == flag for i in issues):
            return True
    return False


def _leaks_header_containing(findings: dict, header: str, keyword: str) -> bool:
    headers = findings.get("headers") or {}
    leaking = headers.get("leaking") or []
    for h in leaking:
        if h["header"].lower() == header.lower():
            return keyword.lower() in h.get("value", "").lower()
    return False


def _leaks_specific_server_version(findings: dict) -> bool:
    """Flag if Server header reveals a specific versioned product (not just 'cloudflare')."""
    headers = findings.get("headers") or {}
    leaking = headers.get("leaking") or []
    for h in leaking:
        if h["header"].lower() == "server":
            value = h.get("value", "").lower()
            # Generic CDN values aren't interesting, versioned servers are
            generic = ("cloudflare", "fastly", "akamai", "amazon", "google")
            if not any(g in value for g in generic):
                return True
    return False


def _has_interesting_subdomains(findings: dict) -> bool:
    enum = findings.get("subdomain_enum") or {}
    subs = enum.get("subdomains") or []
    return any(s.get("interesting") for s in subs)


# ─── Core Inference ───────────────────────────────────────────────────────────

CONFIDENCE_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
SEVERITY_ORDER   = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}


def infer(findings: dict) -> list[dict]:
    """
    Run all inference rules against a findings dict.
    Returns a list of triggered attack vectors, sorted by severity then confidence.
    """
    triggered = []
    for rule in INFERENCE_RULES:
        try:
            if rule["condition"](findings):
                triggered.append({
                    "id":         rule["id"],
                    "attack":     rule["attack"],
                    "confidence": rule["confidence"],
                    "severity":   rule["severity"],
                    "rationale":  rule["rationale"],
                    "next_steps": rule["next_steps"],
                })
        except Exception:
            # Never let a broken rule crash the whole report
            continue

    triggered.sort(key=lambda x: (
        SEVERITY_ORDER.get(x["severity"], 99),
        CONFIDENCE_ORDER.get(x["confidence"], 99),
    ))

    return triggered


def infer_bulk(targets: list[dict]) -> list[dict]:
    """
    Run inference across multiple targets (from a full-recon run).
    Returns each target annotated with its attack vectors,
    sorted so the highest-risk targets come first.
    """
    results = []
    for target in targets:
        vectors = infer(target.get("findings", target))
        high_count   = sum(1 for v in vectors if v["severity"] == "HIGH")
        medium_count = sum(1 for v in vectors if v["severity"] == "MEDIUM")
        results.append({
            **target,
            "attack_vectors": vectors,
            "vector_counts": {"HIGH": high_count, "MEDIUM": medium_count},
        })

    # Sort: most HIGH vectors first, then MEDIUM
    results.sort(key=lambda x: (
        -x["vector_counts"]["HIGH"],
        -x["vector_counts"]["MEDIUM"],
    ))
    return results


# ─── Reporting ────────────────────────────────────────────────────────────────

CONFIDENCE_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


def print_inference_report(url: str, vectors: list[dict]):
    print(f"\n  {'─'*54}")
    print(f"  🎯 ATTACK INFERENCE  ·  {url}")
    print(f"  {'─'*54}")

    if not vectors:
        print("\n  ✅ No obvious attack vectors inferred from passive recon.")
        print("  This doesn't mean the target is secure — manual testing is still needed.\n")
        return

    high   = [v for v in vectors if v["severity"] == "HIGH"]
    medium = [v for v in vectors if v["severity"] == "MEDIUM"]
    low    = [v for v in vectors if v["severity"] in ("LOW", "INFO")]

    for group, label in [(high, "HIGH PRIORITY"), (medium, "MEDIUM PRIORITY"), (low, "LOW / INFO")]:
        if not group:
            continue
        print(f"\n  {'─'*20} {label} {'─'*20}\n")
        for v in group:
            emoji = CONFIDENCE_EMOJI.get(v["confidence"], "⚪")
            print(f"  {emoji} {v['attack']}  [confidence: {v['confidence']}]")
            print(f"     Why: {v['rationale']}")
            print(f"     Next steps:")
            for step in v["next_steps"]:
                print(f"       • {step}")
            print()


def print_bulk_report(results: list[dict]):
    print(f"\n  {'═'*54}")
    print(f"  🎯 BULK ATTACK INFERENCE REPORT")
    print(f"  {'═'*54}")
    print(f"  Targets analyzed: {len(results)}")
    actionable = sum(1 for r in results if r["vector_counts"]["HIGH"] > 0)
    print(f"  Targets with HIGH vectors: {actionable}")
    print()

    for r in results:
        url = r.get("url", r.get("subdomain", "unknown"))
        counts = r["vector_counts"]
        vectors = r["attack_vectors"]
        if not vectors:
            continue
        attack_names = ", ".join(v["attack"] for v in vectors[:3])
        if len(vectors) > 3:
            attack_names += f" (+{len(vectors)-3} more)"
        print(f"  🌐 {url}")
        print(f"     Vectors: {counts['HIGH']} HIGH  {counts['MEDIUM']} MEDIUM")
        print(f"     {attack_names}")
        print()


# ─── CLI ──────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🎯 Attack Inference Engine — map recon findings to attack vectors",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python attack_inference.py --findings report.json
        """
    )
    parser.add_argument("--findings", metavar="FILE", required=True,
                        help="JSON findings file from main.py --json output")
    args = parser.parse_args()

    with open(args.findings) as f:
        data = json.load(f)

    url = data.get("meta", {}).get("url", args.findings)
    vectors = infer(data)
    print_inference_report(url, vectors)


if __name__ == "__main__":
    main()
