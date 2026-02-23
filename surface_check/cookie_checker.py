#!/usr/bin/env python3
"""
Cookie Flag Checker
Parses and analyzes Set-Cookie headers for missing security flags.
Can be used standalone or imported as a module.
"""

import re
import requests
import json
import argparse
from datetime import datetime
from urllib.parse import urlparse


# ─── Flag Definitions ────────────────────────────────────────────────────────

COOKIE_FLAGS = {
    "HttpOnly": {
        "severity": "HIGH",
        "description": (
            "Prevents JavaScript from accessing the cookie via document.cookie. "
            "Without this, XSS attacks can steal session tokens directly."
        ),
        "recommendation": "Append HttpOnly to the Set-Cookie directive.",
        "attack": "XSS-based session hijacking",
    },
    "Secure": {
        "severity": "HIGH",
        "description": (
            "Ensures the cookie is only transmitted over HTTPS. "
            "Without this, the cookie can be intercepted on HTTP connections "
            "or via SSL stripping attacks."
        ),
        "recommendation": "Append Secure to the Set-Cookie directive.",
        "attack": "Man-in-the-middle / SSL stripping",
    },
    "SameSite": {
        "severity": "MEDIUM",
        "description": (
            "Controls whether the cookie is sent with cross-site requests. "
            "Without this, the cookie is vulnerable to Cross-Site Request Forgery (CSRF)."
        ),
        "recommendation": "Set SameSite=Lax (default-safe) or SameSite=Strict for sensitive cookies.",
        "attack": "Cross-Site Request Forgery (CSRF)",
    },
}

SAMESITE_VALUES = {
    "strict": {
        "safe": True,
        "note": "Most restrictive. Cookie not sent on any cross-site request.",
    },
    "lax": {
        "safe": True,
        "note": "Balanced. Cookie sent on top-level navigations but not sub-requests.",
    },
    "none": {
        "safe": False,
        "note": "Cookie sent on all cross-site requests. REQUIRES Secure flag.",
    },
}

# Patterns that suggest a cookie is session-related (higher risk if flags missing)
SESSION_PATTERNS = re.compile(
    r"(sess|session|token|auth|jwt|login|user|account|id|csrf|xsrf)",
    re.IGNORECASE,
)

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
SEVERITY_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


# ─── Parsing ─────────────────────────────────────────────────────────────────

def parse_set_cookie(header_value: str) -> dict:
    """
    Parse a single Set-Cookie header string into a structured dict.

    Example input:
      sessionid=abc123; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=3600

    Returns:
      {
        "name": "sessionid",
        "value": "abc123",
        "raw": "sessionid=abc123; ...",
        "flags": {"httponly": True, "secure": True, "samesite": "Lax"},
        "attributes": {"path": "/", "max-age": "3600"},
        "is_session_cookie": True,
      }
    """
    parts = [p.strip() for p in header_value.split(";")]
    if not parts:
        return {}

    # First part is always name=value
    name_value = parts[0]
    if "=" in name_value:
        name, _, value = name_value.partition("=")
    else:
        name, value = name_value, ""

    flags = {"httponly": False, "secure": False, "samesite": None}  # None = not set (different from "None" value)
    attributes = {}

    for part in parts[1:]:
        part_lower = part.lower()
        if part_lower == "httponly":
            flags["httponly"] = True
        elif part_lower == "secure":
            flags["secure"] = True
        elif part_lower.startswith("samesite="):
            flags["samesite"] = part.split("=", 1)[1].strip()
        elif "=" in part:
            k, _, v = part.partition("=")
            attributes[k.strip().lower()] = v.strip()
        else:
            attributes[part.lower()] = True

    return {
        "name": name.strip(),
        "value": value.strip(),
        "raw": header_value,
        "flags": flags,
        "attributes": attributes,
        "is_session_cookie": bool(SESSION_PATTERNS.search(name.strip())),
    }


def get_set_cookie_headers(url: str, timeout: int = 10) -> tuple:
    """Fetch a URL and return all Set-Cookie headers."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    response = requests.get(url, timeout=timeout, allow_redirects=True)

    # requests merges duplicate headers — raw Set-Cookie needs special handling
    set_cookie_headers = response.raw.headers.getlist("Set-Cookie")

    # Fallback: some adapters don't support getlist
    if not set_cookie_headers:
        raw = response.headers.get("Set-Cookie", "")
        set_cookie_headers = [raw] if raw else []

    return set_cookie_headers, response.url, response.status_code


# ─── Analysis ────────────────────────────────────────────────────────────────

def analyze_cookie(cookie: dict) -> dict:
    """Analyze a single parsed cookie and return its issues."""
    issues = []
    flags = cookie["flags"]

    for flag_name, info in COOKIE_FLAGS.items():
        flag_key = flag_name.lower()

        if flag_key == "samesite":
            if flags["samesite"] is None:
                issues.append({
                    "flag": flag_name,
                    "severity": info["severity"],
                    "description": info["description"],
                    "recommendation": info["recommendation"],
                    "attack": info["attack"],
                })
            else:
                ss_val = flags["samesite"].lower()
                ss_info = SAMESITE_VALUES.get(ss_val, {})
                if not ss_info.get("safe", True):
                    # SameSite=None requires Secure flag
                    if not flags["secure"]:
                        issues.append({
                            "flag": "SameSite=None without Secure",
                            "severity": "HIGH",
                            "description": (
                                "SameSite=None is set but the Secure flag is missing. "
                                "This combination is rejected by modern browsers and "
                                "exposes the cookie over HTTP."
                            ),
                            "recommendation": "Add the Secure flag or change SameSite to Lax.",
                            "attack": "Cookie interception + CSRF",
                        })
                    else:
                        issues.append({
                            "flag": "SameSite=None",
                            "severity": "INFO",
                            "description": ss_info.get("note", ""),
                            "recommendation": "Only use SameSite=None if cross-site access is genuinely required.",
                            "attack": "CSRF (reduced protection)",
                        })
        else:
            if not flags.get(flag_key):
                severity = info["severity"]
                # Escalate severity if it looks like a session cookie
                if cookie["is_session_cookie"] and severity == "MEDIUM":
                    severity = "HIGH"
                issues.append({
                    "flag": flag_name,
                    "severity": severity,
                    "description": info["description"],
                    "recommendation": info["recommendation"],
                    "attack": info["attack"],
                })

    return {
        **cookie,
        "issues": sorted(issues, key=lambda x: SEVERITY_ORDER.get(x["severity"], 99)),
        "risk_level": _overall_risk(issues, cookie["is_session_cookie"]),
    }


def _overall_risk(issues: list, is_session: bool) -> str:
    """Determine overall risk level for a cookie."""
    if not issues:
        return "SECURE"
    severities = [i["severity"] for i in issues]
    if "HIGH" in severities:
        return "HIGH"
    if "MEDIUM" in severities:
        return "HIGH" if is_session else "MEDIUM"
    return "LOW"


def analyze_cookies(set_cookie_headers: list) -> dict:
    """Analyze all Set-Cookie headers and return aggregated findings."""
    parsed = [parse_set_cookie(h) for h in set_cookie_headers if h]
    analyzed = [analyze_cookie(c) for c in parsed if c]

    all_issues = [issue for c in analyzed for issue in c["issues"]]
    high = sum(1 for i in all_issues if i["severity"] == "HIGH")
    medium = sum(1 for i in all_issues if i["severity"] == "MEDIUM")

    score_deduction = (high * 20) + (medium * 10)
    score = max(0, 100 - score_deduction)
    grade = "A" if score >= 80 else "B" if score >= 60 else "C" if score >= 40 else "F"

    return {
        "cookies": analyzed,
        "total": len(analyzed),
        "session_cookies": sum(1 for c in analyzed if c["is_session_cookie"]),
        "secure_cookies": sum(1 for c in analyzed if not c["issues"]),
        "issue_counts": {"HIGH": high, "MEDIUM": medium},
        "score": {"score": score, "grade": grade},
    }


# ─── Reporting ───────────────────────────────────────────────────────────────

def print_cookie_report(url: str, final_url: str, status_code: int, findings: dict):
    """Print a formatted terminal report for cookie analysis."""
    score_info = findings["score"]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "═" * 60)
    print("  🍪 COOKIE SECURITY ANALYSIS REPORT")
    print("═" * 60)
    print(f"  URL        : {url}")
    if final_url != url:
        print(f"  Resolved   : {final_url}")
    print(f"  Status     : {status_code}")
    print(f"  Scanned    : {timestamp}")
    print(f"  Cookies    : {findings['total']} found  "
          f"({findings['session_cookies']} session-related, "
          f"{findings['secure_cookies']} fully secure)")
    print(f"  Score      : {score_info['score']}/100  Grade: {score_info['grade']}")
    print("═" * 60)

    if findings["total"] == 0:
        print("\n  ℹ️  No Set-Cookie headers found on this response.")
        print("  Try scanning a login endpoint or authenticated route.\n")
        print("═" * 60)
        return

    for cookie in findings["cookies"]:
        risk = cookie["risk_level"]
        risk_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "SECURE": "✅"}.get(risk, "⚪")
        session_tag = " [SESSION]" if cookie["is_session_cookie"] else ""
        
        print(f"\n  {risk_emoji} {cookie['name']}{session_tag}  ──  Risk: {risk}")
        print(f"     Raw: {cookie['raw'][:80]}{'...' if len(cookie['raw']) > 80 else ''}")

        # Show flag status summary
        flags = cookie["flags"]
        flag_line = "     Flags: "
        flag_line += ("✓ HttpOnly  " if flags["httponly"] else "✗ HttpOnly  ")
        flag_line += ("✓ Secure  " if flags["secure"] else "✗ Secure  ")
        ss = flags["samesite"]
        flag_line += (f"✓ SameSite={ss}" if ss else "✗ SameSite")
        print(flag_line)

        if cookie["issues"]:
            print()
            for issue in cookie["issues"]:
                emoji = SEVERITY_EMOJI.get(issue["severity"], "⚪")
                print(f"     {emoji} [{issue['severity']}] Missing: {issue['flag']}")
                print(f"          Attack vector: {issue['attack']}")
                print(f"          Fix: {issue['recommendation']}")

    print("\n" + "═" * 60)

    # Summary of unique issues across all cookies
    all_attacks = list({i["attack"] for c in findings["cookies"] for i in c["issues"]})
    if all_attacks:
        print("\n  ⚠️  ATTACK VECTORS ENABLED BY THESE FINDINGS:")
        for attack in all_attacks:
            print(f"     • {attack}")

    print()


def save_cookie_json(url: str, final_url: str, status_code: int, findings: dict, output_file: str):
    """Save cookie findings as JSON."""
    report = {
        "meta": {
            "url": url,
            "resolved_url": final_url,
            "status_code": status_code,
            "timestamp": datetime.now().isoformat(),
            "tool": "CookieChecker v1.0",
        },
        "score": findings["score"],
        "summary": {
            "total_cookies": findings["total"],
            "session_cookies": findings["session_cookies"],
            "secure_cookies": findings["secure_cookies"],
            "issue_counts": findings["issue_counts"],
        },
        "cookies": findings["cookies"],
    }
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  📄 JSON report saved: {output_file}")


# ─── CLI Entry Point ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🍪 Cookie Flag Checker - Analyze Set-Cookie security flags",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python cookie_checker.py https://example.com
  python cookie_checker.py https://example.com/login --json cookies.json
  python cookie_checker.py https://example.com --timeout 15
        """
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--json", metavar="FILE", help="Save JSON report to file")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")

    args = parser.parse_args()

    print(f"\n  Scanning cookies: {args.url} ...")

    try:
        headers, final_url, status_code = get_set_cookie_headers(args.url, args.timeout)
        findings = analyze_cookies(headers)
        print_cookie_report(args.url, final_url, status_code, findings)

        if args.json:
            save_cookie_json(args.url, final_url, status_code, findings, args.json)

    except requests.exceptions.ConnectionError:
        print(f"\n  ❌ Error: Could not connect to {args.url}")
    except requests.exceptions.Timeout:
        print(f"\n  ❌ Error: Request timed out after {args.timeout}s")
    except Exception as e:
        print(f"\n  ❌ Unexpected error: {e}")


if __name__ == "__main__":
    main()
