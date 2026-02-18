#!/usr/bin/env python3
"""
Security Recon Tool
-------------------
Main entry point for the security header and cookie analysis suite.
Runs both header_checker and cookie_checker against a target URL
and produces a unified report.

Usage:
  python main.py https://example.com
  python main.py https://example.com --json report.json
  python main.py https://example.com --headers-only
  python main.py https://example.com --cookies-only
  python main.py https://example.com --quiet
"""

import argparse
import json
import sys
from datetime import datetime

import requests

from header_checker import fetch_headers, analyze_headers
from cookie_checker import get_set_cookie_headers, analyze_cookies


# ─── Unified Report ───────────────────────────────────────────────────────────

SEVERITY_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


def print_header_section(findings: dict):
    if not findings:
        return

    score = findings["score"]
    print(f"\n  {'─'*54}")
    print(f"  🔍 HEADERS  ·  Score: {score['score']}/100  Grade: {score['grade']}  ({score['label']})")
    print(f"  {'─'*54}")

    if findings["missing"]:
        print(f"\n  ❌ Missing ({len(findings['missing'])}):")
        for h in findings["missing"]:
            emoji = SEVERITY_EMOJI.get(h["severity"], "⚪")
            print(f"     {emoji} [{h['severity']:6}]  {h['header']}")
            print(f"              ↳ {h['description']}")
            print(f"              Fix: {h['recommendation']}")
            print()

    if findings["warnings"]:
        print(f"  ⚠️  Misconfigured ({len(findings['warnings'])}):")
        for h in findings["warnings"]:
            print(f"     🟡 {h['header']}: {h['value']}")
            print(f"              ↳ {h['warning']}")
            print()

    if findings["leaking"]:
        print(f"  💧 Information Leakage ({len(findings['leaking'])}):")
        for h in findings["leaking"]:
            print(f"     ⚠️  {h['header']}: {h['value']}")
            print(f"              ↳ {h['description']}")
            print()

    present_names = [h["header"] for h in findings["present"]]
    if present_names:
        print(f"  ✅ Present: {', '.join(present_names)}")


def print_cookie_section(findings: dict):
    if not findings:
        return

    score = findings["score"]
    print(f"\n  {'─'*54}")
    print(f"  🍪 COOKIES  ·  Score: {score['score']}/100  Grade: {score['grade']}  "
          f"·  {findings['total']} cookies found")
    print(f"  {'─'*54}")

    if findings["total"] == 0:
        print("\n  ℹ️  No Set-Cookie headers on this response.")
        print("     Tip: Try scanning a login or authenticated endpoint.\n")
        return

    for cookie in findings["cookies"]:
        risk = cookie["risk_level"]
        risk_emoji = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "SECURE": "✅"}.get(risk, "⚪")
        session_tag = " [SESSION]" if cookie["is_session_cookie"] else ""

        flags = cookie["flags"]
        honly = "✓ HttpOnly" if flags["httponly"] else "✗ HttpOnly"
        sec   = "✓ Secure"   if flags["secure"]   else "✗ Secure"
        ss    = f"✓ SameSite={flags['samesite']}" if flags["samesite"] else "✗ SameSite"

        print(f"\n     {risk_emoji} {cookie['name']}{session_tag}")
        print(f"        Flags: {honly}  {sec}  {ss}")

        for issue in cookie["issues"]:
            emoji = SEVERITY_EMOJI.get(issue["severity"], "⚪")
            print(f"        {emoji} [{issue['severity']:6}]  {issue['flag']} missing")
            print(f"                 ↳ Attack: {issue['attack']}")
            print(f"                   Fix:    {issue['recommendation']}")

    all_attacks = list({i["attack"] for c in findings["cookies"] for i in c["issues"]})
    if all_attacks:
        print(f"\n  ⚠️  Attack vectors enabled: {', '.join(all_attacks)}")


def print_unified_report(url: str, final_url: str, status_code: int,
                          header_findings: dict, cookie_findings: dict):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "═" * 60)
    print("  🛡️  SECURITY RECON REPORT")
    print("═" * 60)
    print(f"  URL      : {url}")
    if final_url and final_url != url:
        print(f"  Resolved : {final_url}")
    print(f"  Status   : {status_code}")
    print(f"  Scanned  : {timestamp}")

    # Overall score — average of both modules when both are run
    scores = []
    if header_findings:
        scores.append(header_findings["score"]["score"])
    if cookie_findings:
        scores.append(cookie_findings["score"]["score"])

    if scores:
        overall = sum(scores) // len(scores)
        grade = "A" if overall >= 80 else "B" if overall >= 60 else "C" if overall >= 40 else "F"
        label = "Good" if overall >= 80 else "Fair" if overall >= 60 else "Poor" if overall >= 40 else "Critical"
        print(f"  Overall  : {overall}/100  Grade: {grade}  ({label})")

    print("═" * 60)

    if header_findings:
        print_header_section(header_findings)
    if cookie_findings:
        print_cookie_section(cookie_findings)

    print("\n" + "═" * 60)
    print()


def build_json_report(url: str, final_url: str, status_code: int,
                       header_findings: dict, cookie_findings: dict) -> dict:
    scores = []
    if header_findings:
        scores.append(header_findings["score"]["score"])
    if cookie_findings:
        scores.append(cookie_findings["score"]["score"])

    overall = sum(scores) // len(scores) if scores else 0
    grade = "A" if overall >= 80 else "B" if overall >= 60 else "C" if overall >= 40 else "F"

    return {
        "meta": {
            "url": url,
            "resolved_url": final_url,
            "status_code": status_code,
            "timestamp": datetime.now().isoformat(),
            "tool": "SecurityRecon v1.0",
        },
        "overall_score": {"score": overall, "grade": grade},
        "headers": header_findings,
        "cookies": cookie_findings,
    }


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🛡️  Security Recon Tool — Headers + Cookies",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py https://example.com
  python main.py https://example.com --json report.json
  python main.py https://example.com --headers-only
  python main.py https://example.com --cookies-only
  python main.py https://example.com --quiet
        """
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--json", metavar="FILE", help="Save full JSON report to file")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--headers-only", action="store_true", help="Run header analysis only")
    parser.add_argument("--cookies-only", action="store_true", help="Run cookie analysis only")
    parser.add_argument("--quiet", action="store_true", help="Print overall score only")

    args = parser.parse_args()

    run_headers = not args.cookies_only
    run_cookies = not args.headers_only

    print(f"\n  🛡️  Scanning: {args.url}")
    if run_headers:
        print("     → Headers")
    if run_cookies:
        print("     → Cookies")

    header_findings = None
    cookie_findings = None
    final_url = args.url
    status_code = None

    try:
        # Headers module
        if run_headers:
            print("\n  Fetching headers...")
            raw_headers, final_url, status_code = fetch_headers(args.url, args.timeout)
            header_findings = analyze_headers(raw_headers)

        # Cookies module — reuse same connection if possible
        if run_cookies:
            if not run_headers:
                print("\n  Fetching cookies...")
            cookie_headers, final_url, status_code = get_set_cookie_headers(args.url, args.timeout)
            cookie_findings = analyze_cookies(cookie_headers)

        # Output
        if args.quiet:
            scores = []
            if header_findings:
                scores.append(header_findings["score"]["score"])
            if cookie_findings:
                scores.append(cookie_findings["score"]["score"])
            if scores:
                overall = sum(scores) // len(scores)
                grade = "A" if overall >= 80 else "B" if overall >= 60 else "C" if overall >= 40 else "F"
                print(f"\n  Overall Score: {overall}/100  Grade: {grade}\n")
        else:
            print_unified_report(args.url, final_url, status_code, header_findings, cookie_findings)

        if args.json:
            report = build_json_report(args.url, final_url, status_code, header_findings, cookie_findings)
            with open(args.json, "w") as f:
                json.dump(report, f, indent=2)
            print(f"  📄 JSON report saved: {args.json}")

    except requests.exceptions.ConnectionError:
        print(f"\n  ❌ Could not connect to {args.url}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(f"\n  ❌ Request timed out after {args.timeout}s")
        sys.exit(1)
    except Exception as e:
        print(f"\n  ❌ Unexpected error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
