#!/usr/bin/env python3
"""
Security Recon Tool
-------------------
Main entry point for the security recon suite.
Orchestrates header, cookie, subdomain, and attack inference modules.

Modes:
  Default         — headers + cookies for a single URL
  --full-recon    — subdomain enum + headers + cookies + attack inference
                    across the entire domain

Usage:
  python main.py https://example.com
  python main.py example.com --full-recon
  python main.py https://example.com --json report.json
  python main.py https://example.com --headers-only
  python main.py https://example.com --cookies-only
  python main.py example.com --full-recon --json recon.json
  python main.py https://example.com --quiet
"""

import argparse
import json
import re
import sys
from datetime import datetime
from urllib.parse import urlparse

import requests

from header_checker import fetch_headers, analyze_headers
from cookie_checker import get_set_cookie_headers, analyze_cookies
from subdomain_enum import enumerate as enumerate_subdomains, print_enum_report
from attack_inference import infer, infer_bulk, print_inference_report, print_bulk_report


# ─── Helpers ─────────────────────────────────────────────────────────────────

SEVERITY_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


def extract_domain(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return urlparse(url).netloc.lower()


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        return "https://" + url
    return url


# ─── Single Target Scan ───────────────────────────────────────────────────────

def scan_target(url: str, run_headers: bool = True, run_cookies: bool = True,
                timeout: int = 10) -> dict:
    url = normalize_url(url)
    findings = {"url": url, "headers": None, "cookies": None,
                "status_code": None, "final_url": url}

    try:
        if run_headers:
            raw_headers, final_url, status_code = fetch_headers(url, timeout)
            findings["headers"] = analyze_headers(raw_headers)
            findings["final_url"] = final_url
            findings["status_code"] = status_code

        if run_cookies:
            cookie_headers, final_url, status_code = get_set_cookie_headers(url, timeout)
            findings["cookies"] = analyze_cookies(cookie_headers)
            if not findings["final_url"]:
                findings["final_url"] = final_url
            if not findings["status_code"]:
                findings["status_code"] = status_code

    except requests.exceptions.ConnectionError:
        findings["error"] = f"Could not connect to {url}"
    except requests.exceptions.Timeout:
        findings["error"] = f"Timeout after {timeout}s"
    except Exception as e:
        findings["error"] = str(e)

    return findings


# ─── Reporting: Single Target ─────────────────────────────────────────────────

def print_header_section(findings: dict):
    if not findings:
        return
    score = findings["score"]
    print(f"\n  {'─'*54}")
    print(f"  🔍 HEADERS  ·  Score: {score['score']}/100  "
          f"Grade: {score['grade']}  ({score['label']})")
    print(f"  {'─'*54}")

    if findings["missing"]:
        print(f"\n  ❌ Missing ({len(findings['missing'])}):\n")
        for h in findings["missing"]:
            emoji = SEVERITY_EMOJI.get(h["severity"], "⚪")
            print(f"     {emoji} [{h['severity']:6}]  {h['header']}")
            print(f"              ↳ {h['description']}")
            print(f"              Fix: {h['recommendation']}")
            print()

    if findings["warnings"]:
        print(f"  ⚠️  Misconfigured ({len(findings['warnings'])}):\n")
        for h in findings["warnings"]:
            print(f"     🟡 {h['header']}")
            print(f"              ↳ {h['warning']}")
            print()

    if findings["leaking"]:
        print(f"  💧 Information Leakage ({len(findings['leaking'])}):\n")
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
          f"·  {findings['total']} found")
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


def print_single_report(scan: dict, show_inference: bool = True):
    url = scan["url"]
    final_url = scan.get("final_url", url)
    status = scan.get("status_code", "?")
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "═" * 60)
    print("  🛡️  SECURITY RECON REPORT")
    print("═" * 60)
    print(f"  URL      : {url}")
    if final_url and final_url != url:
        print(f"  Resolved : {final_url}")
    print(f"  Status   : {status}")
    print(f"  Scanned  : {timestamp}")

    if scan.get("error"):
        print(f"\n  ❌ Error: {scan['error']}")
        print("═" * 60)
        return

    scores = []
    if scan.get("headers"):
        scores.append(scan["headers"]["score"]["score"])
    if scan.get("cookies"):
        scores.append(scan["cookies"]["score"]["score"])
    if scores:
        overall = sum(scores) // len(scores)
        grade = "A" if overall >= 80 else "B" if overall >= 60 else "C" if overall >= 40 else "F"
        label = "Good" if overall >= 80 else "Fair" if overall >= 60 else "Poor" if overall >= 40 else "Critical"
        print(f"  Overall  : {overall}/100  Grade: {grade}  ({label})")

    print("═" * 60)

    if scan.get("headers"):
        print_header_section(scan["headers"])
    if scan.get("cookies"):
        print_cookie_section(scan["cookies"])
    if show_inference:
        vectors = infer(scan)
        if vectors:
            print_inference_report(url, vectors)

    print("\n" + "═" * 60)
    print()


# ─── Full Recon Mode ──────────────────────────────────────────────────────────

def full_recon(domain: str, timeout: int = 10, threads: int = 20,
               run_inference: bool = True) -> dict:
    domain = extract_domain(domain) if ("/" in domain or domain.startswith("http")) else domain

    print(f"\n  🛡️  FULL RECON MODE  ·  {domain}")
    print("═" * 60)

    # Step 1: Subdomain enumeration
    enum_results = enumerate_subdomains(domain, timeout=timeout, threads=threads)
    print_enum_report(enum_results)

    if enum_results["live"] == 0:
        print("  No live subdomains found — scanning base domain only.")
        targets = [{"subdomain": domain, "url": f"https://{domain}", "live": True}]
    else:
        targets = enum_results["subdomains"]

    # Step 2: Scan each live target
    print(f"\n  🔍 Scanning {len(targets)} live targets...")
    print("═" * 60)

    scanned = []
    for target in targets:
        url = target.get("url") or f"https://{target['subdomain']}"
        subdomain = target.get("subdomain", domain)
        print(f"\n  → {subdomain}")

        scan = scan_target(url, run_headers=True, run_cookies=True, timeout=timeout)
        scan["subdomain"] = subdomain
        scan["subdomain_meta"] = target

        if scan.get("error"):
            print(f"     ⚠  {scan['error']}")
        else:
            h_score = scan["headers"]["score"]["score"] if scan.get("headers") else "?"
            c_score = scan["cookies"]["score"]["score"] if scan.get("cookies") else "?"
            print(f"     Headers: {h_score}/100  Cookies: {c_score}/100")

        scanned.append(scan)

    # Step 3: Attack inference
    bulk_results = []
    if run_inference:
        bulk_input = [
            {"url": s["url"], "findings": s}
            for s in scanned if not s.get("error")
        ]
        bulk_results = infer_bulk(bulk_input)
        print_bulk_report(bulk_results)

    return {
        "meta": {
            "domain": domain,
            "timestamp": datetime.now().isoformat(),
            "tool": "SecurityRecon v2.0 full-recon",
            "targets_scanned": len(scanned),
        },
        "subdomain_enum": enum_results,
        "scans": scanned,
        "bulk_inference": bulk_results,
    }


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🛡️  Security Recon Tool — Headers + Cookies + Subdomains + Attack Inference",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python main.py https://example.com
  python main.py example.com --full-recon
  python main.py https://example.com --json report.json
  python main.py https://example.com --headers-only
  python main.py https://example.com --cookies-only
  python main.py example.com --full-recon --json recon.json --threads 30
  python main.py https://example.com --quiet
        """
    )
    parser.add_argument("target", help="URL (single scan) or domain (full-recon)")
    parser.add_argument("--full-recon", action="store_true",
                        help="Enumerate subdomains, scan all, run attack inference")
    parser.add_argument("--json", metavar="FILE", help="Save JSON report to file")
    parser.add_argument("--timeout", type=int, default=10,
                        help="Request timeout per target in seconds (default: 10)")
    parser.add_argument("--threads", type=int, default=20,
                        help="Threads for subdomain probing (default: 20)")
    parser.add_argument("--headers-only", action="store_true",
                        help="Headers only (single URL mode)")
    parser.add_argument("--cookies-only", action="store_true",
                        help="Cookies only (single URL mode)")
    parser.add_argument("--no-inference", action="store_true",
                        help="Skip attack inference")
    parser.add_argument("--quiet", action="store_true",
                        help="Score summary only")

    args = parser.parse_args()

    # ── Full Recon ────────────────────────────────────────────────────────────
    if args.full_recon:
        domain = extract_domain(args.target) if args.target.startswith("http") else args.target
        result = full_recon(domain, timeout=args.timeout, threads=args.threads,
                            run_inference=not args.no_inference)
        if args.json:
            with open(args.json, "w") as f:
                json.dump(result, f, indent=2, default=str)
            print(f"\n  📄 Full recon JSON saved: {args.json}")
        return

    # ── Single URL ────────────────────────────────────────────────────────────
    run_headers = not args.cookies_only
    run_cookies = not args.headers_only

    print(f"\n  🛡️  Scanning: {args.target}")
    scan = scan_target(args.target, run_headers=run_headers,
                       run_cookies=run_cookies, timeout=args.timeout)

    if scan.get("error"):
        print(f"\n  ❌ {scan['error']}")
        sys.exit(1)

    if args.quiet:
        scores = []
        if scan.get("headers"):
            scores.append(scan["headers"]["score"]["score"])
        if scan.get("cookies"):
            scores.append(scan["cookies"]["score"]["score"])
        if scores:
            overall = sum(scores) // len(scores)
            grade = "A" if overall >= 80 else "B" if overall >= 60 else "C" if overall >= 40 else "F"
            print(f"\n  Overall Score: {overall}/100  Grade: {grade}\n")
        return

    print_single_report(scan, show_inference=not args.no_inference)

    if args.json:
        scores = []
        if scan.get("headers"):
            scores.append(scan["headers"]["score"]["score"])
        if scan.get("cookies"):
            scores.append(scan["cookies"]["score"]["score"])
        overall = sum(scores) // max(1, len(scores))
        report = {
            "meta": {
                "url": args.target,
                "resolved_url": scan.get("final_url"),
                "status_code": scan.get("status_code"),
                "timestamp": datetime.now().isoformat(),
                "tool": "SecurityRecon v2.0",
            },
            "overall_score": {"score": overall},
            "headers": scan.get("headers"),
            "cookies": scan.get("cookies"),
            "attack_vectors": infer(scan) if not args.no_inference else [],
        }
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"  📄 JSON report saved: {args.json}")


if __name__ == "__main__":
    main()
