#!/usr/bin/env python3
"""
Security Header Checker - Portfolio Project
Analyzes HTTP security headers for a given URL and generates a report.
"""

import requests
import json
import argparse
from datetime import datetime
from urllib.parse import urlparse

# ─── Security Header Definitions ────────────────────────────────────────────

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "severity": "HIGH",
        "description": "Enforces HTTPS connections. Prevents protocol downgrade attacks and cookie hijacking.",
        "recommendation": "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Strict-Transport-Security",
    },
    "Content-Security-Policy": {
        "severity": "HIGH",
        "description": "Controls resources the browser is allowed to load. Mitigates XSS and data injection.",
        "recommendation": "Add a CSP policy. Start with: Content-Security-Policy: default-src 'self'",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Content-Security-Policy",
    },
    "X-Frame-Options": {
        "severity": "MEDIUM",
        "description": "Prevents clickjacking by controlling whether the page can be embedded in frames.",
        "recommendation": "Add: X-Frame-Options: DENY  (or SAMEORIGIN if framing is needed internally)",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Frame-Options",
    },
    "X-Content-Type-Options": {
        "severity": "MEDIUM",
        "description": "Prevents MIME-type sniffing. Stops browsers from interpreting files as a different MIME type.",
        "recommendation": "Add: X-Content-Type-Options: nosniff",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options",
    },
    "Referrer-Policy": {
        "severity": "LOW",
        "description": "Controls how much referrer information is included with requests.",
        "recommendation": "Add: Referrer-Policy: strict-origin-when-cross-origin",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Referrer-Policy",
    },
    "Permissions-Policy": {
        "severity": "LOW",
        "description": "Controls browser features and APIs (camera, mic, geolocation, etc.).",
        "recommendation": "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Permissions-Policy",
    },
    "Cache-Control": {
        "severity": "LOW",
        "description": "Controls caching behavior. Sensitive pages should not be cached.",
        "recommendation": "For sensitive pages: Cache-Control: no-store, no-cache, must-revalidate",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/Cache-Control",
    },
    "X-XSS-Protection": {
        "severity": "INFO",
        "description": "Legacy XSS filter (deprecated in modern browsers, but still checked by some scanners).",
        "recommendation": "Add: X-XSS-Protection: 1; mode=block  (Note: CSP is the modern replacement)",
        "docs": "https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-XSS-Protection",
    },
}

LEAKY_HEADERS = {
    "Server": "Reveals server software and version. Consider removing or obscuring.",
    "X-Powered-By": "Reveals backend technology (e.g. PHP/7.4). Remove this header.",
    "X-AspNet-Version": "Reveals ASP.NET version. Remove via customHeaders config.",
    "X-AspNetMvc-Version": "Reveals ASP.NET MVC version. Disable in Global.asax.",
}

SEVERITY_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2, "INFO": 3}
SEVERITY_EMOJI = {"HIGH": "🔴", "MEDIUM": "🟡", "LOW": "🔵", "INFO": "⚪"}


# ─── Core Analysis ───────────────────────────────────────────────────────────

def fetch_headers(url: str, timeout: int = 10) -> dict:
    """Fetch HTTP headers from a URL."""
    if not url.startswith(("http://", "https://")):
        url = "https://" + url

    response = requests.get(url, timeout=timeout, allow_redirects=True)
    return {k.lower(): v for k, v in response.headers.items()}, response.url, response.status_code


def analyze_headers(raw_headers: dict) -> dict:
    """Analyze headers and return structured findings."""
    headers_lower = {k.lower(): v for k, v in raw_headers.items()}

    missing = []
    present = []
    leaking = []
    warnings = []

    # Extract CSP value once — used for cross-header logic below
    csp_value = headers_lower.get("content-security-policy", "")

    # Check for missing security headers
    for header, info in SECURITY_HEADERS.items():
        header_lower = header.lower()
        if header_lower not in headers_lower:

            # X-Frame-Options: skip penalty if CSP contains frame-ancestors.
            # frame-ancestors is the modern CSP equivalent and supersedes
            # X-Frame-Options in all browsers that support CSP Level 2+.
            if header == "X-Frame-Options" and "frame-ancestors" in csp_value:
                present.append({
                    "header": header,
                    "value": "Covered by CSP frame-ancestors directive",
                    "severity": info["severity"],
                    "note": "Clickjacking protection provided via Content-Security-Policy frame-ancestors",
                })
                continue

            missing.append({
                "header": header,
                "severity": info["severity"],
                "description": info["description"],
                "recommendation": info["recommendation"],
                "docs": info["docs"],
            })
        else:
            value = headers_lower[header_lower]
            finding = {
                "header": header,
                "value": value,
                "severity": info["severity"],
            }
            # Warn on weak values
            if header == "Strict-Transport-Security" and "max-age" in value:
                max_age = int(''.join(filter(str.isdigit, value.split("max-age=")[1].split(";")[0])))
                if max_age < 31536000:
                    finding["warning"] = f"max-age={max_age} is less than recommended 31536000 (1 year)"
                    warnings.append(finding)
            if header == "Content-Security-Policy" and "unsafe-inline" in value:
                # Only warn if unsafe-inline is in script-src context, not just style-src-attr
                # style-src-attr unsafe-inline is less dangerous than script-src unsafe-inline
                csp_lower = value.lower()
                script_src_unsafe = (
                    ("script-src" in csp_lower and "'unsafe-inline'" in csp_lower)
                    and "nonce-" not in csp_lower  # nonce neutralizes unsafe-inline for scripts
                )
                style_attr_only = (
                    "style-src-attr 'unsafe-inline'" in value
                    and "script-src" not in csp_lower.split("style-src-attr")[0].split("script-src")[-1]
                )
                if script_src_unsafe:
                    finding["warning"] = "'unsafe-inline' in script-src critically weakens XSS protection"
                elif style_attr_only:
                    finding["warning"] = "'unsafe-inline' in style-src-attr allows CSS injection (lower risk than script unsafe-inline)"
                else:
                    finding["warning"] = "'unsafe-inline' present — review which directives are affected"
                warnings.append(finding)
            present.append(finding)

    # Check for leaky headers
    for header, description in LEAKY_HEADERS.items():
        header_lower = header.lower()
        if header_lower in headers_lower:
            leaking.append({
                "header": header,
                "value": headers_lower[header_lower],
                "description": description,
            })

    # Sort missing by severity
    missing.sort(key=lambda x: SEVERITY_ORDER.get(x["severity"], 99))

    return {
        "missing": missing,
        "present": present,
        "leaking": leaking,
        "warnings": warnings,
        "score": calculate_score(missing, leaking, warnings),
    }


def calculate_score(missing: list, leaking: list, warnings: list) -> dict:
    """Calculate a security score (0-100)."""
    deductions = 0
    deductions += sum({"HIGH": 25, "MEDIUM": 15, "LOW": 5, "INFO": 2}.get(h["severity"], 0) for h in missing)
    deductions += len(leaking) * 5
    deductions += len(warnings) * 5

    score = max(0, 100 - deductions)

    if score >= 80:
        grade, label = "A", "Good"
    elif score >= 60:
        grade, label = "B", "Fair"
    elif score >= 40:
        grade, label = "C", "Poor"
    else:
        grade, label = "F", "Critical"

    return {"score": score, "grade": grade, "label": label}


# ─── Reporting ───────────────────────────────────────────────────────────────

def print_report(url: str, final_url: str, status_code: int, findings: dict):
    """Print a formatted terminal report."""
    score_info = findings["score"]
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    print("\n" + "═" * 60)
    print("  🔍 SECURITY HEADER ANALYSIS REPORT")
    print("═" * 60)
    print(f"  URL        : {url}")
    if final_url != url:
        print(f"  Resolved   : {final_url}")
    print(f"  Status     : {status_code}")
    print(f"  Scanned    : {timestamp}")
    print(f"  Score      : {score_info['score']}/100  Grade: {score_info['grade']}  ({score_info['label']})")
    print("═" * 60)

    if findings["missing"]:
        print(f"\n❌  MISSING HEADERS ({len(findings['missing'])} found)\n")
        for h in findings["missing"]:
            emoji = SEVERITY_EMOJI.get(h["severity"], "⚪")
            print(f"  {emoji} [{h['severity']}] {h['header']}")
            print(f"     → {h['description']}")
            print(f"     Fix: {h['recommendation']}")
            print()

    if findings["warnings"]:
        print(f"⚠️   MISCONFIGURED HEADERS ({len(findings['warnings'])} found)\n")
        for h in findings["warnings"]:
            print(f"  🟡 {h['header']}: {h['value']}")
            print(f"     → {h['warning']}")
            print()

    if findings["leaking"]:
        print(f"💧  INFORMATION LEAKAGE ({len(findings['leaking'])} found)\n")
        for h in findings["leaking"]:
            print(f"  ⚠️  {h['header']}: {h['value']}")
            print(f"     → {h['description']}")
            print()

    if findings["present"]:
        print(f"✅  PRESENT SECURITY HEADERS ({len(findings['present'])} found)\n")
        for h in findings["present"]:
            print(f"  ✓  {h['header']}")
        print()

    print("═" * 60)
    print()


def save_json_report(url: str, final_url: str, status_code: int, findings: dict, output_file: str):
    """Save findings as JSON."""
    report = {
        "meta": {
            "url": url,
            "resolved_url": final_url,
            "status_code": status_code,
            "timestamp": datetime.now().isoformat(),
            "tool": "SecurityHeaderChecker v1.0",
        },
        "score": findings["score"],
        "summary": {
            "missing_count": len(findings["missing"]),
            "present_count": len(findings["present"]),
            "leaking_count": len(findings["leaking"]),
            "warning_count": len(findings["warnings"]),
        },
        "findings": findings,
    }
    with open(output_file, "w") as f:
        json.dump(report, f, indent=2)
    print(f"  📄 JSON report saved: {output_file}")


# ─── CLI Entry Point ─────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🔍 Security Header Checker - Audit HTTP security headers",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python header_checker.py https://example.com
  python header_checker.py example.com --json report.json
  python header_checker.py https://example.com --timeout 15
        """
    )
    parser.add_argument("url", help="Target URL to scan")
    parser.add_argument("--json", metavar="FILE", help="Save JSON report to file")
    parser.add_argument("--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("--quiet", action="store_true", help="Only show score summary")

    args = parser.parse_args()

    print(f"\n  Scanning: {args.url} ...")

    try:
        raw_headers, final_url, status_code = fetch_headers(args.url, args.timeout)
        findings = analyze_headers(raw_headers)

        if args.quiet:
            s = findings["score"]
            print(f"  Score: {s['score']}/100  Grade: {s['grade']}  ({s['label']})")
        else:
            print_report(args.url, final_url, status_code, findings)

        if args.json:
            save_json_report(args.url, final_url, status_code, findings, args.json)

    except requests.exceptions.ConnectionError:
        print(f"\n  ❌ Error: Could not connect to {args.url}")
    except requests.exceptions.Timeout:
        print(f"\n  ❌ Error: Request timed out after {args.timeout}s")
    except Exception as e:
        print(f"\n  ❌ Unexpected error: {e}")


if __name__ == "__main__":
    main()
