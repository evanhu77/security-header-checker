#!/usr/bin/env python3
"""
Subdomain Enumerator
--------------------
Discovers subdomains via crt.sh certificate transparency logs,
then probes each one to verify it's live and collects basic metadata.

Can be used standalone or imported as a module by main.py.

Usage:
  python subdomain_enum.py example.com
  python subdomain_enum.py example.com --json subs.json
  python subdomain_enum.py example.com --timeout 5 --threads 20
"""

import argparse
import json
import re
import socket
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from urllib.parse import urlparse

import requests


# ─── crt.sh Discovery ────────────────────────────────────────────────────────

def fetch_crtsh(domain: str, timeout: int = 15) -> list[str]:
    """
    Query crt.sh for all certificates issued for a domain.
    Returns a deduplicated, sorted list of discovered subdomains.

    crt.sh uses certificate transparency logs — every TLS cert issued
    by a trusted CA is logged publicly. No API key needed.
    """
    url = f"https://crt.sh/?q=%.{domain}&output=json"

    try:
        resp = requests.get(url, timeout=timeout, headers={"Accept": "application/json"})
        resp.raise_for_status()
        data = resp.json()
    except requests.exceptions.RequestException as e:
        print(f"  ⚠  crt.sh request failed: {e}")
        return []
    except json.JSONDecodeError:
        print("  ⚠  crt.sh returned unexpected response format")
        return []

    subdomains = set()
    for entry in data:
        # name_value can contain multiple names separated by newlines
        names = entry.get("name_value", "").split("\n")
        for name in names:
            name = name.strip().lower()
            # Filter out wildcards and ensure it's a subdomain of our target
            if name.startswith("*."):
                name = name[2:]
            if name.endswith(f".{domain}") or name == domain:
                # Basic sanitization — only valid hostname chars
                if re.match(r"^[a-z0-9.\-]+$", name):
                    subdomains.add(name)

    return sorted(subdomains)


# ─── Liveness Checking ───────────────────────────────────────────────────────

def check_subdomain(subdomain: str, timeout: int = 5) -> dict:
    """
    Check if a subdomain is live by attempting HTTP/HTTPS connections.
    Returns a result dict with status, redirect info, and server details.
    """
    result = {
        "subdomain": subdomain,
        "live": False,
        "url": None,
        "status_code": None,
        "redirect_url": None,
        "server": None,
        "ip": None,
        "error": None,
    }

    # Resolve IP first — fast fail for dead subdomains
    try:
        result["ip"] = socket.gethostbyname(subdomain)
    except socket.gaierror:
        result["error"] = "DNS resolution failed"
        return result

    # Try HTTPS first, fall back to HTTP
    for scheme in ("https", "http"):
        url = f"{scheme}://{subdomain}"
        try:
            resp = requests.get(
                url,
                timeout=timeout,
                allow_redirects=True,
                headers={"User-Agent": "SecurityRecon/1.0"},
            )
            result["live"] = True
            result["url"] = url
            result["status_code"] = resp.status_code
            result["server"] = resp.headers.get("server", resp.headers.get("Server"))

            # Capture final URL if redirected
            if resp.url != url:
                result["redirect_url"] = resp.url

            # Note if HTTP redirects to HTTPS (good) or stays on HTTP (bad)
            if scheme == "http" and resp.url.startswith("https://"):
                result["http_to_https"] = True
            elif scheme == "http":
                result["http_to_https"] = False

            return result

        except requests.exceptions.SSLError:
            result["ssl_error"] = True
            # Still mark as live — SSL errors are interesting findings
            result["live"] = True
            result["url"] = f"https://{subdomain}"
            result["error"] = "SSL certificate error"
            return result
        except requests.exceptions.ConnectionError:
            continue
        except requests.exceptions.Timeout:
            result["error"] = f"Timeout after {timeout}s"
            return result

    result["error"] = "Connection refused on both HTTP and HTTPS"
    return result


def check_subdomains_concurrent(subdomains: list[str], timeout: int = 5,
                                 threads: int = 20) -> list[dict]:
    """
    Check all subdomains concurrently using a thread pool.
    Returns only live subdomains, sorted by subdomain name.
    """
    results = []
    total = len(subdomains)

    print(f"  Probing {total} subdomains ({threads} threads)...")

    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(check_subdomain, sub, timeout): sub
                   for sub in subdomains}

        completed = 0
        for future in as_completed(futures):
            completed += 1
            result = future.result()
            if result["live"]:
                results.append(result)
            # Progress indicator
            if completed % 20 == 0 or completed == total:
                live_so_far = len(results)
                print(f"  [{completed}/{total}] {live_so_far} live so far...")

    return sorted(results, key=lambda x: x["subdomain"])


# ─── Full Enumeration ─────────────────────────────────────────────────────────

def enumerate(domain: str, timeout: int = 5, threads: int = 20,
              crtsh_timeout: int = 15) -> dict:
    """
    Full subdomain enumeration pipeline:
      1. Query crt.sh for known subdomains
      2. Probe each for liveness
      3. Return structured results

    This is the main function to call when importing as a module.
    """
    # Strip scheme if accidentally passed a URL
    domain = re.sub(r"^https?://", "", domain).split("/")[0].lower()

    print(f"\n  🔍 Enumerating subdomains for: {domain}")
    print(f"  Querying crt.sh...")

    raw_subdomains = fetch_crtsh(domain, timeout=crtsh_timeout)

    if not raw_subdomains:
        print("  No subdomains found via crt.sh")
        return {
            "domain": domain,
            "discovered": 0,
            "live": 0,
            "subdomains": [],
            "timestamp": datetime.now().isoformat(),
        }

    print(f"  Found {len(raw_subdomains)} unique subdomains in certificate logs")

    live_results = check_subdomains_concurrent(raw_subdomains, timeout=timeout,
                                               threads=threads)

    # Flag interesting subdomains worth prioritizing for security testing
    for result in live_results:
        result["interesting"] = _is_interesting(result["subdomain"])

    live_results.sort(key=lambda x: (not x["interesting"], x["subdomain"]))

    return {
        "domain": domain,
        "discovered": len(raw_subdomains),
        "live": len(live_results),
        "subdomains": live_results,
        "timestamp": datetime.now().isoformat(),
    }


def _is_interesting(subdomain: str) -> bool:
    """
    Flag subdomains that are likely to be more interesting for security testing.
    These patterns suggest auth, APIs, admin panels, or staging environments.
    """
    interesting_patterns = re.compile(
        r"(api|auth|login|admin|dev|staging|test|beta|internal|"
        r"portal|dashboard|app|mobile|legacy|old|backup|vpn|"
        r"mail|smtp|ftp|jenkins|gitlab|jira|confluence|grafana)",
        re.IGNORECASE,
    )
    return bool(interesting_patterns.search(subdomain))


# ─── Reporting ────────────────────────────────────────────────────────────────

def print_enum_report(results: dict):
    domain = results["domain"]
    subdomains = results["subdomains"]

    print(f"\n  {'─'*54}")
    print(f"  🌐 SUBDOMAIN ENUMERATION  ·  {domain}")
    print(f"  {'─'*54}")
    print(f"  Discovered : {results['discovered']} in certificate logs")
    print(f"  Live       : {results['live']} responding")

    interesting = [s for s in subdomains if s.get("interesting")]
    if interesting:
        print(f"\n  ⭐ PRIORITY TARGETS ({len(interesting)}):\n")
        for sub in interesting:
            _print_subdomain_line(sub)

    normal = [s for s in subdomains if not s.get("interesting")]
    if normal:
        print(f"\n  📋 ALL LIVE SUBDOMAINS ({len(normal)}):\n")
        for sub in normal:
            _print_subdomain_line(sub)

    print()


def _print_subdomain_line(sub: dict):
    status = sub.get("status_code", "?")
    ip = sub.get("ip", "")
    server = sub.get("server", "")
    ssl_err = " [SSL ERROR]" if sub.get("ssl_error") else ""
    no_https = " [NO HTTPS REDIRECT]" if sub.get("http_to_https") is False else ""
    interesting_tag = " ⭐" if sub.get("interesting") else ""

    server_str = f"  {server}" if server else ""
    print(f"  {sub['subdomain']}{interesting_tag}")
    print(f"    → {sub['url']}  [{status}]  {ip}{server_str}{ssl_err}{no_https}")


def save_enum_json(results: dict, output_file: str):
    with open(output_file, "w") as f:
        json.dump(results, f, indent=2)
    print(f"  📄 JSON saved: {output_file}")


# ─── CLI ─────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="🌐 Subdomain Enumerator — crt.sh certificate transparency",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python subdomain_enum.py example.com
  python subdomain_enum.py example.com --json subs.json
  python subdomain_enum.py example.com --threads 30 --timeout 8
        """
    )
    parser.add_argument("domain", help="Target domain (e.g. example.com)")
    parser.add_argument("--json", metavar="FILE", help="Save JSON output to file")
    parser.add_argument("--timeout", type=int, default=5,
                        help="Per-subdomain probe timeout in seconds (default: 5)")
    parser.add_argument("--threads", type=int, default=20,
                        help="Concurrent probe threads (default: 20)")

    args = parser.parse_args()

    results = enumerate(args.domain, timeout=args.timeout, threads=args.threads)
    print_enum_report(results)

    if args.json:
        save_enum_json(results, args.json)


if __name__ == "__main__":
    main()
