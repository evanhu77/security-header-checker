#!/usr/bin/env python3
"""
Attack Surface Mapper
Progressive scanner: passive -> light active -> full active
Integrates header checker, JS analysis, endpoint discovery, and more
"""

import argparse
import sys
import json
import time
from urllib.parse import urlparse
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich import print as rprint

from recon.passive import PassiveRecon
from recon.active import ActiveRecon
from analysis.classifier import EntryPointClassifier
from analysis.scorer import VulnScorer
from output.terminal import TerminalReporter
from output.html_report import HTMLReporter

console = Console()

BANNER = """
[bold red]
╔═══════════════════════════════════════════╗
║       ATTACK SURFACE MAPPER v1.0          ║
║   Progressive Recon & Entry Point Finder  ║
╚═══════════════════════════════════════════╝
[/bold red]
"""

def parse_args():
    parser = argparse.ArgumentParser(
        description="Attack Surface Mapper - Find entry points for bug bounty research"
    )
    parser.add_argument("url", help="Target URL (e.g. https://example.com)")
    parser.add_argument("--passive-only", action="store_true", help="Run passive recon only")
    parser.add_argument("--light", action="store_true", help="Run passive + light active")
    parser.add_argument("--full", action="store_true", help="Run full scan (default)")
    parser.add_argument("--output", "-o", help="Output file prefix (default: target name)")
    parser.add_argument("--json", help="Save raw JSON results to file")
    parser.add_argument("--no-html", action="store_true", help="Skip HTML report")
    parser.add_argument("--no-terminal", action="store_true", help="Skip terminal output")
    return parser.parse_args()


def normalize_url(url):
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    return f"{parsed.scheme}://{parsed.netloc}", parsed.netloc


def determine_scan_level(args):
    if args.passive_only:
        return "passive"
    elif args.light:
        return "light"
    else:
        return "full"


def main():
    args = parse_args()
    console.print(BANNER)

    # Normalize URL
    base_url, domain = normalize_url(args.url)
    output_prefix = args.output or domain.replace(".", "_")
    scan_level = determine_scan_level(args)

    console.print(f"[bold cyan]Target:[/bold cyan] {base_url}")
    console.print(f"[bold cyan]Domain:[/bold cyan] {domain}")
    console.print(f"[bold cyan]Scan Level:[/bold cyan] {scan_level.upper()}")
    console.print(f"[bold cyan]Output:[/bold cyan] {output_prefix}_*")
    console.print()

    all_findings = {
        "meta": {
            "target": base_url,
            "domain": domain,
            "scan_level": scan_level,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S"),
        },
        "entry_points": [],
        "passive": {},
        "active": {},
        "summary": {}
    }

    # ─── PHASE 1: PASSIVE RECON ───────────────────────────────────────────────
    console.print(Panel("[bold yellow]PHASE 1: Passive Recon[/bold yellow] — No direct target contact", 
                       border_style="yellow"))
    
    passive = PassiveRecon(base_url, domain)
    passive_results = passive.run()
    all_findings["passive"] = passive_results

    entry_points = passive_results.get("entry_points", [])
    console.print(f"[green]✓[/green] Passive phase complete — {len(entry_points)} entry points found\n")

    if scan_level == "passive":
        _finalize(all_findings, output_prefix, args)
        return

    # ─── PHASE 2: LIGHT ACTIVE ────────────────────────────────────────────────
    console.print(Panel("[bold yellow]PHASE 2: Light Active[/bold yellow] — Minimal requests to target",
                       border_style="yellow"))

    active = ActiveRecon(base_url, domain)
    light_results = active.run_light(passive_results)
    all_findings["active"]["light"] = light_results

    new_eps = light_results.get("entry_points", [])
    entry_points.extend(new_eps)
    console.print(f"[green]✓[/green] Light active phase complete — {len(new_eps)} new entry points found\n")

    if scan_level == "light":
        _finalize(all_findings, output_prefix, args)
        return

    # ─── PHASE 3: FULL ACTIVE ─────────────────────────────────────────────────
    console.print(Panel("[bold yellow]PHASE 3: Full Active[/bold yellow] — Deep crawl and analysis",
                       border_style="yellow"))

    full_results = active.run_full(passive_results, light_results)
    all_findings["active"]["full"] = full_results

    new_eps = full_results.get("entry_points", [])
    entry_points.extend(new_eps)
    console.print(f"[green]✓[/green] Full active phase complete — {len(new_eps)} new entry points found\n")

    _finalize(all_findings, output_prefix, args)


def _finalize(all_findings, output_prefix, args):
    # Classify and score all entry points
    classifier = EntryPointClassifier()
    scorer = VulnScorer()

    all_eps = []
    all_eps.extend(all_findings["passive"].get("entry_points", []))
    if "light" in all_findings.get("active", {}):
        all_eps.extend(all_findings["active"]["light"].get("entry_points", []))
    if "full" in all_findings.get("active", {}):
        all_eps.extend(all_findings["active"]["full"].get("entry_points", []))

    # Deduplicate
    seen = set()
    unique_eps = []
    for ep in all_eps:
        key = f"{ep.get('type')}:{ep.get('url', '')}:{ep.get('param', '')}"
        if key not in seen:
            seen.add(key)
            unique_eps.append(ep)

    # Classify and score
    for ep in unique_eps:
        ep["attack_types"] = classifier.classify(ep)
        ep["priority"] = scorer.score(ep)

    # Sort by priority
    unique_eps.sort(key=lambda x: x.get("priority", 0), reverse=True)
    all_findings["entry_points"] = unique_eps
    all_findings["summary"] = {
        "total_entry_points": len(unique_eps),
        "high_priority": len([e for e in unique_eps if e.get("priority", 0) >= 7]),
        "medium_priority": len([e for e in unique_eps if 4 <= e.get("priority", 0) < 7]),
        "low_priority": len([e for e in unique_eps if e.get("priority", 0) < 4]),
    }

    # Output
    if not args.no_terminal:
        reporter = TerminalReporter(console)
        reporter.report(all_findings)

    if args.json:
        with open(args.json, "w") as f:
            json.dump(all_findings, f, indent=2)
        console.print(f"[green]✓[/green] JSON saved to {args.json}")

    if not args.no_html:
        html_reporter = HTMLReporter()
        html_file = f"{output_prefix}_report.html"
        html_reporter.generate(all_findings, html_file)
        console.print(f"[green]✓[/green] HTML report saved to {html_file}")


if __name__ == "__main__":
    main()
