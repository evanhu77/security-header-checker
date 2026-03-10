"""
Terminal Reporter
Rich formatted output showing prioritized entry points
"""

from rich.table import Table
from rich.panel import Panel
from rich.console import Console
from rich import box


class TerminalReporter:
    def __init__(self, console):
        self.console = console

    def report(self, findings):
        meta = findings.get("meta", {})
        summary = findings.get("summary", {})
        entry_points = findings.get("entry_points", [])

        # Header
        self.console.print()
        self.console.print(Panel(
            f"[bold]Target:[/bold] {meta.get('target')}\n"
            f"[bold]Scan Level:[/bold] {meta.get('scan_level', '').upper()}\n"
            f"[bold]Timestamp:[/bold] {meta.get('timestamp')}",
            title="[bold cyan]SCAN COMPLETE[/bold cyan]",
            border_style="cyan"
        ))

        # Summary stats
        self.console.print()
        stats_table = Table(box=box.SIMPLE, show_header=False)
        stats_table.add_column("Metric", style="cyan")
        stats_table.add_column("Value", style="bold white")

        stats_table.add_row("Total Entry Points", str(summary.get("total_entry_points", 0)))
        stats_table.add_row("🔴 High Priority", str(summary.get("high_priority", 0)))
        stats_table.add_row("🟡 Medium Priority", str(summary.get("medium_priority", 0)))
        stats_table.add_row("⚪ Low Priority", str(summary.get("low_priority", 0)))

        self.console.print(Panel(stats_table, title="Summary", border_style="white"))

        if not entry_points:
            self.console.print("[yellow]No entry points found.[/yellow]")
            return

        # Technologies found
        techs = findings.get("passive", {}).get("technologies", [])
        if techs:
            self.console.print(f"\n[bold cyan]Technologies Detected:[/bold cyan] {', '.join(techs)}\n")

        # Top entry points table
        self.console.print(Panel("[bold red]TOP ENTRY POINTS — Start Here[/bold red]", 
                                border_style="red"))

        top_eps = entry_points[:20]  # Show top 20

        ep_table = Table(
            box=box.ROUNDED,
            show_header=True,
            header_style="bold cyan",
            border_style="dim"
        )
        ep_table.add_column("#", width=3)
        ep_table.add_column("Priority", width=8)
        ep_table.add_column("Type", width=22)
        ep_table.add_column("Severity", width=10)
        ep_table.add_column("URL/Target", width=45, no_wrap=True)
        ep_table.add_column("Attack Types", width=35)

        for i, ep in enumerate(top_eps, 1):
            priority = ep.get("priority", 0)
            severity = ep.get("severity", "LOW")

            # Color coding
            if priority >= 10:
                priority_str = f"[bold red]{priority}[/bold red]"
            elif priority >= 7:
                priority_str = f"[red]{priority}[/red]"
            elif priority >= 5:
                priority_str = f"[yellow]{priority}[/yellow]"
            else:
                priority_str = f"[dim]{priority}[/dim]"

            severity_colors = {
                "CRITICAL": "[bold red]CRITICAL[/bold red]",
                "HIGH": "[red]HIGH[/red]",
                "MEDIUM": "[yellow]MEDIUM[/yellow]",
                "LOW": "[dim]LOW[/dim]",
            }
            severity_str = severity_colors.get(severity, severity)

            url = ep.get("url", "")
            if len(url) > 43:
                url = url[:40] + "..."

            attacks = ep.get("attack_types", [])
            attack_str = ", ".join(attacks[:3])
            if len(attacks) > 3:
                attack_str += "..."

            ep_table.add_row(
                str(i),
                priority_str,
                ep.get("type", "").replace("_", " "),
                severity_str,
                url,
                attack_str
            )

        self.console.print(ep_table)

        # Detailed action items for top 5
        self.console.print()
        self.console.print(Panel("[bold yellow]ACTION ITEMS — What to test first[/bold yellow]",
                                border_style="yellow"))

        for i, ep in enumerate(top_eps[:5], 1):
            self.console.print(f"\n[bold cyan][{i}][/bold cyan] [bold]{ep.get('type', '').replace('_', ' ').upper()}[/bold]")
            self.console.print(f"    URL: [link]{ep.get('url', '')}[/link]")
            self.console.print(f"    Detail: {ep.get('detail', '')}")
            self.console.print(f"    [yellow]→ {ep.get('attack_hint', '')}[/yellow]")
            attacks = ep.get("attack_types", [])
            if attacks:
                self.console.print(f"    Attack types: {', '.join(attacks)}")

        # Google dorks
        dorks = findings.get("passive", {}).get("google_dorks", [])
        if dorks:
            self.console.print()
            self.console.print(Panel("[bold]Google Dorks — Manual search these[/bold]",
                                    border_style="dim"))
            for dork in dorks[:5]:
                self.console.print(f"  [dim]{dork}[/dim]")

        self.console.print()
        self.console.print("[bold green]✓ Scan complete. Check HTML report for full details.[/bold green]")
