"""
HTML Report Generator
Generates a self-contained HTML report with all findings
"""

import json
from datetime import datetime


class HTMLReporter:

    def generate(self, findings, output_file):
        meta = findings.get("meta", {})
        summary = findings.get("summary", {})
        entry_points = findings.get("entry_points", [])
        passive = findings.get("passive", {})

        html = self._build_html(meta, summary, entry_points, passive, findings)

        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html)

    def _severity_badge(self, severity):
        colors = {
            "CRITICAL": "#ff0000",
            "HIGH": "#ff4444",
            "MEDIUM": "#ffaa00",
            "LOW": "#888888",
            "INFO": "#4444ff",
        }
        color = colors.get(severity, "#888888")
        return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:3px;font-size:11px;font-weight:bold;">{severity}</span>'

    def _priority_badge(self, priority):
        if priority >= 10:
            color = "#ff0000"
        elif priority >= 7:
            color = "#ff6600"
        elif priority >= 5:
            color = "#ffaa00"
        else:
            color = "#666666"
        return f'<span style="background:{color};color:white;padding:2px 8px;border-radius:3px;font-weight:bold;">{priority}</span>'

    def _build_html(self, meta, summary, entry_points, passive, findings):
        techs = passive.get("technologies", [])
        subdomains = passive.get("subdomains", [])
        dorks = passive.get("google_dorks", [])
        security_issues = passive.get("security_issues", [])

        # Build entry points rows
        ep_rows = ""
        for i, ep in enumerate(entry_points, 1):
            attacks = ", ".join(ep.get("attack_types", []))
            url = ep.get("url", "")
            ep_rows += f"""
            <tr class="ep-row" data-severity="{ep.get('severity','LOW')}" data-priority="{ep.get('priority',0)}">
                <td>{i}</td>
                <td>{self._priority_badge(ep.get('priority', 0))}</td>
                <td>{self._severity_badge(ep.get('severity', 'LOW'))}</td>
                <td><code style="font-size:11px;">{ep.get('type','').replace('_',' ')}</code></td>
                <td><a href="{url}" target="_blank" style="color:#4af;font-size:11px;">{url[:60]}{'...' if len(url)>60 else ''}</a></td>
                <td style="font-size:11px;">{attacks}</td>
                <td style="font-size:11px;color:#aaa;">{ep.get('attack_hint','')[:80]}</td>
            </tr>
            """

        # Build security issues
        sec_rows = ""
        for issue in security_issues:
            sec_rows += f"""
            <tr>
                <td>{self._severity_badge(issue.get('severity','LOW'))}</td>
                <td>{issue.get('type','').replace('_',' ')}</td>
                <td>{issue.get('header', issue.get('issue', ''))}</td>
                <td style="color:#aaa;font-size:11px;">{issue.get('value','')[:80]}</td>
            </tr>
            """

        # Build subdomain list
        subdomain_items = ""
        for sub in subdomains[:50]:
            subdomain_items += f'<li><a href="https://{sub}" target="_blank" style="color:#4af;">{sub}</a></li>'

        # Dorks
        dork_items = ""
        for dork in dorks:
            encoded = dork.replace('"', '%22').replace(' ', '+')
            dork_items += f'<li><a href="https://google.com/search?q={encoded}" target="_blank" style="color:#4af;">{dork}</a></li>'

        # Top 5 action items
        action_items = ""
        for i, ep in enumerate(entry_points[:5], 1):
            attacks = ", ".join(ep.get("attack_types", []))
            action_items += f"""
            <div style="background:#1a1a2e;border-left:4px solid {'#ff4444' if ep.get('severity')=='HIGH' else '#ffaa00'};
                        padding:15px;margin:10px 0;border-radius:4px;">
                <div style="font-size:18px;font-weight:bold;color:#fff;">
                    [{i}] {ep.get('type','').replace('_',' ').upper()}
                    {self._severity_badge(ep.get('severity','LOW'))}
                    {self._priority_badge(ep.get('priority',0))}
                </div>
                <div style="margin:8px 0;">
                    <strong>URL:</strong> <a href="{ep.get('url','')}" target="_blank" style="color:#4af;">{ep.get('url','')}</a>
                </div>
                <div style="margin:4px 0;color:#ccc;">{ep.get('detail','')}</div>
                <div style="margin:8px 0;color:#ffaa00;">→ {ep.get('attack_hint','')}</div>
                <div style="color:#888;font-size:12px;">Attack types: {attacks}</div>
            </div>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Attack Surface Report — {meta.get('domain','')}</title>
    <style>
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ background: #0d1117; color: #e6edf3; font-family: 'Segoe UI', system-ui, sans-serif; }}
        .header {{ background: linear-gradient(135deg, #1a1a2e, #16213e); padding: 30px; border-bottom: 1px solid #30363d; }}
        .header h1 {{ font-size: 28px; color: #fff; }}
        .header .meta {{ color: #8b949e; margin-top: 8px; font-size: 14px; }}
        .container {{ max-width: 1400px; margin: 0 auto; padding: 20px; }}
        .stats {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 15px; margin: 20px 0; }}
        .stat-card {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; text-align: center; }}
        .stat-card .number {{ font-size: 36px; font-weight: bold; }}
        .stat-card .label {{ color: #8b949e; font-size: 13px; margin-top: 5px; }}
        .section {{ background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin: 20px 0; }}
        .section h2 {{ font-size: 18px; margin-bottom: 15px; color: #fff; padding-bottom: 10px; border-bottom: 1px solid #30363d; }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{ background: #21262d; padding: 10px; text-align: left; font-size: 12px; color: #8b949e; text-transform: uppercase; }}
        td {{ padding: 10px; border-bottom: 1px solid #21262d; font-size: 13px; vertical-align: top; }}
        tr:hover td {{ background: #1c2128; }}
        .tech-badge {{ background: #1f6feb; color: #fff; padding: 2px 10px; border-radius: 12px; font-size: 12px; margin: 2px; display: inline-block; }}
        .filter-bar {{ margin-bottom: 15px; }}
        .filter-btn {{ background: #21262d; border: 1px solid #30363d; color: #e6edf3; padding: 6px 14px; border-radius: 6px; cursor: pointer; margin-right: 5px; font-size: 13px; }}
        .filter-btn:hover {{ background: #30363d; }}
        .filter-btn.active {{ background: #1f6feb; border-color: #1f6feb; }}
        ul {{ padding-left: 20px; }}
        li {{ margin: 4px 0; font-size: 13px; }}
        a {{ color: #58a6ff; text-decoration: none; }}
        a:hover {{ text-decoration: underline; }}
    </style>
</head>
<body>
    <div class="header">
        <h1>⚔️ Attack Surface Report</h1>
        <div class="meta">
            Target: <strong>{meta.get('target','')}</strong> &nbsp;|&nbsp;
            Scan Level: <strong>{meta.get('scan_level','').upper()}</strong> &nbsp;|&nbsp;
            Generated: <strong>{meta.get('timestamp','')}</strong>
        </div>
    </div>

    <div class="container">
        <!-- Stats -->
        <div class="stats">
            <div class="stat-card">
                <div class="number" style="color:#fff;">{summary.get('total_entry_points',0)}</div>
                <div class="label">Total Entry Points</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color:#ff4444;">{summary.get('high_priority',0)}</div>
                <div class="label">High Priority</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color:#ffaa00;">{summary.get('medium_priority',0)}</div>
                <div class="label">Medium Priority</div>
            </div>
            <div class="stat-card">
                <div class="number" style="color:#888;">{summary.get('low_priority',0)}</div>
                <div class="label">Low Priority</div>
            </div>
        </div>

        <!-- Technologies -->
        {'<div class="section"><h2>🔧 Technologies Detected</h2><div>' + ''.join(f'<span class="tech-badge">{t}</span>' for t in techs) + '</div></div>' if techs else ''}

        <!-- Action Items -->
        <div class="section">
            <h2>🎯 Top Action Items — Test These First</h2>
            {action_items if action_items else '<p style="color:#888;">No high priority items found.</p>'}
        </div>

        <!-- Entry Points Table -->
        <div class="section">
            <h2>📋 All Entry Points</h2>
            <div class="filter-bar">
                <button class="filter-btn active" onclick="filterTable('all')">All</button>
                <button class="filter-btn" onclick="filterTable('CRITICAL')">Critical</button>
                <button class="filter-btn" onclick="filterTable('HIGH')">High</button>
                <button class="filter-btn" onclick="filterTable('MEDIUM')">Medium</button>
                <button class="filter-btn" onclick="filterTable('LOW')">Low</button>
            </div>
            <table id="epTable">
                <thead>
                    <tr>
                        <th>#</th><th>Priority</th><th>Severity</th><th>Type</th>
                        <th>URL</th><th>Attack Types</th><th>Hint</th>
                    </tr>
                </thead>
                <tbody>{ep_rows}</tbody>
            </table>
        </div>

        <!-- Security Headers -->
        {'<div class="section"><h2>🛡️ Security Header Issues</h2><table><thead><tr><th>Severity</th><th>Type</th><th>Header</th><th>Value</th></tr></thead><tbody>' + sec_rows + '</tbody></table></div>' if sec_rows else ''}

        <!-- Subdomains -->
        {'<div class="section"><h2>🌐 Subdomains (' + str(len(subdomains)) + ')</h2><ul>' + subdomain_items + '</ul></div>' if subdomains else ''}

        <!-- Google Dorks -->
        {'<div class="section"><h2>🔍 Google Dorks</h2><ul>' + dork_items + '</ul></div>' if dork_items else ''}

    </div>

    <script>
        function filterTable(severity) {{
            const rows = document.querySelectorAll('.ep-row');
            rows.forEach(row => {{
                if (severity === 'all' || row.dataset.severity === severity) {{
                    row.style.display = '';
                }} else {{
                    row.style.display = 'none';
                }}
            }});
            document.querySelectorAll('.filter-btn').forEach(btn => btn.classList.remove('active'));
            event.target.classList.add('active');
        }}
    </script>
</body>
</html>"""
