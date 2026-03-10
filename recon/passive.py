"""
Passive Recon Module
Gathers info without directly touching the target:
- crt.sh subdomain enumeration
- Wayback Machine endpoint discovery
- Google dork suggestions
- SecurityHeaders check
- DNS records
"""

import requests
import json
import time
import re
from urllib.parse import urlparse, urljoin
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn

console = Console()


class PassiveRecon:
    def __init__(self, base_url, domain):
        self.base_url = base_url
        self.domain = domain
        self.entry_points = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (compatible; SecurityResearch/1.0)"
        })
        self.timeout = 15

    def run(self):
        results = {
            "subdomains": [],
            "wayback_urls": [],
            "headers": {},
            "cookies": [],
            "dns": {},
            "js_files": [],
            "entry_points": [],
            "google_dorks": [],
        }

        tasks = [
            ("Checking security headers", self._check_headers, results),
            ("Enumerating subdomains via crt.sh", self._crt_subdomains, results),
            ("Fetching Wayback Machine URLs", self._wayback_urls, results),
            ("Checking DNS records", self._dns_records, results),
            ("Generating Google dorks", self._google_dorks, results),
        ]

        for desc, fn, res in tasks:
            with console.status(f"[cyan]{desc}...[/cyan]"):
                try:
                    fn(res)
                except Exception as e:
                    console.print(f"[yellow]⚠[/yellow] {desc} failed: {e}")

        results["entry_points"] = self.entry_points
        self._print_passive_summary(results)
        return results

    def _check_headers(self, results):
        """Check security headers and cookies - integrates header checker logic"""
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout, allow_redirects=True)
            headers = dict(resp.headers)
            results["headers"] = headers
            results["final_url"] = resp.url
            results["status_code"] = resp.status_code

            # Security header analysis
            security_issues = []
            
            missing_headers = {
                "Strict-Transport-Security": "HIGH",
                "Content-Security-Policy": "HIGH", 
                "X-Frame-Options": "MEDIUM",
                "X-Content-Type-Options": "MEDIUM",
                "Referrer-Policy": "LOW",
                "Permissions-Policy": "LOW",
            }

            for header, severity in missing_headers.items():
                if header not in headers:
                    security_issues.append({
                        "type": "missing_header",
                        "header": header,
                        "severity": severity
                    })

            # Check for info leakage
            leak_headers = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]
            for h in leak_headers:
                if h in headers:
                    security_issues.append({
                        "type": "info_disclosure",
                        "header": h,
                        "value": headers[h],
                        "severity": "LOW"
                    })

            # CSP analysis
            csp = headers.get("Content-Security-Policy", "")
            if csp:
                if "'unsafe-inline'" in csp:
                    security_issues.append({
                        "type": "weak_csp",
                        "issue": "unsafe-inline in CSP",
                        "severity": "MEDIUM"
                    })
                if "'unsafe-eval'" in csp:
                    security_issues.append({
                        "type": "weak_csp", 
                        "issue": "unsafe-eval in CSP",
                        "severity": "MEDIUM"
                    })

            results["security_issues"] = security_issues

            # Cookie analysis
            cookies = []
            for cookie in resp.cookies:
                cookie_issues = []
                if not cookie.has_nonstandard_attr("HttpOnly"):
                    cookie_issues.append({"flag": "HttpOnly", "severity": "HIGH"})
                if not cookie.secure:
                    cookie_issues.append({"flag": "Secure", "severity": "HIGH"})
                if not cookie.has_nonstandard_attr("SameSite"):
                    cookie_issues.append({"flag": "SameSite", "severity": "MEDIUM"})

                cookies.append({
                    "name": cookie.name,
                    "issues": cookie_issues,
                    "is_session": any(k in cookie.name.lower() 
                                     for k in ["session", "token", "auth", "jwt", "sid"])
                })

                if cookie_issues and any(i["severity"] == "HIGH" for i in cookie_issues):
                    self.entry_points.append({
                        "type": "insecure_cookie",
                        "url": self.base_url,
                        "param": cookie.name,
                        "detail": f"Cookie missing: {', '.join(i['flag'] for i in cookie_issues)}",
                        "phase": "passive",
                        "severity": "MEDIUM",
                        "attack_hint": "Requires XSS to exploit - look for injection points"
                    })

            results["cookies"] = cookies

            # Tech detection from headers
            tech = self._detect_tech(headers, resp.text[:5000] if resp.text else "")
            results["technologies"] = tech

        except requests.RequestException as e:
            results["headers_error"] = str(e)

    def _detect_tech(self, headers, body):
        """Detect technologies from headers and body"""
        tech = []
        
        server = headers.get("Server", "")
        powered_by = headers.get("X-Powered-By", "")
        
        indicators = {
            "nginx": "nginx",
            "apache": "Apache",
            "cloudflare": "Cloudflare",
            "php": "PHP",
            "asp.net": "ASP.NET",
            "express": "Express.js",
            "django": "Django",
            "rails": "Ruby on Rails",
            "wordpress": "WordPress",
            "drupal": "Drupal",
            "react": "React",
            "angular": "Angular",
            "vue": "Vue.js",
            "next.js": "Next.js",
            "graphql": "GraphQL",
        }

        combined = (server + powered_by + body).lower()
        for key, name in indicators.items():
            if key in combined:
                tech.append(name)

        # GraphQL is a big one for bug bounty
        if "graphql" in combined or "/graphql" in body or "/api/graphql" in body:
            self.entry_points.append({
                "type": "graphql_endpoint",
                "url": urljoin(self.base_url, "/graphql"),
                "detail": "GraphQL detected - try introspection query",
                "phase": "passive",
                "severity": "HIGH",
                "attack_hint": "Run introspection: {__schema{types{name}}} — check for IDOR, auth bypass"
            })

        return list(set(tech))

    def _crt_subdomains(self, results):
        """Enumerate subdomains via crt.sh certificate transparency"""
        try:
            resp = self.session.get(
                f"https://crt.sh/?q=%.{self.domain}&output=json",
                timeout=20
            )
            if resp.status_code == 200:
                data = resp.json()
                subdomains = set()
                for cert in data:
                    name = cert.get("name_value", "")
                    for sub in name.split("\n"):
                        sub = sub.strip().lstrip("*.")
                        if sub.endswith(self.domain) and sub != self.domain:
                            subdomains.add(sub)

                results["subdomains"] = list(subdomains)

                # Interesting subdomain patterns
                interesting_patterns = [
                    "api", "admin", "dev", "staging", "test", "beta", "internal",
                    "dashboard", "portal", "app", "mobile", "legacy", "old",
                    "vpn", "mail", "jenkins", "gitlab", "jira", "confluence"
                ]

                for sub in subdomains:
                    sub_prefix = sub.replace(f".{self.domain}", "").lower()
                    for pattern in interesting_patterns:
                        if pattern in sub_prefix:
                            self.entry_points.append({
                                "type": "interesting_subdomain",
                                "url": f"https://{sub}",
                                "param": sub,
                                "detail": f"Interesting subdomain pattern: '{pattern}'",
                                "phase": "passive",
                                "severity": "MEDIUM",
                                "attack_hint": f"Check if {sub} has different auth/security posture than main domain"
                            })
                            break

                console.print(f"  [dim]Found {len(subdomains)} subdomains[/dim]")
        except Exception as e:
            results["subdomains_error"] = str(e)

    def _wayback_urls(self, results):
        """Fetch historical URLs from Wayback Machine CDX API"""
        try:
            resp = self.session.get(
                f"https://web.archive.org/cdx/search/cdx"
                f"?url=*.{self.domain}/*&output=json&fl=original&collapse=urlkey&limit=500",
                timeout=30
            )
            if resp.status_code == 200:
                data = resp.json()
                urls = [row[0] for row in data[1:] if row]  # Skip header row
                results["wayback_urls"] = urls[:200]  # Cap at 200

                # Extract interesting patterns
                param_pattern = re.compile(r'\?.*=')
                api_pattern = re.compile(r'/api/|/v\d+/|\.json|\.xml')
                upload_pattern = re.compile(r'upload|file|attach|image|document', re.I)
                admin_pattern = re.compile(r'admin|dashboard|manage|panel|console', re.I)

                interesting_urls = set()
                for url in urls:
                    if param_pattern.search(url):
                        interesting_urls.add(("param_url", url, "URL with parameters - test for injection/IDOR"))
                    elif api_pattern.search(url):
                        interesting_urls.add(("api_endpoint", url, "API endpoint found in historical data"))
                    elif upload_pattern.search(url):
                        interesting_urls.add(("file_upload", url, "Possible file upload endpoint"))
                    elif admin_pattern.search(url):
                        interesting_urls.add(("admin_panel", url, "Admin/management panel"))

                for ep_type, url, detail in list(interesting_urls)[:50]:
                    self.entry_points.append({
                        "type": ep_type,
                        "url": url,
                        "detail": detail,
                        "phase": "passive",
                        "severity": "MEDIUM" if ep_type in ["admin_panel", "file_upload"] else "LOW",
                        "attack_hint": self._get_attack_hint(ep_type)
                    })

                console.print(f"  [dim]Found {len(urls)} historical URLs, {len(interesting_urls)} interesting[/dim]")
        except Exception as e:
            results["wayback_error"] = str(e)

    def _dns_records(self, results):
        """Check DNS records for interesting info"""
        import subprocess
        dns_data = {}
        
        for record_type in ["A", "CNAME", "MX", "TXT", "NS"]:
            try:
                result = subprocess.run(
                    ["dig", "+short", record_type, self.domain],
                    capture_output=True, text=True, timeout=10
                )
                if result.stdout.strip():
                    dns_data[record_type] = result.stdout.strip().split("\n")
            except Exception:
                pass

        results["dns"] = dns_data

        # Check TXT records for interesting info (API keys, verification tokens, etc.)
        txt_records = dns_data.get("TXT", [])
        for txt in txt_records:
            if any(k in txt.lower() for k in ["verification", "site-verify", "google-site"]):
                pass  # Normal
            elif any(k in txt.lower() for k in ["key", "token", "secret", "password"]):
                self.entry_points.append({
                    "type": "dns_info_disclosure",
                    "url": f"DNS TXT: {self.domain}",
                    "detail": f"Sensitive data in TXT record: {txt[:100]}",
                    "phase": "passive",
                    "severity": "HIGH",
                    "attack_hint": "Potential credential/key exposure in DNS"
                })

    def _google_dorks(self, results):
        """Generate useful Google dorks for manual searching"""
        domain = self.domain
        dorks = [
            f'site:{domain} ext:php OR ext:asp OR ext:aspx OR ext:jsp "login"',
            f'site:{domain} inurl:api OR inurl:v1 OR inurl:v2',
            f'site:{domain} inurl:admin OR inurl:dashboard OR inurl:panel',
            f'site:{domain} inurl:upload OR inurl:file OR inurl:attachment',
            f'site:{domain} ext:json OR ext:xml OR ext:yaml',
            f'site:{domain} inurl:?id= OR inurl:?user= OR inurl:?account=',
            f'site:{domain} "internal server error" OR "stack trace" OR "debug"',
            f'site:{domain} filetype:pdf OR filetype:doc OR filetype:xls',
            f'"{domain}" inurl:github.com',
            f'site:{domain} inurl:reset OR inurl:forgot OR inurl:recover',
        ]
        results["google_dorks"] = dorks

    def _get_attack_hint(self, ep_type):
        hints = {
            "param_url": "Test each parameter for SQLi, XSS, IDOR — try changing IDs to other users",
            "api_endpoint": "Check for missing auth, IDOR, rate limiting, verbose errors",
            "file_upload": "Test file type bypass, path traversal, malicious content",
            "admin_panel": "Check if accessible without auth, test default credentials",
            "interesting_subdomain": "May have weaker security than main domain",
        }
        return hints.get(ep_type, "Manual investigation recommended")

    def _print_passive_summary(self, results):
        from rich.table import Table
        
        table = Table(title="Passive Recon Summary", border_style="cyan")
        table.add_column("Category", style="cyan")
        table.add_column("Count", style="white")
        table.add_column("Notable", style="yellow")

        table.add_row(
            "Subdomains",
            str(len(results.get("subdomains", []))),
            f"{len([e for e in self.entry_points if e['type'] == 'interesting_subdomain'])} interesting"
        )
        table.add_row(
            "Wayback URLs",
            str(len(results.get("wayback_urls", []))),
            f"{len([e for e in self.entry_points if e['phase'] == 'passive' and 'url' in e['type']])} with params"
        )
        table.add_row(
            "Security Issues",
            str(len(results.get("security_issues", []))),
            f"{len([i for i in results.get('security_issues', []) if i.get('severity') == 'HIGH'])} HIGH"
        )
        table.add_row(
            "Technologies",
            str(len(results.get("technologies", []))),
            ", ".join(results.get("technologies", [])[:3])
        )
        table.add_row(
            "Entry Points Found",
            str(len(self.entry_points)),
            f"Phase 1 total"
        )

        console.print(table)
        console.print()
