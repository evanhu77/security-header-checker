"""
Active Recon Module
Light: headers, robots.txt, common paths, JS file fetching
Full: deep crawl, form extraction, API endpoint discovery, parameter fuzzing
"""

import requests
import re
import json
import time
from urllib.parse import urlparse, urljoin, parse_qs, urlunparse
from bs4 import BeautifulSoup
from rich.console import Console

console = Console()

# Common paths to check
COMMON_PATHS = [
    "/robots.txt", "/sitemap.xml", "/.well-known/security.txt",
    "/api", "/api/v1", "/api/v2", "/api/v3", "/graphql", "/graphiql",
    "/swagger", "/swagger.json", "/swagger-ui.html", "/api-docs",
    "/openapi.json", "/.env", "/config.json", "/package.json",
    "/admin", "/administrator", "/login", "/signin", "/auth",
    "/dashboard", "/panel", "/manage", "/console",
    "/upload", "/uploads", "/files", "/documents", "/attachments",
    "/backup", "/db", "/database", "/dump",
    "/debug", "/test", "/dev", "/staging",
    "/.git/HEAD", "/.git/config", "/.svn/entries",
    "/wp-admin", "/wp-login.php", "/xmlrpc.php",  # WordPress
    "/phpmyadmin", "/pma",  # PHPMyAdmin
    "/actuator", "/actuator/health", "/actuator/env",  # Spring Boot
    "/metrics", "/health", "/status", "/info",  # Common APIs
    "/__debug__/", "/django-admin/",  # Django
    "/rails/info", "/rails/mailers",  # Rails
]

# Patterns that indicate interesting API parameters
IDOR_PARAM_PATTERNS = re.compile(
    r'(id|user|account|profile|order|invoice|ticket|report|'
    r'document|file|uuid|guid|ref|token|key|hash)[\s]*[=:]',
    re.IGNORECASE
)

# JS endpoint extraction patterns
JS_ENDPOINT_PATTERN = re.compile(
    r'["\']([/][a-zA-Z0-9_\-/]+(?:\?[^"\']*)?)["\']'
)
JS_API_PATTERN = re.compile(
    r'(?:fetch|axios|http\.get|http\.post|ajax)\s*\(\s*["\']([^"\']+)["\']',
    re.IGNORECASE
)


class ActiveRecon:
    def __init__(self, base_url, domain):
        self.base_url = base_url
        self.domain = domain
        self.entry_points = []
        self.session = requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })
        self.timeout = 15
        self.visited = set()
        self.js_files = set()

    def run_light(self, passive_results):
        """Light active: robots, common paths, JS files, forms on homepage"""
        results = {"entry_points": [], "paths_found": [], "js_endpoints": [], "forms": []}

        tasks = [
            ("Checking robots.txt & sitemap", self._check_robots_sitemap, results),
            ("Probing common paths", self._probe_common_paths, results),
            ("Extracting JS endpoints", self._extract_js_endpoints, results),
            ("Analyzing homepage forms", self._analyze_homepage, results),
        ]

        for desc, fn, res in tasks:
            with console.status(f"[cyan]{desc}...[/cyan]"):
                try:
                    fn(res)
                    time.sleep(0.5)  # Polite delay
                except Exception as e:
                    console.print(f"[yellow]⚠[/yellow] {desc} failed: {e}")

        results["entry_points"] = self.entry_points
        self._print_phase_summary("Light Active", results)
        return results

    def run_full(self, passive_results, light_results):
        """Full active: deep crawl, parameter extraction, API fuzzing"""
        results = {"entry_points": [], "crawled_urls": [], "parameters": [], "api_endpoints": []}

        # Seed with discovered URLs
        seed_urls = [self.base_url]
        for ep in light_results.get("entry_points", []):
            if ep.get("url", "").startswith(self.base_url):
                seed_urls.append(ep["url"])

        tasks = [
            ("Deep crawling", lambda r: self._deep_crawl(seed_urls, r), results),
            ("Extracting all parameters", self._extract_parameters, results),
            ("Checking API endpoints", self._check_api_endpoints, results),
            ("Testing for open redirects", self._test_open_redirects, results),
        ]

        for desc, fn, res in tasks:
            with console.status(f"[cyan]{desc}...[/cyan]"):
                try:
                    fn(res)
                    time.sleep(0.5)
                except Exception as e:
                    console.print(f"[yellow]⚠[/yellow] {desc} failed: {e}")

        results["entry_points"] = self.entry_points
        self._print_phase_summary("Full Active", results)
        return results

    def _check_robots_sitemap(self, results):
        """Parse robots.txt and sitemap for hidden paths"""
        # robots.txt
        try:
            resp = self.session.get(f"{self.base_url}/robots.txt", timeout=self.timeout)
            if resp.status_code == 200 and "User-agent" in resp.text:
                results["robots_txt"] = resp.text
                
                disallowed = []
                for line in resp.text.split("\n"):
                    line = line.strip()
                    if line.lower().startswith("disallow:"):
                        path = line.split(":", 1)[1].strip()
                        if path and path != "/":
                            disallowed.append(path)

                results["disallowed_paths"] = disallowed

                for path in disallowed[:20]:  # Cap at 20
                    if any(k in path.lower() for k in ["admin", "api", "upload", "private", "internal"]):
                        self.entry_points.append({
                            "type": "robots_disallowed",
                            "url": urljoin(self.base_url, path),
                            "param": path,
                            "detail": f"Disallowed in robots.txt: {path}",
                            "phase": "light_active",
                            "severity": "MEDIUM",
                            "attack_hint": "Disallowed paths often hide sensitive functionality"
                        })

                console.print(f"  [dim]{len(disallowed)} disallowed paths in robots.txt[/dim]")
        except Exception:
            pass

        # sitemap.xml
        try:
            resp = self.session.get(f"{self.base_url}/sitemap.xml", timeout=self.timeout)
            if resp.status_code == 200:
                urls = re.findall(r'<loc>(.*?)</loc>', resp.text)
                results["sitemap_urls"] = urls[:100]
                console.print(f"  [dim]{len(urls)} URLs in sitemap[/dim]")
        except Exception:
            pass

    def _probe_common_paths(self, results):
        """Check common sensitive paths"""
        found_paths = []

        for path in COMMON_PATHS:
            try:
                url = urljoin(self.base_url, path)
                resp = self.session.get(url, timeout=8, allow_redirects=False)
                
                if resp.status_code in [200, 201, 301, 302, 403, 405]:
                    found_paths.append({
                        "path": path,
                        "url": url,
                        "status": resp.status_code,
                        "size": len(resp.content)
                    })

                    severity = "LOW"
                    attack_hint = "Investigate manually"

                    # Categorize findings
                    if resp.status_code == 200:
                        if any(k in path for k in [".env", "config.json", "package.json", ".git"]):
                            severity = "CRITICAL"
                            attack_hint = "Possible sensitive file exposure — check contents immediately"
                        elif any(k in path for k in ["/api", "/graphql", "/swagger", "openapi"]):
                            severity = "HIGH"
                            attack_hint = "API endpoint accessible — test for auth, IDOR, injection"
                        elif any(k in path for k in ["/admin", "/dashboard", "/panel"]):
                            severity = "HIGH"
                            attack_hint = "Admin panel accessible — test auth bypass"
                        elif any(k in path for k in ["/actuator", "/metrics", "/health"]):
                            severity = "MEDIUM"
                            attack_hint = "Debug/metrics endpoint — may expose internal data"
                    elif resp.status_code == 403:
                        severity = "MEDIUM"
                        attack_hint = "Forbidden but exists — try auth bypass techniques"

                    self.entry_points.append({
                        "type": "discovered_path",
                        "url": url,
                        "param": path,
                        "detail": f"HTTP {resp.status_code} — {path}",
                        "phase": "light_active",
                        "severity": severity,
                        "status_code": resp.status_code,
                        "attack_hint": attack_hint
                    })

                time.sleep(0.1)
            except requests.RequestException:
                pass

        results["paths_found"] = found_paths
        console.print(f"  [dim]{len(found_paths)} paths responded[/dim]")

    def _extract_js_endpoints(self, results):
        """Fetch homepage, find JS files, extract API endpoints from them"""
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, "html.parser")

            # Find all script tags with src
            js_urls = set()
            for script in soup.find_all("script", src=True):
                src = script["src"]
                if src.startswith("//"):
                    src = "https:" + src
                elif src.startswith("/"):
                    src = urljoin(self.base_url, src)
                if self.domain in src or src.startswith(self.base_url):
                    js_urls.add(src)

            results["js_files"] = list(js_urls)
            console.print(f"  [dim]Found {len(js_urls)} JS files[/dim]")

            # Extract endpoints from JS files
            all_endpoints = set()
            for js_url in list(js_urls)[:10]:  # Cap at 10 for light mode
                try:
                    js_resp = self.session.get(js_url, timeout=10)
                    if js_resp.status_code == 200:
                        # Extract API patterns
                        endpoints = JS_API_PATTERN.findall(js_resp.text)
                        path_endpoints = JS_ENDPOINT_PATTERN.findall(js_resp.text)
                        
                        for ep in endpoints + path_endpoints:
                            if ep.startswith("/") and len(ep) > 2:
                                all_endpoints.add(ep)
                    time.sleep(0.2)
                except Exception:
                    pass

            results["js_endpoints"] = list(all_endpoints)

            # Score JS endpoints
            for ep in all_endpoints:
                ep_lower = ep.lower()
                if any(k in ep_lower for k in ["api", "auth", "user", "account", "admin", "upload"]):
                    severity = "HIGH"
                    attack_hint = "API endpoint from JS — test for auth, IDOR, injection"
                elif any(k in ep_lower for k in ["v1", "v2", "v3", "graphql", "rest"]):
                    severity = "HIGH"
                    attack_hint = "Versioned API — check for older unpatched versions"
                elif "?" in ep:
                    severity = "MEDIUM"
                    attack_hint = "URL with parameters — test each for injection/IDOR"
                else:
                    severity = "LOW"
                    attack_hint = "Investigate endpoint manually"

                self.entry_points.append({
                    "type": "js_extracted_endpoint",
                    "url": urljoin(self.base_url, ep) if ep.startswith("/") else ep,
                    "param": ep,
                    "detail": f"Endpoint extracted from JS: {ep}",
                    "phase": "light_active",
                    "severity": severity,
                    "attack_hint": attack_hint
                })

            console.print(f"  [dim]Extracted {len(all_endpoints)} endpoints from JS[/dim]")

        except Exception as e:
            results["js_error"] = str(e)

    def _analyze_homepage(self, results):
        """Extract forms and input fields from homepage"""
        try:
            resp = self.session.get(self.base_url, timeout=self.timeout)
            soup = BeautifulSoup(resp.text, "html.parser")

            forms = []
            for form in soup.find_all("form"):
                form_data = {
                    "action": form.get("action", ""),
                    "method": form.get("method", "GET").upper(),
                    "inputs": []
                }

                for inp in form.find_all(["input", "textarea", "select"]):
                    input_data = {
                        "type": inp.get("type", "text"),
                        "name": inp.get("name", ""),
                        "id": inp.get("id", ""),
                    }
                    form_data["inputs"].append(input_data)

                forms.append(form_data)

                # Classify form type
                inputs_text = str(form_data).lower()
                if any(k in inputs_text for k in ["password", "passwd", "pwd"]):
                    form_type = "login_form"
                    severity = "MEDIUM"
                    attack_hint = "Login form — test for SQLi, credential stuffing, account enum"
                elif any(k in inputs_text for k in ["search", "query", "q="]):
                    form_type = "search_form"
                    severity = "MEDIUM"
                    attack_hint = "Search form — test for XSS, SQLi, SSTI"
                elif any(k in inputs_text for k in ["file", "upload", "attach"]):
                    form_type = "file_upload"
                    severity = "HIGH"
                    attack_hint = "File upload — test extension bypass, path traversal, malicious content"
                elif form_data["method"] == "POST":
                    form_type = "post_form"
                    severity = "MEDIUM"
                    attack_hint = "POST form — test for CSRF, injection in all fields"
                else:
                    form_type = "general_form"
                    severity = "LOW"
                    attack_hint = "Form found — investigate all input fields"

                action_url = form_data["action"]
                if action_url:
                    action_url = urljoin(self.base_url, action_url)
                else:
                    action_url = self.base_url

                self.entry_points.append({
                    "type": form_type,
                    "url": action_url,
                    "param": f"{len(form_data['inputs'])} inputs",
                    "detail": f"{form_data['method']} form with {len(form_data['inputs'])} fields",
                    "phase": "light_active",
                    "severity": severity,
                    "attack_hint": attack_hint,
                    "form_data": form_data
                })

            results["forms"] = forms
            console.print(f"  [dim]Found {len(forms)} forms on homepage[/dim]")

        except Exception as e:
            results["forms_error"] = str(e)

    def _deep_crawl(self, seed_urls, results, max_pages=50):
        """Crawl the site and collect all URLs and parameters"""
        to_visit = set(seed_urls)
        visited = set()
        all_urls = []
        
        while to_visit and len(visited) < max_pages:
            url = to_visit.pop()
            if url in visited:
                continue
            
            try:
                parsed = urlparse(url)
                if parsed.netloc and self.domain not in parsed.netloc:
                    continue

                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                visited.add(url)
                all_urls.append(url)

                if "text/html" not in resp.headers.get("Content-Type", ""):
                    continue

                soup = BeautifulSoup(resp.text, "html.parser")

                # Collect links
                for a in soup.find_all("a", href=True):
                    href = a["href"]
                    full_url = urljoin(url, href)
                    parsed_href = urlparse(full_url)
                    if self.domain in parsed_href.netloc:
                        normalized = urlunparse(parsed_href._replace(fragment=""))
                        if normalized not in visited:
                            to_visit.add(normalized)

                time.sleep(0.3)

            except Exception:
                visited.add(url)
                continue

        results["crawled_urls"] = all_urls
        console.print(f"  [dim]Crawled {len(all_urls)} pages[/dim]")

    def _extract_parameters(self, results):
        """Extract all URL parameters and classify them"""
        crawled = results.get("crawled_urls", [])
        param_findings = {}

        for url in crawled:
            parsed = urlparse(url)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param_name in params:
                    if param_name not in param_findings:
                        param_findings[param_name] = []
                    param_findings[param_name].append(url)

                    # IDOR candidates
                    if IDOR_PARAM_PATTERNS.search(param_name):
                        self.entry_points.append({
                            "type": "idor_candidate",
                            "url": url,
                            "param": param_name,
                            "detail": f"Parameter '{param_name}' looks like an object reference",
                            "phase": "full_active",
                            "severity": "HIGH",
                            "attack_hint": f"Try changing {param_name} value to access other users' data"
                        })

        results["parameters"] = param_findings
        console.print(f"  [dim]Found {len(param_findings)} unique parameters[/dim]")

    def _check_api_endpoints(self, results):
        """Try common API versioning patterns"""
        api_bases = ["/api", "/api/v1", "/api/v2", "/rest", "/service"]
        api_resources = [
            "/users", "/user", "/accounts", "/account",
            "/orders", "/order", "/products", "/product",
            "/profile", "/settings", "/admin", "/config"
        ]

        found_apis = []
        for base in api_bases:
            for resource in api_resources:
                url = urljoin(self.base_url, base + resource)
                try:
                    resp = self.session.get(url, timeout=8, allow_redirects=False)
                    if resp.status_code in [200, 401, 403, 405]:
                        found_apis.append({"url": url, "status": resp.status_code})

                        if resp.status_code == 200:
                            # Check if it returns data
                            try:
                                data = resp.json()
                                self.entry_points.append({
                                    "type": "api_endpoint",
                                    "url": url,
                                    "param": base + resource,
                                    "detail": f"API endpoint returns data: {str(data)[:100]}",
                                    "phase": "full_active",
                                    "severity": "HIGH",
                                    "attack_hint": "Unauthenticated API response — test IDOR by changing IDs"
                                })
                            except Exception:
                                pass
                        elif resp.status_code == 401:
                            self.entry_points.append({
                                "type": "api_endpoint_auth",
                                "url": url,
                                "param": base + resource,
                                "detail": f"API endpoint requires auth (401)",
                                "phase": "full_active",
                                "severity": "MEDIUM",
                                "attack_hint": "Auth-protected API — test auth bypass, JWT issues, header manipulation"
                            })
                    time.sleep(0.15)
                except Exception:
                    pass

        results["api_endpoints"] = found_apis
        console.print(f"  [dim]Found {len(found_apis)} API endpoint responses[/dim]")

    def _test_open_redirects(self, results):
        """Check login/redirect endpoints for open redirect"""
        redirect_params = ["redirect", "redirect_uri", "return", "returnUrl", 
                          "next", "url", "target", "dest", "destination", "continue"]
        
        redirect_endpoints = ["/login", "/signin", "/auth", "/oauth", "/logout"]
        
        for endpoint in redirect_endpoints:
            for param in redirect_params:
                url = f"{self.base_url}{endpoint}?{param}=https://evil.com"
                try:
                    resp = self.session.get(url, timeout=8, allow_redirects=False)
                    if resp.status_code in [301, 302, 303, 307, 308]:
                        location = resp.headers.get("Location", "")
                        if "evil.com" in location:
                            self.entry_points.append({
                                "type": "open_redirect",
                                "url": url,
                                "param": param,
                                "detail": f"Open redirect via {param} parameter — redirects to: {location}",
                                "phase": "full_active",
                                "severity": "MEDIUM",
                                "attack_hint": "Open redirect confirmed — can be used for phishing, OAuth token theft"
                            })
                    time.sleep(0.1)
                except Exception:
                    pass

    def _print_phase_summary(self, phase_name, results):
        from rich.table import Table
        new_eps = results.get("entry_points", [])
        
        high = len([e for e in new_eps if e.get("severity") == "HIGH" or e.get("severity") == "CRITICAL"])
        med = len([e for e in new_eps if e.get("severity") == "MEDIUM"])
        low = len([e for e in new_eps if e.get("severity") == "LOW"])

        console.print(f"[bold]{phase_name} Results:[/bold] "
                     f"[red]{high} HIGH[/red] | "
                     f"[yellow]{med} MEDIUM[/yellow] | "
                     f"[dim]{low} LOW[/dim]")
        console.print()
