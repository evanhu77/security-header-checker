"""
recon/surface_scraper.py
Scrapes HTML and JS from every discovered route.
Extracts forms, redirect params, ID params, comments, JS endpoints, secrets, CORS.
"""

import re
import time
import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urljoin, parse_qs, urlparse
from rich.console import Console

console = Console()

# ── Parameter categories ──────────────────────────────────────────────────────

REDIRECT_PARAMS = {
    "redirect", "redirect_uri", "redirect_url", "return", "returnurl",
    "returnto", "return_to", "next", "url", "goto", "target", "dest",
    "destination", "continue", "forward", "location", "ref"
}

ID_PARAMS = {
    "id", "user", "user_id", "userid", "uid", "account", "account_id",
    "order", "order_id", "item", "item_id", "product", "product_id",
    "file", "path", "doc", "document", "invoice", "ticket", "report",
    "uuid", "guid", "ref", "record", "resource", "object"
}

SENSITIVE_INPUT_NAMES = {
    "role", "admin", "is_admin", "superuser", "privilege", "group",
    "permission", "token", "api_key", "apikey", "secret", "debug", "internal"
}

# ── LinkFinder pattern (GerbenJavado/LinkFinder) ─────────────────────────────

LINKFINDER_PATTERN = re.compile(
    r"""
    (?:"|')
    (
        (?:[a-zA-Z]{1,10}://|//)
        [^"'/]{1,}
        \.[a-zA-Z]{2,}[^"']{0,}
        |
        (?:/|\.\./|\./)[^"'><,;|()*]
        (?:[a-zA-Z0-9\-_/]{1,})
        (?:\.[a-zA-Z]{1,4}|(?:\?[^"']{0,}))?
        |
        [a-zA-Z0-9_\-/]{1,}/
        [a-zA-Z0-9_\-/]{1,}
        (?:\.[a-zA-Z]{1,4}|(?:\?[^"']{0,}))?
    )
    (?:"|')
    """,
    re.VERBOSE
)

# ── SecretFinder patterns ─────────────────────────────────────────────────────

SECRET_PATTERNS = [
    (re.compile(r'["\']?api[_-]?key["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', re.I), "api_key"),
    (re.compile(r'["\']?secret["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-]{20,})["\']', re.I), "secret"),
    (re.compile(r'["\']?token["\']?\s*[:=]\s*["\']([a-zA-Z0-9_\-\.]{20,})["\']', re.I), "token"),
    (re.compile(r'eyJ[a-zA-Z0-9_\-]+\.eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'), "jwt"),
    (re.compile(r'AKIA[0-9A-Z]{16}'), "aws_access_key_id"),
    (re.compile(r'["\']?bearer\s+([a-zA-Z0-9_\-\.]{20,})["\']', re.I), "bearer_token"),
]


class SurfaceScraper:
    def __init__(self, base_url, domain, session=None, timeout=15):
        self.base_url = base_url
        self.domain = domain
        self.timeout = timeout
        self.session = session or requests.Session()
        self.session.headers.update({
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        })

    def scrape_all(self, urls):
        """Run scraper against all discovered routes, return aggregated findings."""
        results = {
            "forms": [],
            "redirect_params": [],
            "id_params": [],
            "sensitive_inputs": [],
            "comments": [],
            "js_endpoints": [],
            "js_secrets": [],
            "tech_disclosure": [],
            "cors": [],
            "pages_scraped": 0,
        }

        console.print(f"  [dim]Scraping {len(urls)} routes...[/dim]")

        for url in urls:
            try:
                resp = self.session.get(url, timeout=self.timeout, allow_redirects=True)
                content_type = resp.headers.get("Content-Type", "")

                if "text/html" in content_type:
                    self._scrape_html(url, resp.text, results)

                if "javascript" in content_type or url.endswith(".js"):
                    self._scrape_js(url, resp.text, results)
                else:
                    self._scrape_inline_js(url, resp.text, results)

                self._check_cors(url, results)
                results["pages_scraped"] += 1
                time.sleep(0.2)

            except Exception as e:
                console.print(f"  [dim]Scrape failed {url}: {e}[/dim]")

        # Deduplicate JS endpoints
        seen = set()
        unique = []
        for ep in results["js_endpoints"]:
            if ep["endpoint"] not in seen:
                seen.add(ep["endpoint"])
                unique.append(ep)
        results["js_endpoints"] = unique

        self._print_summary(results)
        return results

    def _scrape_html(self, url, html, results):
        """Extract forms, comments, params, meta from HTML."""
        soup = BeautifulSoup(html, "html.parser")

        # Forms
        for form in soup.find_all("form"):
            inputs = []
            sensitive = []
            for inp in form.find_all(["input", "textarea", "select"]):
                name = inp.get("name", "")
                itype = inp.get("type", "text")
                inputs.append({"name": name, "type": itype})
                if name.lower() in SENSITIVE_INPUT_NAMES:
                    sensitive.append(name)

            form_data = {
                "page": url,
                "action": urljoin(url, form.get("action", "")),
                "method": form.get("method", "GET").upper(),
                "inputs": inputs,
            }
            results["forms"].append(form_data)

            if sensitive:
                results["sensitive_inputs"].append({
                    "page": url,
                    "action": form_data["action"],
                    "fields": sensitive
                })

        # Links with interesting parameters
        for tag in soup.find_all("a", href=True):
            href = tag.get("href", "")
            parsed = urlparse(href)
            if parsed.query:
                params = parse_qs(parsed.query)
                for param in params:
                    if param.lower() in REDIRECT_PARAMS:
                        results["redirect_params"].append({"page": url, "param": param, "url": href})
                    if param.lower() in ID_PARAMS:
                        results["id_params"].append({"page": url, "param": param, "url": href})

        # HTML comments
        for comment in soup.find_all(string=lambda text: isinstance(text, Comment)):
            stripped = comment.strip()
            if stripped:
                results["comments"].append({"page": url, "comment": stripped[:200]})

        # Meta tech disclosure
        for meta in soup.find_all("meta"):
            name = meta.get("name", "").lower()
            content = meta.get("content", "")
            if name in ["generator", "framework", "powered-by"] and content:
                results["tech_disclosure"].append({"page": url, "tag": name, "value": content})

    def _is_useful_endpoint(self, endpoint):
        """Filter out MIME types, asset paths, and other noise from LinkFinder results."""
        if len(endpoint) <= 3:
            return False
        if endpoint.startswith("//"):
            return False
        # Filter MIME types (contain / but look like type/subtype)
        mime_prefixes = (
            "application/", "text/", "image/", "multipart/",
            "audio/", "video/", "font/", "zz-application/"
        )
        if any(endpoint.startswith(p) for p in mime_prefixes):
            return False
        # Filter pure asset paths that aren't interesting
        boring_extensions = (".png", ".jpg", ".jpeg", ".gif", ".svg",
                             ".ico", ".woff", ".woff2", ".ttf", ".eot")
        if any(endpoint.endswith(ext) for ext in boring_extensions):
            return False
        return True

    def _scrape_js(self, url, js_text, results):
        """Extract endpoints and secrets from JS content."""
        for match in LINKFINDER_PATTERN.finditer(js_text):
            endpoint = match.group(1)
            if not self._is_useful_endpoint(endpoint):
                continue
            results["js_endpoints"].append({"source": url, "endpoint": endpoint})

        for pattern, label in SECRET_PATTERNS:
            for match in pattern.finditer(js_text):
                value = match.group(0)[:80]
                results["js_secrets"].append({"source": url, "type": label, "value": value})

    def _scrape_inline_js(self, url, html, results):
        """Extract endpoints from inline script tags and linked JS files."""
        soup = BeautifulSoup(html, "html.parser")

        # Inline scripts
        for script in soup.find_all("script"):
            if script.string:
                self._scrape_js(url, script.string, results)

        # Linked JS files — fetch any script that resolves to our domain
        # Handles: relative (/main.js), protocol-relative (//host/main.js), absolute
        for script in soup.find_all("script", src=True):
            src = script["src"]

            # Resolve to absolute URL
            if src.startswith("//"):
                src = "https:" + src
            elif not src.startswith("http"):
                # relative path like "runtime.abc123.js" or "/runtime.js"
                src = urljoin(url, src)

            # Only fetch scripts from our own domain (avoid CDN noise)
            parsed_src = urlparse(src)
            parsed_base = urlparse(self.base_url)
            if parsed_src.netloc and parsed_src.netloc != parsed_base.netloc:
                continue

            try:
                js_resp = self.session.get(src, timeout=15)
                if js_resp.status_code == 200:
                    self._scrape_js(src, js_resp.text, results)
                time.sleep(0.15)
            except Exception:
                pass

    def _check_cors(self, url, results):
        """Test CORS misconfiguration with three origin variations."""
        test_origins = [
            "https://evil.com",
            "null",
            f"https://{self.domain}.evil.com",
        ]
        for origin in test_origins:
            try:
                resp = self.session.get(url, timeout=8, headers={"Origin": origin})
                acao = resp.headers.get("Access-Control-Allow-Origin", "")
                acac = resp.headers.get("Access-Control-Allow-Credentials", "")
                if acao == origin or acao == "*":
                    results["cors"].append({
                        "url": url,
                        "origin_sent": origin,
                        "acao": acao,
                        "credentials": acac,
                        "severity": "HIGH" if acac.lower() == "true" else "MEDIUM"
                    })
                    break
            except Exception:
                pass

    def _print_summary(self, results):
        console.print(
            f"  [dim]Surface scrape complete — "
            f"{len(results['forms'])} forms | "
            f"{len(results['js_endpoints'])} JS endpoints | "
            f"{len(results['js_secrets'])} secrets | "
            f"{len(results['cors'])} CORS issues | "
            f"{len(results['comments'])} comments[/dim]"
        )
