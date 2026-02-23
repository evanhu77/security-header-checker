# 🛡️ Security Recon Tool

A modular Python recon suite for passive security analysis of web targets. Analyzes HTTP security headers, cookie flags, enumerates subdomains via certificate transparency logs, and maps findings to actionable attack vectors — all from a single command.

Built as a bug bounty recon workflow tool and portfolio project.

---

## What It Does

Point it at a domain and it tells you:
- Which security headers are missing or misconfigured, and why they matter
- Which cookies are vulnerable (missing `HttpOnly`, `Secure`, `SameSite`)
- Every subdomain that's ever had a TLS certificate issued (via crt.sh)
- Which of those subdomains are live and worth investigating
- What attack types are plausible based on the combined findings — with confidence levels and specific next steps

The attack inference layer is the key feature. Rather than just reporting "X-Frame-Options is missing", it connects the dots: missing CSP + session cookie without `HttpOnly` = XSS-to-session-hijacking chain worth investigating. It tells you *where to look next*, not just what's wrong.

---

## Project Structure

```
security-header-checker/
├── main.py              # Entry point — orchestrates all modules
├── header_checker.py    # HTTP security header analysis
├── cookie_checker.py    # Set-Cookie flag analysis
├── subdomain_enum.py    # crt.sh subdomain discovery + liveness probing
└── attack_inference.py  # Maps findings to attack vectors with next steps
```

Each module works standalone or as an importable library.

---

## Installation

```bash
git clone https://github.com/YOUR_USERNAME/security-header-checker.git
cd security-header-checker
pip install requests
```

No other dependencies. No API keys required.

---

## Usage

### Single URL scan (headers + cookies + inference)
```bash
python main.py https://example.com
```

### Save JSON report
```bash
python main.py https://example.com --json report.json
```

### Full recon mode — subdomain enum + scan all + attack inference
```bash
python main.py example.com --full-recon
python main.py example.com --full-recon --json recon.json --threads 30
```

### Targeted scans
```bash
python main.py https://example.com --headers-only
python main.py https://example.com --cookies-only
python main.py https://example.com --quiet        # score summary only
python main.py https://example.com --no-inference # skip attack inference
```

### Run individual modules standalone
```bash
python header_checker.py https://example.com
python cookie_checker.py https://example.com/login   # hit login pages for cookies
python subdomain_enum.py example.com --json subs.json
python attack_inference.py --findings report.json
```

---

## Example Output

**Single URL scan:**
```
════════════════════════════════════════════════════════════
  🛡️  SECURITY RECON REPORT
════════════════════════════════════════════════════════════
  URL      : https://example.com
  Status   : 200
  Overall  : 52/100  Grade: C  (Poor)
════════════════════════════════════════════════════════════

  ──────────────────────────────────────────────────────
  🔍 HEADERS  ·  Score: 63/100  Grade: B  (Fair)
  ──────────────────────────────────────────────────────

  ❌ Missing (2):

     🔴 [HIGH  ]  Content-Security-Policy
              ↳ Controls resources the browser is allowed to load. Mitigates XSS and data injection.
              Fix: Add a CSP policy. Start with: Content-Security-Policy: default-src 'self'

     🟡 [MEDIUM]  X-Content-Type-Options
              ↳ Prevents MIME-type sniffing.
              Fix: Add: X-Content-Type-Options: nosniff

  💧 Information Leakage (1):

     ⚠️  X-Powered-By: PHP/7.4
              ↳ Reveals backend technology. Remove this header.

  ──────────────────────────────────────────────────────
  🍪 COOKIES  ·  Score: 0/100  Grade: F  ·  2 found
  ──────────────────────────────────────────────────────

     🔴 session_id [SESSION]
        Flags: ✗ HttpOnly  ✗ Secure  ✗ SameSite
        🔴 [HIGH  ]  HttpOnly missing
                 ↳ Attack: XSS-based session hijacking
                   Fix:    Append HttpOnly to the Set-Cookie directive.

  ──────────────────────────────────────────────────────
  🎯 ATTACK INFERENCE  ·  https://example.com
  ──────────────────────────────────────────────────────

  ──────────────────── HIGH PRIORITY ────────────────────

  🔴 Cross-Site Scripting (XSS)  [confidence: HIGH]
     Why: No Content-Security-Policy means XSS payloads won't be blocked by the browser.
     Next steps:
       • Identify all input fields and URL parameters
       • Test for reflected XSS: inject <script>alert(1)</script>
       • Test for stored XSS in any user-controlled persistent fields

  🔴 Session Hijacking via XSS  [confidence: HIGH]
     Why: Session cookie lacks HttpOnly — document.cookie exposes the token directly.
     Next steps:
       • If XSS is found anywhere on the domain, demonstrate cookie theft as escalation
       • Check if the cookie is scoped broadly (Path=/) which maximizes exposure
```

**Full recon mode:**
```
  🛡️  FULL RECON MODE  ·  example.com
════════════════════════════════════════════════════════════
  🌐 SUBDOMAIN ENUMERATION  ·  example.com
  ──────────────────────────────────────────────────────
  Discovered : 47 in certificate logs
  Live       : 23 responding

  ⭐ PRIORITY TARGETS (6):

  api.example.com ⭐
    → https://api.example.com  [200]  93.184.216.34  cloudflare
  dev.example.com ⭐
    → https://dev.example.com  [200]  93.184.216.35  nginx/1.18.0  [NO HTTPS REDIRECT]
  admin.example.com ⭐
    → https://admin.example.com  [403]  93.184.216.36

  🔍 Scanning 23 live targets...
  → api.example.com        Headers: 45/100  Cookies: 0/100
  → dev.example.com        Headers: 20/100  Cookies: F
  ...

  🎯 BULK ATTACK INFERENCE REPORT
  Targets analyzed: 23  |  Targets with HIGH vectors: 8

  🌐 dev.example.com
     Vectors: 3 HIGH  2 MEDIUM
     XSS, Session Hijacking via XSS, Protocol Downgrade (+2 more)
```

---

## Headers Analyzed

| Header | Severity | What It Protects Against |
|--------|----------|--------------------------|
| `Strict-Transport-Security` | HIGH | Protocol downgrade, SSL stripping |
| `Content-Security-Policy` | HIGH | XSS, data injection |
| `X-Frame-Options` | MEDIUM | Clickjacking (also checks CSP `frame-ancestors`) |
| `X-Content-Type-Options` | MEDIUM | MIME confusion attacks |
| `Referrer-Policy` | LOW | Information leakage via referrer |
| `Permissions-Policy` | LOW | Browser feature abuse |
| `Cache-Control` | LOW | Sensitive data cached in browser |
| `X-XSS-Protection` | INFO | Legacy XSS filter (deprecated) |

**Leakage headers detected:** `Server`, `X-Powered-By`, `X-AspNet-Version`, `X-AspNetMvc-Version`

---

## Cookie Flags Analyzed

| Flag | Severity | Attack if Missing |
|------|----------|-------------------|
| `HttpOnly` | HIGH | XSS-based session hijacking via `document.cookie` |
| `Secure` | HIGH | Cookie transmitted over HTTP, interceptable |
| `SameSite` | MEDIUM | Cross-Site Request Forgery (CSRF) |

Session-related cookies (matching patterns like `session`, `token`, `auth`, `jwt`) are automatically flagged for elevated scrutiny.

---

## Attack Inference Rules

The inference engine maps passive findings to likely vulnerability classes:

| Rule | Triggers When | Confidence |
|------|--------------|------------|
| XSS | CSP missing | HIGH |
| XSS — CSP Bypass | `unsafe-inline` present without nonce | MEDIUM |
| Session Hijacking | Session cookie missing `HttpOnly` | HIGH |
| SSL Stripping | Session cookie missing `Secure` | HIGH |
| CSRF | Any cookie missing `SameSite` | MEDIUM |
| Clickjacking | No `X-Frame-Options` and no `frame-ancestors` in CSP | HIGH |
| Protocol Downgrade | HSTS missing | MEDIUM |
| Version-Targeted Attack | Versioned PHP/server info leaked | MEDIUM |
| MIME Confusion | `X-Content-Type-Options` missing | LOW |
| Expanded Attack Surface | Interesting subdomains found (dev/api/admin/staging) | INFO |

---

## Bug Bounty Workflow

This tool is designed as a **first-pass recon step**, not a vulnerability scanner. The intended workflow:

```
1. Find an in-scope target on HackerOne / Bugcrowd
2. Run full recon:  python main.py target.com --full-recon --json recon.json
3. Review attack inference output — focus on HIGH confidence vectors
4. Manually investigate flagged areas with Burp Suite
5. Document and report any confirmed vulnerabilities
```

The tool's output tells you *where to look*. Manual testing confirms whether something is actually exploitable.

**Important:** Only run against targets you have explicit permission to test. Always read the program's scope and rules of engagement before testing anything.

---

## Roadmap

- [ ] Findings tracker — diff runs over time, alert on regressions
- [ ] CORS misconfiguration detection
- [ ] Subdomain takeover detection (unclaimed CNAME targets)
- [ ] Open redirect signals
- [ ] HTML report output
- [ ] `requirements.txt` and proper packaging

---

## Tech Stack

- Python 3.10+
- `requests` — HTTP client
- `concurrent.futures` — parallel subdomain probing
- crt.sh — certificate transparency log API (no key required)

---

## License

MIT
