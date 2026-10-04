# CyberScope

An automated OSINT and security recon tool. Give it a domain, an IP address, or a URL, and it runs eleven checks against it, explains what each result actually means, and can generate a downloadable PDF report.

**Live API:** https://cyberscope-production.up.railway.app/docs
**Live demo (frontend):** https://cyberscope-frontend.vercel.app
**Frontend repo:** https://github.com/AmnaIdrees-09/cyberscope-frontend

![CyberScope screenshot](docs/screenshot-main.png)

> Note: the live backend is hosted on Railway's free tier. The first request after a period of inactivity may take a few seconds to respond while the service wakes up.

## What it checks

| # | Check | What it does |
|---|-------|---------------|
| 1 | DNS records | A, AAAA, MX, NS, CNAME, SOA, TXT lookups, with per-record-type failure detection |
| 2 | WHOIS | Registrar, creation/expiry dates, domain age, flags very recently registered domains |
| 3 | Subdomains | Certificate transparency search via crt.sh, flags dev/staging/admin-sounding hosts |
| 4 | IP reputation | Geolocation (ipwho.is / ip-api.com / ipapi.co, in that order) plus AbuseIPDB abuse score |
| 5 | SSL/TLS | Certificate issuer and expiry, flags expired or soon-to-expire certs |
| 6 | Security headers | Checks for CSP, HSTS, X-Frame-Options, X-Content-Type-Options, Referrer-Policy, Permissions-Policy |
| 7 | Email authentication | SPF and DMARC records, reads the actual DMARC policy (`none` / `quarantine` / `reject`) |
| 8 | URL reputation | VirusTotal scan results, with basic false-positive handling for well-known sites |
| 9 | MITRE ATT&CK mapping | Connects warning/critical findings to real ATT&CK technique IDs |
| 10 | AI summary | Gemini-generated plain-English overview of every finding from the scan |
| 11 | PDF report | Re-runs every check and renders a downloadable report |

## Why these checks matter

Each check exists because it maps to something an attacker or a scanner would actually look for:

- **No SPF/DMARC enforcement** means a domain's email is easy to spoof — this is one of the most common phishing setups.
- **A domain registered days ago** is a classic short-lived phishing pattern.
- **Forgotten dev/staging subdomains** are frequently less monitored and more exploitable than production.
- **Missing security headers** remove browser-level protection against XSS and clickjacking.
- **An expired or invalid TLS certificate** is a real, visible red flag to any visitor and a common sign of neglect.

The tool doesn't just fetch this data — every check has an analysis layer that turns raw output into a plain-language finding with a severity (`critical` / `warning` / `info`), and a failed lookup is always reported as "unavailable," never silently treated as "nothing found."

## Tech stack

- **FastAPI** (Python) for the API
- **dnspython**, **python-whois**, **requests** for the underlying lookups
- **AbuseIPDB**, **VirusTotal**, **crt.sh** as external data sources
- **Google Gemini API** for AI-generated summaries
- **xhtml2pdf** for PDF report generation
- **slowapi** for per-endpoint rate limiting
- In-memory caching (10-minute TTL) so a re-scan or PDF export doesn't repeat every external call

## Architecture
app/
├── api/ # FastAPI routes — thin, just call services and shape responses
├── services/ # Business logic — one file per check, pure functions, unit-testable
├── models/ # Pydantic schemas for request/response validation
├── core/ # Shared infrastructure (cache, rate limiter, SSRF guard)
└── main.py # App setup, CORS, rate limiter, router registration
tests/ # pytest unit tests

Routes never talk to external services directly — every check goes through `services/checks.py`, which adds caching. Any check that connects to a user-supplied hostname (SSL, security headers) resolves and validates the address first via `core/security.py`, rejecting private, loopback, and other non-public IP ranges before making the request.

## Security measures

Since this backend accepts arbitrary domains/IPs/URLs from any caller, two protections are built in:

- **SSRF protection** — before connecting to any caller-supplied hostname, the backend resolves it and confirms the address is genuinely public. This stops the server from being used to probe internal services, cloud metadata endpoints, or private network ranges. Redirects are re-validated at each hop for the same reason.
- **Rate limiting** — every endpoint has a per-IP rate limit (5-20 requests/minute depending on the endpoint's cost), enforced via `slowapi`.

## Running it locally

**Requirements:** Python 3.11+

```bash
git clone https://github.com/AmnaIdrees-09/CyberScope.git
cd CyberScope
python -m venv venv
venv\Scripts\activate        # Windows
# source venv/bin/activate   # macOS/Linux

pip install -r requirements.txt
```

Create a `.env` file in the project root:
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
GEMINI_API_KEY=your_key_here
ALLOWED_ORIGINS=http://localhost:3000

All three API keys are free to obtain (AbuseIPDB, VirusTotal, and Google AI Studio for Gemini).

```bash
uvicorn app.main:app --reload
```

The API is now running at `http://127.0.0.1:8000`. Interactive docs (Swagger UI) are at `http://127.0.0.1:8000/docs`.

## Running the tests

```bash
pytest
```

## API reference

Full interactive documentation is auto-generated at `/docs` (or see the [live version](https://cyberscope-production.up.railway.app/docs)). Key endpoints:
GET /api/investigate/{domain} DNS records + findings
GET /api/whois/{domain} WHOIS + domain age
GET /api/subdomains/{domain} Subdomain enumeration
GET /api/ip/{ip} IP geolocation + reputation
GET /api/ssl/{domain} SSL/TLS certificate check
GET /api/headers/{domain} Security header check
GET /api/email-auth/{domain} SPF/DMARC check
GET /api/url-reputation?url=... VirusTotal URL reputation
POST /api/summary AI summary from a set of findings
POST /api/mitre MITRE ATT&CK mapping from a set of findings
GET /api/report/{domain} Full PDF report

## Deployment

Deployed on [Railway](https://railway.app). Build command: `pip install -r requirements.txt`. Start command: `uvicorn app.main:app --host 0.0.0.0 --port $PORT`. Environment variables (API keys + `ALLOWED_ORIGINS`, set to the deployed frontend's URL) are configured in Railway's dashboard.

## Known limitations

Being upfront about these because they're real, and every real security tool has trade-offs like this:

- **crt.sh** has no official API and occasionally returns errors or times out under load. When this happens, the subdomain check reports "lookup unavailable" rather than falsely claiming there are no subdomains.
- **VirusTotal's free tier** allows roughly 4 requests/minute — fine for personal/demo use, not for production-scale traffic.
- **The MITRE mapping is a small, curated keyword-based mapping**, not the full MITRE ATT&CK dataset. It connects the specific technique IDs this tool can find real evidence for, rather than pretending to cover the whole framework.
- **The cache is in memory**, so it resets whenever the server restarts and isn't shared across multiple server instances.

## What I'd build next

- A persistent cache/database instead of in-memory (so it survives restarts and scales across instances)
- Expanding the MITRE mapping using the full official ATT&CK dataset
- Scheduled/historical scans instead of only on-demand

## License

MIT