# 🛡️ Scam & Phishing Infrastructure Triage Workbench

A modular, high-speed Python workbench, CLI tool, and FastAPI web application designed for security analysts, incident responders, and SOC teams to triage suspicious URLs, domains, and IP addresses. 

The workbench performs **100% passive infrastructure enrichment** and automated heuristic risk triage **without ever communicating directly with the target** or exposing internal networks to SSRF vulnerabilities.

---

## 🚀 Key Features

* **URL Deconstruction & Defanging**:
  * Strips, normalizes, and defangs targets (`hxxp://evil[.]com/login`, `192[.]168[.]1[.]1`).
  * Extracts scheme, port, path, query, host, and parses registrable domains using the Public Suffix List (PSL).
* **Passive DNS Resolution** (`dnspython`):
  * Resolves `A` (IPv4), `AAAA` (IPv6), `MX` (mail servers, including RFC 7505 Null MX), `NS` (nameservers), and `TXT` records.
  * Detects and parses `v=spf1` SPF policies and `_dmarc.<domain>` DMARC configurations.
* **Domain Registration & RDAP Lookup** (`rdap.org`):
  * Retrieves registration dates, expiration dates, last update timestamps, and registrar name.
  * Calculates exact domain age in days and remaining days until expiration.
* **Certificate Transparency Discovery** (`crt.sh`):
  * Passively queries public CT logs via `crt.sh` JSON API to uncover hidden or historical subdomains without brute-forcing.
* **Public ASN & Hosting Infrastructure**:
  * Resolves public Autonomous System Numbers (ASN), AS Organization names, BGP prefixes / CIDRs, and country codes via Team Cymru DNS mapping with RDAP IP fallback.
* **Automated Heuristic Risk Engine**:
  * Flags newly registered domains (<30 days), expiring domains, missing/permissive SPF/DMARC policies (`+all`, `p=none`), high-risk phishing keywords, fast-flux DNS TTLs, and raw IP targets.
  * Produces a normalized composite risk score (`0–100`) mapped to risk tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`).
* **FastAPI Web Service & Dark-Mode Terminal UI**:
  * Responsive single-page application (Tailwind CSS CDN) with dark SOC/cybersecurity terminal styling.
  * One-click demo sample case pills (Bank Phish, Crypto Drainer, Benign Reference).
  * **"Download Markdown Brief"** and **"Copy Defanged IoCs"** buttons.
  * `DEMO_MODE_ONLY` environment flag to safely disable live scans when hosted publicly.
  * In-memory thread-safe rate limiter (default: 10 requests/minute per client).
* **Hardened Docker Containerization**:
  * Multi-stage/slim container running as unprivileged `appuser`.
  * `docker-compose.yml` binding exclusively to `127.0.0.1:8000` for reverse-proxy / Cloudflare Tunnel readiness.

---

## 🔒 Strict Security & SSRF Guardrails

1. **Direct-Target Probing Lockout**:
   * The tool **NEVER** sends HTTP requests or connects directly to the target URL, domain, or IP address.
   * `SafeHttpClient` actively enforces a blacklist of the target host and all resolved target IPs; any internal code or plugin attempting to query the target raises an immediate `DirectTargetAccessForbiddenError`.
2. **SSRF & Private Network Blocking**:
   * Outbound network calls to public APIs (`rdap.org`, `crt.sh`) first resolve the API destination host and validate all IPs.
   * Blocks:
     * RFC 1918 Private ranges (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`, `fc00::/7`)
     * Loopback addresses (`127.0.0.1/8`, `::1`)
     * Link-local & Cloud Metadata (`169.254.0.0/16`, `fe80::/10`, `169.254.169.254`, `metadata.google.internal`)
     * Carrier-Grade NAT (`100.64.0.0/10`)
     * Documentation/test networks (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`)
3. **Strict Timeouts & Redirect Controls**:
   * Outbound calls enforce a hard 5.0-second timeout.
   * Automatic HTTP redirects are strictly disabled (`allow_redirects=False`).
   * When following necessary bootstrap redirects (such as `rdap.org` redirection to authoritative TLD registries), every intermediate hop is re-validated through the complete SSRF guardrail before following.

---

## 📦 Installation & Setup

### Prerequisites
* Python 3.10+ (tested on Python 3.14)
* Standard Python `venv`

### Setup

```bash
# Clone repository
git clone https://github.com/example/scam-triage-workbench.git
cd scam-triage-workbench

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 🌐 Web Application & Dark-Mode Terminal UI

Launch the FastAPI web application with `uvicorn`:

```bash
uvicorn app:app --host 127.0.0.1 --port 8000 --reload
```

Then visit **`http://127.0.0.1:8000`** in your browser.

### Key Web Features
- **Live Passive Triage**: Paste any URL, domain, or IP (accepts defanged inputs).
- **One-Click Sample Case Pills**:
  - 🔴 **Case 1: Bank Credential Harvest (Chase Spoof)**: High-risk .top domain with fast-flux DNS.
  - 🟠 **Case 2: Crypto Wallet Drainer (MetaMask Kit)**: Subdomain churn on .xyz TLD with permissive DMARC.
  - 🟢 **Case 3: Benign Baseline (example.com)**: Historical WHOIS age and strict DMARC reject policy.
- **Copy Defanged IoCs**: Formats defanged target, host, IPs, and subdomains directly into your clipboard.
- **Download Markdown Brief**: Generates and downloads a `.md` triage brief for ticket attachments.

### Demo Mode (`DEMO_MODE_ONLY`)
To host the web UI publicly without allowing arbitrary outbound network calls, launch with `DEMO_MODE_ONLY=true`:

```bash
DEMO_MODE_ONLY=true uvicorn app:app --host 0.0.0.0 --port 8000
```
In Demo Mode:
- Live triage queries to `/api/triage` return `HTTP 403 Forbidden`.
- All 3 pre-loaded sample cases remain interactive with zero network calls.

---

## 🐳 Docker Deployment

The workbench includes a production-ready, hardened `Dockerfile` running as non-root `appuser`.

### Using Docker Compose (Recommended)

```bash
# Build and run container in background (binds to 127.0.0.1:8000)
docker compose up -d

# Check container logs
docker compose logs -f

# Verify container healthcheck
docker compose ps

# Stop container
docker compose down
```

### Standalone Docker Build

```bash
# Build image
docker build -t scam-triage-workbench .

# Run container
docker run -d \
  -p 127.0.0.1:8000:8000 \
  --name triage-workbench \
  --restart unless-stopped \
  scam-triage-workbench
```

---

## 💻 CLI Usage

```bash
python3 triage.py <target> [options]
```

### Options

| Flag | Name | Description |
| :--- | :--- | :--- |
| `target` | Positional | Suspicious URL, domain, or IP (accepts raw or defanged) |
| `-o`, `--output` | `--output <path>` | File path to write report (`.md`, `.json`, or base name) |
| `-f`, `--format` | `--format <fmt>` | `text` (terminal summary), `markdown`, `json`, or `all` |
| `-q`, `--quiet` | `--quiet` | Suppress terminal UI output (useful for scripted workflows) |
| `--dns-servers` | `--dns-servers <ips>` | Comma-separated custom DNS resolvers (e.g. `9.9.9.9,1.1.1.1`) |
| `--timeout` | `--timeout <secs>` | Timeout in seconds (capped at 5.0s) |
| `-v`, `--version` | `--version` | Show program version |

### Examples

```bash
# Terminal summary
python3 triage.py example.com

# Defanged Phishing URL with Markdown report
python3 triage.py "hxxps://secure-login-account-update[.]xyz/verify?token=abc" -f markdown -o phishing_report.md

# Pure JSON export
python3 triage.py 8.8.8.8 -f json -o dns_report.json -q

# Export both Markdown and JSON simultaneously
python3 triage.py suspicious-bank.com -f all -o case_1042
```

---

## 🔌 REST API Endpoints

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/` | Web application dark-mode terminal UI |
| `GET` | `/api/health` | Service health, version, and demo mode status |
| `GET` | `/api/samples` | List available pre-loaded sample cases |
| `GET` | `/api/samples/{id}` | Retrieve complete structured report for a sample case |
| `POST` | `/api/triage` | Execute live passive triage (rate-limited, blocked in Demo Mode) |
| `POST` | `/api/export/markdown` | Convert JSON `TriageReport` into a downloadable Markdown brief |

### Rate Limiting
- `POST /api/triage` is protected by an in-memory sliding-window rate limiter (default: 10 requests/minute per client IP).
- Exceeding the threshold returns `429 Too Many Requests` with a `Retry-After: <seconds>` header.
- Configurable via the `RATE_LIMIT_PER_MINUTE` environment variable.

---

## 🧪 Testing

The workbench includes 46 automated tests covering defanging, SSRF protections, DNS parsing, RDAP parsing, CT discovery, ASN lookups, heuristic triggers, CLI operations, and FastAPI endpoints:

```bash
# Run complete test suite
pytest tests/ -v
```

---

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

Copyright (c) 2026 Michael Voorhies.

