# HTTP Security Headers Tester (sht)

A small CLI tool that checks a target URL for common **web security headers** and **cookie flags**, then produces a simple **score + grade (A–F)** with practical remediation guidance.

This is designed to be:
- **Fast**: one command, clear output
- **Portable**: runs anywhere Python runs
- **Useful**: includes “what’s wrong” + “how to fix it” snippets

> ⚠️ This tool provides a **signal**, not a guarantee. It does not replace a full application security review.

---

## Features

- Checks for:
  - `Strict-Transport-Security` (HSTS)
  - `Content-Security-Policy` (CSP)
  - `X-Frame-Options` (XFO)
  - `X-Content-Type-Options` (XCTO)
  - `Referrer-Policy`
  - `Permissions-Policy`
  - Cookie flags from `Set-Cookie` (`Secure`, `HttpOnly`, `SameSite`)
- Outputs:
  - human-readable results with ✅/⚠️/❌
  - `--json` mode for automation
  - baseline remediation snippets (nginx + Apache)

---

## Quick start

### Requirements
- Python **3.10+**

### Install (dev)
python -m venv .venv  
source .venv/bin/activate  *(Windows: .venv\Scripts\activate)*  
pip install -e .

### Run
sht https://example.com

---

## Usage

**Syntax:**  
sht <url> [--json] [--follow-redirects] [--timeout SECONDS] [--user-agent UA]

**Examples:**
- sht https://example.com
- sht https://example.com --follow-redirects
- sht https://example.com --json
- sht https://example.com --timeout 10 --user-agent "sht/0.1.0"

---

## Example output

A (92/100)  200  https://example.com

✅ HSTS: Strict-Transport-Security — PASS  
Value: max-age=15552000; includeSubDomains  

⚠️ CSP: Content-Security-Policy — WARN  
Value: default-src 'self' 'unsafe-inline'  

✅ XCTO: X-Content-Type-Options — PASS  
nosniff set.  

⚠️ XFO: X-Frame-Options — WARN  
Missing X-Frame-Options.  

ℹ️ COOKIE: Set-Cookie flags — INFO  
No Set-Cookie observed on this response.  

---

## What the grade means

`sht` uses a lightweight scoring system:
- Starts at **100**
- Subtracts points for missing/weak controls (severity-weighted)
- Produces a grade:
  - **A**: 90–100
  - **B**: 80–89
  - **C**: 70–79
  - **D**: 60–69
  - **F**: <60

This is intentionally simple so results are easy to interpret and automate.

---

## Checks performed (high level)

### HSTS
- Only evaluated for **HTTPS** targets
- Warn/fail if missing or malformed

### CSP
- Presence check + basic “unsafe-* / wildcard” detection
- CSP is app-specific; treat results as guidance

### XFO / XCTO / Referrer-Policy / Permissions-Policy
- Presence and basic value checks

### Cookie flags
- Inspects `Set-Cookie` values for `Secure`, `HttpOnly`, and `SameSite`
- If no cookies are present on the response, reports `INFO`

---

## Remediation snippets (examples)

### nginx
add_header X-Content-Type-Options "nosniff" always;  
add_header Referrer-Policy "strict-origin-when-cross-origin" always;  
add_header X-Frame-Options "SAMEORIGIN" always;  

add_header Strict-Transport-Security "max-age=15552000; includeSubDomains" always;  

*(CSP is app-specific — start in Report-Only, then enforce.)*

### Apache
Header always set X-Content-Type-Options "nosniff"  
Header always set Referrer-Policy "strict-origin-when-cross-origin"  
Header always set X-Frame-Options "SAMEORIGIN"  

Header always set Strict-Transport-Security "max-age=15552000; includeSubDomains"  

---

## Roadmap (small, high-value upgrades)

- `--sarif` output for GitHub code scanning
- HTML detection (only require CSP for HTML responses)
- richer CSP linting (directive-level hints)
- markdown report output (`--report md`)
- batch mode (`--input urls.txt`)

---

## Contributing

PRs are welcome. Keep changes:
- focused
- well-tested
- documented (update this README)

---

## License

MIT (see `LICENSE`).
