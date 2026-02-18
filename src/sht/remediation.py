from __future__ import annotations

def remediation_text(resp, findings) -> str:
    # minimal: always show a sane-ish baseline; refine later based on findings
    nginx = """# nginx (example)
add_header X-Content-Type-Options "nosniff" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header X-Frame-Options "SAMEORIGIN" always;

# HSTS (HTTPS only)
add_header Strict-Transport-Security "max-age=15552000; includeSubDomains" always;

# CSP (start in Report-Only, then enforce)
# add_header Content-Security-Policy-Report-Only "default-src 'self'; object-src 'none'; base-uri 'self'; frame-ancestors 'none'" always;
"""
    apache = """# Apache (example)
Header always set X-Content-Type-Options "nosniff"
Header always set Referrer-Policy "strict-origin-when-cross-origin"
Header always set X-Frame-Options "SAMEORIGIN"

# HSTS (HTTPS only)
Header always set Strict-Transport-Security "max-age=15552000; includeSubDomains"
"""
    return nginx + "\n" + apache
