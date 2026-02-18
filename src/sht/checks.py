from __future__ import annotations
from dataclasses import dataclass
from typing import List
from urllib.parse import urlparse

@dataclass
class Finding:
    id: str
    title: str
    status: str   # pass|warn|fail|info
    severity: str # low|med|high|info
    details: str
    recommendation: str

def _is_https(url: str) -> bool:
    return urlparse(url).scheme.lower() == "https"

def run_checks(resp) -> List[Finding]:
    h = resp.headers
    url = str(resp.url)
    findings: List[Finding] = []

    # HSTS (only meaningful on HTTPS)
    if _is_https(url):
        v = h.get("Strict-Transport-Security")
        if not v:
            findings.append(Finding("HSTS", "Strict-Transport-Security", "fail", "high",
                "Missing HSTS header on HTTPS response.",
                "Add HSTS with a long max-age and includeSubDomains (and preload if appropriate)."))
        else:
            status = "pass" if "max-age=" in v.lower() else "warn"
            findings.append(Finding("HSTS", "Strict-Transport-Security", status, "med" if status=="warn" else "low",
                f"Value: {v}", "Ensure max-age is set (e.g., >= 15552000) and consider includeSubDomains."))

    # CSP (basic presence check; deep parsing can be v0.2)
    csp = h.get("Content-Security-Policy")
    if not csp:
        findings.append(Finding("CSP", "Content-Security-Policy", "warn", "med",
            "CSP not present (common source of XSS risk).",
            "Add a CSP (start with report-only, then enforce)."))
    else:
        bad = any(x in csp.lower() for x in ["unsafe-inline", "unsafe-eval", "*"])
        findings.append(Finding("CSP", "Content-Security-Policy", "warn" if bad else "pass",
            "med" if bad else "low",
            f"Value: {csp}",
            "Avoid unsafe-inline/unsafe-eval and overly-broad sources; prefer nonces/hashes."))

    # X-Frame-Options
    xfo = h.get("X-Frame-Options")
    if not xfo:
        findings.append(Finding("XFO", "X-Frame-Options", "warn", "low",
            "Missing X-Frame-Options.",
            "Set DENY or SAMEORIGIN (or use CSP frame-ancestors)."))
    else:
        ok = xfo.upper() in ("DENY", "SAMEORIGIN")
        findings.append(Finding("XFO", "X-Frame-Options", "pass" if ok else "warn", "low",
            f"Value: {xfo}", "Prefer DENY/SAMEORIGIN, or enforce via CSP frame-ancestors."))

    # X-Content-Type-Options
    xcto = h.get("X-Content-Type-Options")
    if xcto and xcto.lower() == "nosniff":
        findings.append(Finding("XCTO", "X-Content-Type-Options", "pass", "low",
            "nosniff set.", "Keep nosniff enabled."))
    else:
        findings.append(Finding("XCTO", "X-Content-Type-Options", "warn", "low",
            "Missing or not set to nosniff.", "Set X-Content-Type-Options: nosniff"))

    # Referrer-Policy
    rp = h.get("Referrer-Policy")
    if not rp:
        findings.append(Finding("REFPOL", "Referrer-Policy", "warn", "low",
            "Missing Referrer-Policy.", "Set strict-origin-when-cross-origin (or stricter)."))
    else:
        findings.append(Finding("REFPOL", "Referrer-Policy", "pass", "low",
            f"Value: {rp}", "Ensure policy matches privacy needs."))

    # Permissions-Policy (presence)
    pp = h.get("Permissions-Policy")
    findings.append(Finding("PERMPOL", "Permissions-Policy",
        "pass" if pp else "info",
        "low" if pp else "info",
        f"Value: {pp}" if pp else "Not set (consider restricting powerful features).",
        "Add Permissions-Policy to disable features you don’t use (camera, mic, geolocation, etc.)."))

    # Cookie flags (best-effort: checks raw Set-Cookie header(s))
    set_cookie = resp.headers.get_list("Set-Cookie") if hasattr(resp.headers, "get_list") else []
    if set_cookie:
        for i, sc in enumerate(set_cookie, 1):
            low = sc.lower()
            missing = []
            if "secure" not in low: missing.append("Secure")
            if "httponly" not in low: missing.append("HttpOnly")
            if "samesite" not in low: missing.append("SameSite")
            status = "pass" if not missing else "warn"
            findings.append(Finding(f"COOKIE{i}", "Set-Cookie flags", status, "med" if missing else "low",
                f"{'Missing ' + ', '.join(missing) + ' — ' if missing else ''}{sc}",
                "Set Secure; HttpOnly; SameSite=Lax/Strict where appropriate."))
    else:
        findings.append(Finding("COOKIE", "Set-Cookie flags", "info", "info",
            "No Set-Cookie observed on this response.", "If cookies are used, ensure Secure/HttpOnly/SameSite."))

    return findings
