#!/usr/bin/env python3
"""
OWASP Top 10 Web Application Vulnerability Scanner
Detects common security issues using multi-threading.
Usage: python vuln_scanner.py <target_url> [options]
"""

import sys
import time
import queue
import threading
import argparse
import json
import re
import socket
import ssl
import http.client
from datetime import datetime
from urllib.parse import urlparse, urljoin, urlencode, parse_qs, urlunparse, quote
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError
from html.parser import HTMLParser
from collections import defaultdict

# ─────────────────────────────────────────────
# ANSI Colors
# ─────────────────────────────────────────────
class C:
    RED     = "\033[91m"
    YELLOW  = "\033[93m"
    GREEN   = "\033[92m"
    CYAN    = "\033[96m"
    BLUE    = "\033[94m"
    MAGENTA = "\033[95m"
    BOLD    = "\033[1m"
    DIM     = "\033[2m"
    RESET   = "\033[0m"

BANNER = f"""
{C.CYAN}{C.BOLD}
╔══════════════════════════════════════════════════════════╗
║         OWASP Top 10 Vulnerability Scanner v1.0          ║
║         Multi-threaded Web Security Assessment Tool      ║
╚══════════════════════════════════════════════════════════╝
{C.RESET}"""

# ─────────────────────────────────────────────
# Severity Levels
# ─────────────────────────────────────────────
CRITICAL = "CRITICAL"
HIGH     = "HIGH"
MEDIUM   = "MEDIUM"
LOW      = "LOW"
INFO     = "INFO"

SEVERITY_COLOR = {
    CRITICAL: C.RED + C.BOLD,
    HIGH:     C.RED,
    MEDIUM:   C.YELLOW,
    LOW:      C.CYAN,
    INFO:     C.GREEN,
}

# ─────────────────────────────────────────────
# Finding dataclass
# ─────────────────────────────────────────────
class Finding:
    def __init__(self, owasp_id, title, severity, description, evidence="", remediation="", url=""):
        self.owasp_id    = owasp_id
        self.title       = title
        self.severity    = severity
        self.description = description
        self.evidence    = evidence
        self.remediation = remediation
        self.url         = url
        self.timestamp   = datetime.utcnow().isoformat()

    def to_dict(self):
        return self.__dict__

# ─────────────────────────────────────────────
# HTML Link Parser
# ─────────────────────────────────────────────
class LinkParser(HTMLParser):
    def __init__(self, base_url):
        super().__init__()
        self.base_url = base_url
        self.links    = set()
        self.forms    = []
        self._current_form = None

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "a" and "href" in attrs:
            href = attrs["href"]
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                self.links.add(urljoin(self.base_url, href))
        elif tag == "form":
            self._current_form = {
                "action": urljoin(self.base_url, attrs.get("action", self.base_url)),
                "method": attrs.get("method", "get").upper(),
                "inputs": []
            }
        elif tag == "input" and self._current_form is not None:
            self._current_form["inputs"].append({
                "name":  attrs.get("name", ""),
                "type":  attrs.get("type", "text"),
                "value": attrs.get("value", "test")
            })

    def handle_endtag(self, tag):
        if tag == "form" and self._current_form:
            self.forms.append(self._current_form)
            self._current_form = None

# ─────────────────────────────────────────────
# HTTP Helper
# ─────────────────────────────────────────────
class HTTPClient:
    TIMEOUT = 10
    HEADERS = {
        "User-Agent": "Mozilla/5.0 (VulnScanner/1.0; Security Assessment)",
        "Accept":     "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    }

    def __init__(self, verify_ssl=False):
        self.verify_ssl = verify_ssl
        self._lock = threading.Lock()

    def get(self, url, headers=None, allow_redirects=True, timeout=None):
        return self._request("GET", url, headers=headers,
                             allow_redirects=allow_redirects,
                             timeout=timeout or self.TIMEOUT)

    def post(self, url, data=None, headers=None, timeout=None):
        return self._request("POST", url, data=data, headers=headers,
                             timeout=timeout or self.TIMEOUT)

    def _request(self, method, url, data=None, headers=None, allow_redirects=True, timeout=10):
        try:
            req_headers = dict(self.HEADERS)
            if headers:
                req_headers.update(headers)
            body = None
            if data:
                if isinstance(data, dict):
                    body    = urlencode(data).encode()
                    req_headers["Content-Type"] = "application/x-www-form-urlencoded"
                else:
                    body = data.encode() if isinstance(data, str) else data

            req = Request(url, data=body, headers=req_headers, method=method)
            ctx = ssl.create_default_context()
            if not self.verify_ssl:
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE

            with urlopen(req, context=ctx, timeout=timeout) as resp:
                return {
                    "status":  resp.status,
                    "headers": dict(resp.headers),
                    "body":    resp.read().decode("utf-8", errors="replace"),
                    "url":     resp.url,
                }
        except HTTPError as e:
            body = ""
            try:
                body = e.read().decode("utf-8", errors="replace")
            except Exception:
                pass
            return {
                "status":  e.code,
                "headers": dict(e.headers),
                "body":    body,
                "url":     url,
            }
        except Exception as e:
            return {"status": 0, "headers": {}, "body": "", "url": url, "error": str(e)}

# ─────────────────────────────────────────────
# Base Check
# ─────────────────────────────────────────────
class BaseCheck:
    NAME     = "Base Check"
    OWASP_ID = "A00"
    SEVERITY = INFO

    def __init__(self, http_client: HTTPClient):
        self.http = http_client

    def run(self, target_url: str, crawl_data: dict) -> list:
        raise NotImplementedError


# ─────────────────────────────────────────────
# A01 – Broken Access Control
# ─────────────────────────────────────────────
class BrokenAccessControlCheck(BaseCheck):
    NAME     = "Broken Access Control"
    OWASP_ID = "A01:2021"
    SEVERITY = CRITICAL

    SENSITIVE_PATHS = [
        "/admin", "/admin/", "/administrator", "/wp-admin",
        "/dashboard", "/control", "/manager",
        "/.env", "/.git/HEAD", "/.git/config",
        "/config.php", "/config.yml", "/config.json",
        "/backup", "/backup.zip", "/db_backup.sql",
        "/api/admin", "/api/users", "/api/config",
        "/server-status", "/server-info", "/phpinfo.php",
        "/web.config", "/WEB-INF/web.xml",
    ]

    def run(self, target_url, crawl_data):
        findings = []
        parsed   = urlparse(target_url)
        base     = f"{parsed.scheme}://{parsed.netloc}"

        for path in self.SENSITIVE_PATHS:
            url  = base + path
            resp = self.http.get(url, allow_redirects=False)
            if resp["status"] in (200, 301, 302, 403):
                sev = HIGH if resp["status"] == 403 else CRITICAL
                findings.append(Finding(
                    owasp_id    = self.OWASP_ID,
                    title       = "Sensitive Path Exposed",
                    severity    = sev,
                    description = f"Sensitive endpoint accessible: {path}",
                    evidence    = f"HTTP {resp['status']} → {url}",
                    remediation = "Restrict access with authentication and authorization checks.",
                    url         = url,
                ))
        return findings


# ─────────────────────────────────────────────
# A02 – Cryptographic Failures
# ─────────────────────────────────────────────
class CryptographicFailuresCheck(BaseCheck):
    NAME     = "Cryptographic Failures"
    OWASP_ID = "A02:2021"
    SEVERITY = HIGH

    def run(self, target_url, crawl_data):
        findings = []
        parsed   = urlparse(target_url)

        # 1. HTTP (not HTTPS)
        if parsed.scheme == "http":
            findings.append(Finding(
                owasp_id    = self.OWASP_ID,
                title       = "Insecure HTTP Connection",
                severity    = HIGH,
                description = "Application is served over HTTP, exposing data in transit.",
                evidence    = target_url,
                remediation = "Enforce HTTPS with a valid TLS certificate and HSTS header.",
                url         = target_url,
            ))

        # 2. TLS version / weak ciphers (basic probe)
        if parsed.scheme == "https":
            try:
                ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE
                host = parsed.hostname
                port = parsed.port or 443
                with ctx.wrap_socket(socket.create_connection((host, port), timeout=5),
                                     server_hostname=host) as s:
                    cipher = s.cipher()
                    proto  = s.version()
                    if proto in ("TLSv1", "TLSv1.1", "SSLv2", "SSLv3"):
                        findings.append(Finding(
                            owasp_id    = self.OWASP_ID,
                            title       = "Deprecated TLS Version",
                            severity    = HIGH,
                            description = f"Server supports deprecated protocol: {proto}",
                            evidence    = f"Negotiated: {proto} / {cipher[0]}",
                            remediation = "Disable TLS 1.0/1.1 and enforce TLS 1.2+.",
                            url         = target_url,
                        ))
            except Exception:
                pass

        # 3. Missing HSTS
        resp = self.http.get(target_url)
        hsts = resp["headers"].get("Strict-Transport-Security", "")
        if parsed.scheme == "https" and not hsts:
            findings.append(Finding(
                owasp_id    = self.OWASP_ID,
                title       = "Missing HSTS Header",
                severity    = MEDIUM,
                description = "HSTS header is absent; browsers won't enforce HTTPS.",
                evidence    = "Strict-Transport-Security header not found",
                remediation = "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains",
                url         = target_url,
            ))
        return findings


# ─────────────────────────────────────────────
# A03 – Injection (XSS + SQLi)
# ─────────────────────────────────────────────
class InjectionCheck(BaseCheck):
    NAME     = "Injection"
    OWASP_ID = "A03:2021"
    SEVERITY = CRITICAL

    XSS_PAYLOADS = [
        "<script>alert('XSS')</script>",
        "'\"><script>alert(1)</script>",
        "<img src=x onerror=alert(1)>",
        "javascript:alert(1)",
        "<svg onload=alert(1)>",
    ]
    SQLI_PAYLOADS = [
        "'",
        "' OR '1'='1",
        "\" OR \"1\"=\"1",
        "' OR 1=1--",
        "1; DROP TABLE users--",
        "' UNION SELECT NULL--",
    ]
    SQLI_ERRORS = [
        "sql syntax", "mysql_fetch", "ora-", "pg_query",
        "sqlite_", "syntax error", "unclosed quotation",
        "unterminated string", "odbc driver", "jdbc driver",
    ]

    def run(self, target_url, crawl_data):
        findings = []
        forms    = crawl_data.get("forms", [])
        urls     = crawl_data.get("urls", set())

        # Test URL parameters
        for url in list(urls)[:20]:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            params = parse_qs(parsed.query)
            for param in params:
                findings += self._test_xss(url, param, parsed)
                findings += self._test_sqli(url, param, parsed)

        # Test forms
        for form in forms[:10]:
            findings += self._test_form(form)

        return findings

    def _inject_param(self, url, param, payload):
        parsed = urlparse(url)
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [payload]
        new_q = urlencode(params, doseq=True)
        return urlunparse(parsed._replace(query=new_q))

    def _test_xss(self, url, param, parsed):
        findings = []
        for payload in self.XSS_PAYLOADS[:3]:
            test_url = self._inject_param(url, param, payload)
            resp     = self.http.get(test_url)
            if payload in resp.get("body", ""):
                findings.append(Finding(
                    owasp_id    = self.OWASP_ID,
                    title       = "Reflected XSS",
                    severity    = HIGH,
                    description = f"Parameter '{param}' reflects unsanitised input.",
                    evidence    = f"Payload reflected: {payload[:60]}",
                    remediation = "Encode all output; use Content-Security-Policy.",
                    url         = test_url,
                ))
                break
        return findings

    def _test_sqli(self, url, param, parsed):
        findings = []
        for payload in self.SQLI_PAYLOADS[:3]:
            test_url = self._inject_param(url, param, payload)
            resp     = self.http.get(test_url)
            body     = resp.get("body", "").lower()
            for err in self.SQLI_ERRORS:
                if err in body:
                    findings.append(Finding(
                        owasp_id    = self.OWASP_ID,
                        title       = "SQL Injection",
                        severity    = CRITICAL,
                        description = f"Parameter '{param}' may be vulnerable to SQL injection.",
                        evidence    = f"DB error pattern '{err}' detected with payload: {payload[:60]}",
                        remediation = "Use parameterised queries / prepared statements.",
                        url         = test_url,
                    ))
                    return findings
        return findings

    def _test_form(self, form):
        findings = []
        for payload in self.XSS_PAYLOADS[:2]:
            data = {inp["name"]: payload for inp in form["inputs"] if inp["name"]}
            if not data:
                continue
            if form["method"] == "POST":
                resp = self.http.post(form["action"], data=data)
            else:
                resp = self.http.get(form["action"] + "?" + urlencode(data))
            if payload in resp.get("body", ""):
                findings.append(Finding(
                    owasp_id    = self.OWASP_ID,
                    title       = "Form-Based XSS",
                    severity    = HIGH,
                    description = "Form field reflects unsanitised input.",
                    evidence    = f"Payload reflected via form at {form['action']}",
                    remediation = "Sanitise and encode all form output.",
                    url         = form["action"],
                ))
                break
        return findings


# ─────────────────────────────────────────────
# A04 – Insecure Design (CSRF)
# ─────────────────────────────────────────────
class InsecureDesignCheck(BaseCheck):
    NAME     = "Insecure Design / CSRF"
    OWASP_ID = "A04:2021"
    SEVERITY = HIGH

    CSRF_TOKENS = ["csrf", "_token", "authenticity_token", "nonce", "__requestverificationtoken"]

    def run(self, target_url, crawl_data):
        findings = []
        for form in crawl_data.get("forms", []):
            if form["method"] != "POST":
                continue
            input_names = [i["name"].lower() for i in form["inputs"]]
            has_csrf    = any(t in n for t in self.CSRF_TOKENS for n in input_names)
            if not has_csrf:
                findings.append(Finding(
                    owasp_id    = self.OWASP_ID,
                    title       = "Missing CSRF Token",
                    severity    = HIGH,
                    description = "POST form lacks a CSRF token.",
                    evidence    = f"Form action: {form['action']} | Inputs: {input_names}",
                    remediation = "Add a unique, secret, per-session CSRF token to all state-changing forms.",
                    url         = form["action"],
                ))
        return findings


# ─────────────────────────────────────────────
# A05 – Security Misconfiguration
# ─────────────────────────────────────────────
class SecurityMisconfigCheck(BaseCheck):
    NAME     = "Security Misconfiguration"
    OWASP_ID = "A05:2021"
    SEVERITY = MEDIUM

    SECURITY_HEADERS = {
        "X-Frame-Options":           ("MEDIUM", "Clickjacking protection missing"),
        "X-Content-Type-Options":    ("LOW",    "MIME-sniffing protection missing"),
        "Content-Security-Policy":   ("HIGH",   "CSP header absent"),
        "X-XSS-Protection":          ("LOW",    "Legacy XSS protection missing"),
        "Referrer-Policy":           ("LOW",    "Referrer-Policy header absent"),
        "Permissions-Policy":        ("LOW",    "Permissions-Policy header absent"),
    }

    def run(self, target_url, crawl_data):
        findings = []
        resp     = self.http.get(target_url)
        headers  = {k.lower(): v for k, v in resp["headers"].items()}

        # Missing security headers
        for header, (sev, desc) in self.SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append(Finding(
                    owasp_id    = self.OWASP_ID,
                    title       = f"Missing Header: {header}",
                    severity    = sev,
                    description = desc,
                    evidence    = f"Header '{header}' not present in response",
                    remediation = f"Add the '{header}' response header with a secure value.",
                    url         = target_url,
                ))

        # Server version disclosure
        server = headers.get("server", "")
        if re.search(r"[\d.]", server):
            findings.append(Finding(
                owasp_id    = self.OWASP_ID,
                title       = "Server Version Disclosure",
                severity    = LOW,
                description = "Server header reveals version information.",
                evidence    = f"Server: {server}",
                remediation = "Suppress or anonymise the Server header.",
                url         = target_url,
            ))

        # X-Powered-By
        powered = headers.get("x-powered-by", "")
        if powered:
            findings.append(Finding(
                owasp_id    = self.OWASP_ID,
                title       = "Technology Disclosure (X-Powered-By)",
                severity    = LOW,
                description = "X-Powered-By header reveals backend technology.",
                evidence    = f"X-Powered-By: {powered}",
                remediation = "Remove or suppress the X-Powered-By header.",
                url         = target_url,
            ))

        return findings


# ─────────────────────────────────────────────
# A06 – Vulnerable Components
# ─────────────────────────────────────────────
class VulnerableComponentsCheck(BaseCheck):
    NAME     = "Vulnerable & Outdated Components"
    OWASP_ID = "A06:2021"
    SEVERITY = HIGH

    KNOWN_VULNERABLE = {
        "jquery/1.": "jQuery < 2.x has multiple XSS vulnerabilities",
        "jquery/2.0": "jQuery 2.0.x has known XSS issues",
        "jquery/2.1": "jQuery 2.1.x has known XSS issues",
        "bootstrap/2.": "Bootstrap 2.x is EOL",
        "bootstrap/3.": "Bootstrap 3.x has known XSS in tooltip/popover",
        "angular.js/1.": "AngularJS 1.x is EOL and has sandbox-escape CVEs",
        "lodash/4.17.10": "Lodash 4.17.10 has prototype pollution CVE-2019-10744",
        "lodash/4.17.11": "Lodash 4.17.11 has prototype pollution",
    }

    def run(self, target_url, crawl_data):
        findings = []
        body     = crawl_data.get("body", "")

        for pattern, desc in self.KNOWN_VULNERABLE.items():
            if pattern.lower() in body.lower():
                findings.append(Finding(
                    owasp_id    = self.OWASP_ID,
                    title       = "Vulnerable JS Library Detected",
                    severity    = HIGH,
                    description = desc,
                    evidence    = f"Pattern found in page source: {pattern}",
                    remediation = "Update all third-party libraries to the latest patched versions.",
                    url         = target_url,
                ))

        # Check for WordPress version
        wp_ver = re.search(r"wp-includes.*?ver=([\d.]+)", body)
        if wp_ver:
            findings.append(Finding(
                owasp_id    = self.OWASP_ID,
                title       = "WordPress Version Disclosure",
                severity    = MEDIUM,
                description = f"WordPress version {wp_ver.group(1)} detected.",
                evidence    = f"Version string found in HTML source",
                remediation = "Hide WordPress version and keep core/plugins updated.",
                url         = target_url,
            ))

        return findings


# ─────────────────────────────────────────────
# A07 – Auth / Session Failures
# ─────────────────────────────────────────────
class AuthFailuresCheck(BaseCheck):
    NAME     = "Identification & Authentication Failures"
    OWASP_ID = "A07:2021"
    SEVERITY = HIGH

    def run(self, target_url, crawl_data):
        findings = []
        resp     = self.http.get(target_url)
        headers  = {k.lower(): v for k, v in resp["headers"].items()}
        cookies  = headers.get("set-cookie", "")

        # Insecure cookies
        for cookie in cookies.split(","):
            cookie = cookie.strip()
            if "session" in cookie.lower() or "auth" in cookie.lower() or "token" in cookie.lower():
                if "secure" not in cookie.lower():
                    findings.append(Finding(
                        owasp_id    = self.OWASP_ID,
                        title       = "Session Cookie Missing Secure Flag",
                        severity    = HIGH,
                        description = "Session cookie transmitted without Secure flag.",
                        evidence    = f"Set-Cookie: {cookie[:120]}",
                        remediation = "Set Secure flag on all sensitive cookies.",
                        url         = target_url,
                    ))
                if "httponly" not in cookie.lower():
                    findings.append(Finding(
                        owasp_id    = self.OWASP_ID,
                        title       = "Session Cookie Missing HttpOnly Flag",
                        severity    = MEDIUM,
                        description = "Session cookie accessible via JavaScript (XSS risk).",
                        evidence    = f"Set-Cookie: {cookie[:120]}",
                        remediation = "Set HttpOnly flag on all session cookies.",
                        url         = target_url,
                    ))
                if "samesite" not in cookie.lower():
                    findings.append(Finding(
                        owasp_id    = self.OWASP_ID,
                        title       = "Session Cookie Missing SameSite Attribute",
                        severity    = MEDIUM,
                        description = "Cookie lacks SameSite attribute, increasing CSRF risk.",
                        evidence    = f"Set-Cookie: {cookie[:120]}",
                        remediation = "Add SameSite=Strict or SameSite=Lax to session cookies.",
                        url         = target_url,
                    ))
        return findings


# ─────────────────────────────────────────────
# A08 – Software & Data Integrity
# ─────────────────────────────────────────────
class IntegrityFailuresCheck(BaseCheck):
    NAME     = "Software & Data Integrity Failures"
    OWASP_ID = "A08:2021"
    SEVERITY = HIGH

    def run(self, target_url, crawl_data):
        findings = []
        body     = crawl_data.get("body", "")

        # Scripts without SRI
        scripts = re.findall(r'<script[^>]+src=["\']([^"\']+)["\'][^>]*>', body, re.I)
        for src in scripts:
            if src.startswith(("http://", "https://")):
                tag = re.search(rf'<script[^>]+src=["\']' + re.escape(src) + r'["\'][^>]*>', body, re.I)
                if tag and "integrity=" not in tag.group(0).lower():
                    findings.append(Finding(
                        owasp_id    = self.OWASP_ID,
                        title       = "External Script Without SRI",
                        severity    = MEDIUM,
                        description = "External script loaded without Subresource Integrity (SRI) hash.",
                        evidence    = f"src={src[:100]}",
                        remediation = "Add integrity and crossorigin attributes to all external scripts.",
                        url         = target_url,
                    ))

        return findings


# ─────────────────────────────────────────────
# A09 – Security Logging Failures
# ─────────────────────────────────────────────
class LoggingFailuresCheck(BaseCheck):
    NAME     = "Security Logging & Monitoring Failures"
    OWASP_ID = "A09:2021"
    SEVERITY = MEDIUM

    ERROR_PATTERNS = [
        (r"stack trace", "Stack trace exposed in response"),
        (r"at \w+\.\w+\([\w.]+:\d+\)", "Java stack trace exposed"),
        (r"Traceback \(most recent call", "Python traceback exposed"),
        (r"Warning:.*on line \d+", "PHP warning exposed"),
        (r"fatal error", "Fatal error message exposed"),
        (r"undefined variable", "Undefined variable error exposed"),
        (r"access denied for user", "Database error details exposed"),
        (r"ORA-\d+", "Oracle DB error exposed"),
        (r"Microsoft OLE DB", "OLE DB error exposed"),
    ]

    def run(self, target_url, crawl_data):
        findings = []
        body     = crawl_data.get("body", "").lower()

        for pattern, desc in self.ERROR_PATTERNS:
            if re.search(pattern, body, re.I):
                findings.append(Finding(
                    owasp_id    = self.OWASP_ID,
                    title       = "Verbose Error / Debug Information Exposed",
                    severity    = MEDIUM,
                    description = desc,
                    evidence    = f"Pattern matched: {pattern}",
                    remediation = "Disable debug mode in production; log errors server-side only.",
                    url         = target_url,
                ))
        return findings


# ─────────────────────────────────────────────
# A10 – SSRF
# ─────────────────────────────────────────────
class SSRFCheck(BaseCheck):
    NAME     = "Server-Side Request Forgery"
    OWASP_ID = "A10:2021"
    SEVERITY = HIGH

    SSRF_PAYLOADS = [
        "http://127.0.0.1/",
        "http://localhost/",
        "http://169.254.169.254/",               # AWS metadata
        "http://metadata.google.internal/",       # GCP metadata
        "http://169.254.169.254/latest/meta-data/",
        "http://[::1]/",
        "file:///etc/passwd",
    ]

    SSRF_PATTERNS = ["url", "path", "src", "dest", "redirect", "uri", "fetch", "load", "open", "href", "endpoint"]

    def run(self, target_url, crawl_data):
        findings = []
        for url in list(crawl_data.get("urls", set()))[:20]:
            parsed = urlparse(url)
            if not parsed.query:
                continue
            params = parse_qs(parsed.query)
            for param in params:
                if any(p in param.lower() for p in self.SSRF_PATTERNS):
                    for payload in self.SSRF_PAYLOADS[:3]:
                        test_url = self._inject(url, param, payload, parsed)
                        resp     = self.http.get(test_url)
                        body     = resp.get("body", "")
                        if any(s in body for s in ["root:", "ami-id", "instance-id", "computeMetadata"]):
                            findings.append(Finding(
                                owasp_id    = self.OWASP_ID,
                                title       = "Server-Side Request Forgery (SSRF)",
                                severity    = CRITICAL,
                                description = f"Parameter '{param}' may allow SSRF.",
                                evidence    = f"Sensitive content returned for payload: {payload}",
                                remediation = "Validate and restrict URLs; use allowlists for external requests.",
                                url         = test_url,
                            ))
                            break
        return findings

    def _inject(self, url, param, value, parsed):
        params = parse_qs(parsed.query, keep_blank_values=True)
        params[param] = [value]
        return urlunparse(parsed._replace(query=urlencode(params, doseq=True)))


# ─────────────────────────────────────────────
# Crawler
# ─────────────────────────────────────────────
class Crawler:
    MAX_PAGES = 50

    def __init__(self, http_client, base_url, max_depth=2):
        self.http      = http_client
        self.base_url  = base_url
        self.base_host = urlparse(base_url).netloc
        self.max_depth = max_depth
        self.visited   = set()
        self.lock      = threading.Lock()

    def crawl(self) -> dict:
        result  = {"urls": set(), "forms": [], "body": ""}
        queue_  = [(self.base_url, 0)]

        while queue_ and len(self.visited) < self.MAX_PAGES:
            url, depth = queue_.pop(0)
            with self.lock:
                if url in self.visited:
                    continue
                self.visited.add(url)

            if urlparse(url).netloc != self.base_host:
                continue

            resp = self.http.get(url)
            body = resp.get("body", "")
            result["urls"].add(url)

            if not result["body"]:
                result["body"] = body

            parser = LinkParser(url)
            try:
                parser.feed(body)
            except Exception:
                pass

            result["forms"] += parser.forms

            if depth < self.max_depth:
                for link in parser.links:
                    if link not in self.visited:
                        queue_.append((link, depth + 1))

        return result


# ─────────────────────────────────────────────
# Scanner Engine
# ─────────────────────────────────────────────
class VulnerabilityScanner:
    def __init__(self, target_url, threads=10, max_depth=2, verify_ssl=False):
        self.target_url = target_url
        self.threads    = threads
        self.http       = HTTPClient(verify_ssl=verify_ssl)
        self.crawler    = Crawler(self.http, target_url, max_depth)
        self.findings   = []
        self._lock      = threading.Lock()

        self.checks = [
            BrokenAccessControlCheck(self.http),
            CryptographicFailuresCheck(self.http),
            InjectionCheck(self.http),
            InsecureDesignCheck(self.http),
            SecurityMisconfigCheck(self.http),
            VulnerableComponentsCheck(self.http),
            AuthFailuresCheck(self.http),
            IntegrityFailuresCheck(self.http),
            LoggingFailuresCheck(self.http),
            SSRFCheck(self.http),
        ]

    def _run_check(self, check, crawl_data):
        try:
            print(f"  {C.DIM}[*] Running: {check.NAME}{C.RESET}")
            results = check.run(self.target_url, crawl_data)
            with self._lock:
                self.findings.extend(results)
        except Exception as e:
            print(f"  {C.YELLOW}[!] Check {check.NAME} error: {e}{C.RESET}")

    def scan(self) -> list:
        print(f"\n{C.BOLD}[1/3] Crawling target...{C.RESET}")
        crawl_data = self.crawler.crawl()
        print(f"      Discovered {len(crawl_data['urls'])} URL(s), {len(crawl_data['forms'])} form(s)")

        print(f"\n{C.BOLD}[2/3] Running vulnerability checks ({self.threads} threads)...{C.RESET}")
        workers = []
        for check in self.checks:
            t = threading.Thread(target=self._run_check, args=(check, crawl_data), daemon=True)
            workers.append(t)
            t.start()
            if len(workers) >= self.threads:
                for w in workers:
                    w.join()
                workers = []
        for w in workers:
            w.join()

        print(f"\n{C.BOLD}[3/3] Analysis complete.{C.RESET}")
        return self.findings


# ─────────────────────────────────────────────
# Reporter
# ─────────────────────────────────────────────
class Reporter:
    SEV_ORDER = {CRITICAL: 0, HIGH: 1, MEDIUM: 2, LOW: 3, INFO: 4}

    def __init__(self, findings, target_url):
        self.findings   = sorted(findings, key=lambda f: self.SEV_ORDER.get(f.severity, 9))
        self.target_url = target_url

    def print_summary(self):
        counts = defaultdict(int)
        for f in self.findings:
            counts[f.severity] += 1

        total = len(self.findings)
        print(f"\n{C.BOLD}{'─'*60}")
        print(f" SCAN RESULTS  ·  {self.target_url}")
        print(f"{'─'*60}{C.RESET}")

        if not self.findings:
            print(f"\n  {C.GREEN}✓ No vulnerabilities detected.{C.RESET}\n")
            return

        # Severity breakdown
        print(f"\n  {C.BOLD}Severity Summary:{C.RESET}")
        for sev in (CRITICAL, HIGH, MEDIUM, LOW, INFO):
            if counts[sev]:
                col = SEVERITY_COLOR[sev]
                bar = "█" * min(counts[sev], 40)
                print(f"  {col}{sev:<10}{C.RESET} {bar} {counts[sev]}")

        print(f"\n  Total findings: {C.BOLD}{total}{C.RESET}\n")
        print(f"{C.BOLD}{'─'*60}{C.RESET}")

        # Findings detail
        for i, f in enumerate(self.findings, 1):
            col = SEVERITY_COLOR[f.severity]
            print(f"\n  {C.BOLD}[{i}] {f.title}{C.RESET}")
            print(f"       Severity  : {col}{f.severity}{C.RESET}")
            print(f"       OWASP     : {f.owasp_id}")
            print(f"       URL       : {C.DIM}{f.url}{C.RESET}")
            print(f"       Issue     : {f.description}")
            if f.evidence:
                print(f"       Evidence  : {C.DIM}{f.evidence[:120]}{C.RESET}")
            print(f"       Fix       : {C.GREEN}{f.remediation}{C.RESET}")

        print(f"\n{C.BOLD}{'─'*60}{C.RESET}\n")

    def save_json(self, path):
        data = {
            "target":     self.target_url,
            "scan_time":  datetime.utcnow().isoformat(),
            "total":      len(self.findings),
            "findings":   [f.to_dict() for f in self.findings],
        }
        with open(path, "w") as fh:
            json.dump(data, fh, indent=2)
        print(f"  {C.GREEN}✓ JSON report saved → {path}{C.RESET}\n")


# ─────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────
def main():
    parser = argparse.ArgumentParser(
        description="OWASP Top 10 Web Vulnerability Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python vuln_scanner.py https://example.com
  python vuln_scanner.py https://testphp.vulnweb.com --threads 20 --depth 3
  python vuln_scanner.py https://target.com --output results.json
        """
    )
    parser.add_argument("url",            help="Target URL (include scheme: https://...)")
    parser.add_argument("--threads", "-t",type=int, default=10, help="Number of threads (default: 10)")
    parser.add_argument("--depth",   "-d",type=int, default=2,  help="Crawl depth (default: 2)")
    parser.add_argument("--output",  "-o",           default="", help="Save JSON report to file")
    parser.add_argument("--verify-ssl",   action="store_true",   help="Verify SSL certificates")
    args = parser.parse_args()

    print(BANNER)
    print(f"  Target  : {C.CYAN}{args.url}{C.RESET}")
    print(f"  Threads : {args.threads}")
    print(f"  Depth   : {args.depth}")
    print(f"  Started : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

    scanner  = VulnerabilityScanner(args.url, args.threads, args.depth, args.verify_ssl)
    t0       = time.time()
    findings = scanner.scan()
    elapsed  = time.time() - t0

    reporter = Reporter(findings, args.url)
    reporter.print_summary()
    print(f"  Completed in {elapsed:.1f}s")

    if args.output:
        reporter.save_json(args.output)


if __name__ == "__main__":
    main()
