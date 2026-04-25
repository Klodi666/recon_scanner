#!/usr/bin/env python3
"""
ReconScanner - Lightweight OSINT & Vulnerability Assessment Tool
Scans domains, IPs, emails for open ports, vulns, DNS, headers, SSL, leaks.
"""

import socket
import ssl
import sys
import json
import re
import time
import urllib.request
import urllib.parse
import urllib.error
import subprocess
import threading
import http.client
import ipaddress
import hashlib
import base64
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse

# ─────────────────────────────────────────────
# CONFIG
# ─────────────────────────────────────────────
COMMON_PORTS = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 587: "SMTP/TLS", 993: "IMAPS", 995: "POP3S",
    1433: "MSSQL", 1521: "Oracle", 3306: "MySQL", 3389: "RDP",
    5432: "PostgreSQL", 5900: "VNC", 6379: "Redis", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 8888: "HTTP-Dev", 9200: "Elasticsearch",
    27017: "MongoDB", 6443: "Kubernetes"
}

SQLI_PAYLOADS = ["'", "\"", "' OR '1'='1", "' OR 1=1--", "\" OR \"1\"=\"1"]
XSS_PAYLOADS = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]
SENSITIVE_HEADERS = ["X-Powered-By", "Server", "X-AspNet-Version", "X-AspNetMvc-Version"]
SECURITY_HEADERS = ["Content-Security-Policy", "X-Frame-Options", "X-Content-Type-Options",
                    "Strict-Transport-Security", "Referrer-Policy", "Permissions-Policy"]

SOCIAL_PATTERNS = {
    "Twitter/X":   r'(?:twitter\.com|x\.com)/([A-Za-z0-9_]{1,15})',
    "LinkedIn":    r'linkedin\.com/(?:in|company)/([A-Za-z0-9_-]+)',
    "GitHub":      r'github\.com/([A-Za-z0-9_-]+)',
    "Instagram":   r'instagram\.com/([A-Za-z0-9_.]+)',
    "Facebook":    r'facebook\.com/([A-Za-z0-9_.]+)',
    "YouTube":     r'youtube\.com/(?:@|channel/|user/)([A-Za-z0-9_-]+)',
}

# ─────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────
def log(msg, level="INFO"):
    colors = {"INFO": "\033[94m", "OK": "\033[92m", "WARN": "\033[93m",
              "ERR": "\033[91m", "HEAD": "\033[1;96m", "RESET": "\033[0m"}
    icons = {"INFO": "›", "OK": "✓", "WARN": "⚠", "ERR": "✗", "HEAD": "◈"}
    c = colors.get(level, "")
    r = colors["RESET"]
    i = icons.get(level, "·")
    print(f"  {c}{i}{r}  {msg}")

def safe_request(url, timeout=8, method="GET", headers=None):
    try:
        req = urllib.request.Request(url, headers=headers or {
            "User-Agent": "Mozilla/5.0 (compatible; ReconScanner/1.0)"
        }, method=method)
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp, resp.read().decode("utf-8", errors="ignore")
    except Exception as e:
        return None, str(e)

def resolve_host(target):
    """Resolve hostname to IP, or return IP if already numeric."""
    try:
        ipaddress.ip_address(target)
        return target, socket.getfqdn(target)
    except ValueError:
        try:
            ip = socket.gethostbyname(target)
            return ip, target
        except Exception:
            return None, target

# ─────────────────────────────────────────────
# MODULE 1: DNS ENUMERATION
# ─────────────────────────────────────────────
def dns_enum(domain):
    log(f"DNS enumeration → {domain}", "HEAD")
    results = {"domain": domain, "records": {}, "subdomains": []}
    record_types = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]

    for rtype in record_types:
        try:
            out = subprocess.run(
                ["nslookup", f"-type={rtype}", domain],
                capture_output=True, text=True, timeout=5
            )
            lines = [l.strip() for l in out.stdout.splitlines() if l.strip()
                     and not l.startswith("Server") and not l.startswith("Address") and "Non-authoritative" not in l]
            if lines:
                results["records"][rtype] = lines
                log(f"{rtype}: {len(lines)} record(s)", "OK")
        except Exception:
            pass

    # Zone transfer attempt
    try:
        ns_out = subprocess.run(["nslookup", "-type=NS", domain],
                                capture_output=True, text=True, timeout=5)
        ns_servers = re.findall(r'nameserver = (.+)', ns_out.stdout)
        for ns in ns_servers[:2]:
            ns = ns.strip().rstrip(".")
            axfr = subprocess.run(["nslookup", "-type=AXFR", domain, ns],
                                  capture_output=True, text=True, timeout=5)
            if "transfer" in axfr.stdout.lower() and "failed" not in axfr.stdout.lower():
                results["zone_transfer"] = {"ns": ns, "status": "VULNERABLE ⚠️", "data": axfr.stdout[:800]}
                log(f"Zone transfer succeeded on {ns}!", "WARN")
            else:
                results["zone_transfer"] = {"ns": ns, "status": "Blocked ✓"}
    except Exception:
        pass

    # Common subdomain brute-force
    common_subs = ["www", "mail", "ftp", "admin", "api", "dev", "staging",
                   "test", "vpn", "remote", "portal", "shop", "blog", "cdn"]
    found_subs = []
    def check_sub(sub):
        try:
            fqdn = f"{sub}.{domain}"
            ip = socket.gethostbyname(fqdn)
            found_subs.append({"subdomain": fqdn, "ip": ip})
            log(f"Subdomain found: {fqdn} → {ip}", "OK")
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=10) as ex:
        ex.map(check_sub, common_subs)
    results["subdomains"] = found_subs

    return results

# ─────────────────────────────────────────────
# MODULE 2: PORT SCANNING
# ─────────────────────────────────────────────
def port_scan(ip, ports=None, timeout=1.5):
    log(f"Port scanning → {ip}", "HEAD")
    if ports is None:
        ports = list(COMMON_PORTS.keys())

    open_ports = []
    lock = threading.Lock()

    def scan_port(port):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            s.close()
            if result == 0:
                service = COMMON_PORTS.get(port, "Unknown")
                banner = grab_banner(ip, port)
                with lock:
                    open_ports.append({"port": port, "service": service, "banner": banner, "state": "open"})
                    log(f"Port {port}/{service} — OPEN  {banner}", "OK")
        except Exception:
            pass

    with ThreadPoolExecutor(max_workers=50) as ex:
        ex.map(scan_port, ports)

    closed = len(ports) - len(open_ports)
    log(f"Scan complete: {len(open_ports)} open, {closed} closed", "INFO")
    return sorted(open_ports, key=lambda x: x["port"])

def grab_banner(ip, port, timeout=2):
    try:
        s = socket.socket()
        s.settimeout(timeout)
        s.connect((ip, port))
        if port in (80, 8080, 8888):
            s.send(b"HEAD / HTTP/1.0\r\nHost: " + ip.encode() + b"\r\n\r\n")
        elif port == 21:
            pass  # FTP sends banner immediately
        banner = s.recv(256).decode("utf-8", errors="ignore").strip()[:120]
        s.close()
        return banner
    except Exception:
        return ""

# ─────────────────────────────────────────────
# MODULE 3: HTTP HEADER ANALYSIS
# ─────────────────────────────────────────────
def check_http_headers(domain):
    log(f"HTTP header analysis → {domain}", "HEAD")
    results = {"missing_security": [], "info_leaks": [], "raw_headers": {}}

    for scheme in ["https", "http"]:
        url = f"{scheme}://{domain}"
        resp, _ = safe_request(url)
        if resp is None:
            continue

        raw = dict(resp.headers)
        results["raw_headers"] = raw
        results["url"] = url

        for h in SECURITY_HEADERS:
            if h not in raw:
                results["missing_security"].append(h)
                log(f"Missing security header: {h}", "WARN")

        for h in SENSITIVE_HEADERS:
            if h in raw:
                results["info_leaks"].append({h: raw[h]})
                log(f"Info leak header: {h}: {raw[h]}", "WARN")

        # Check cookies
        cookies = resp.headers.get("Set-Cookie", "")
        cookie_issues = []
        if "HttpOnly" not in cookies and cookies:
            cookie_issues.append("Missing HttpOnly flag")
        if "Secure" not in cookies and cookies:
            cookie_issues.append("Missing Secure flag")
        if "SameSite" not in cookies and cookies:
            cookie_issues.append("Missing SameSite flag")
        if cookie_issues:
            results["cookie_issues"] = cookie_issues
            for issue in cookie_issues:
                log(f"Cookie issue: {issue}", "WARN")

        results["status_code"] = resp.status
        break

    if not results["missing_security"]:
        log("All security headers present ✓", "OK")
    return results

# ─────────────────────────────────────────────
# MODULE 4: SSL/TLS ANALYSIS
# ─────────────────────────────────────────────
def check_ssl(domain, port=443):
    log(f"SSL/TLS analysis → {domain}:{port}", "HEAD")
    results = {"issues": [], "info": {}}

    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(8)
            s.connect((domain, port))
            cert = s.getpeercert()
            cipher = s.cipher()
            proto = s.version()

        results["info"]["protocol"] = proto
        results["info"]["cipher"] = cipher[0] if cipher else "Unknown"
        results["info"]["bits"] = cipher[2] if cipher else "Unknown"

        # Expiry check
        exp_str = cert.get("notAfter", "")
        if exp_str:
            exp_dt = datetime.strptime(exp_str, "%b %d %H:%M:%S %Y %Z")
            days_left = (exp_dt - datetime.utcnow()).days
            results["info"]["expires"] = exp_str
            results["info"]["days_until_expiry"] = days_left
            if days_left < 30:
                results["issues"].append(f"Certificate expires in {days_left} days!")
                log(f"Cert expires in {days_left} days!", "WARN")
            else:
                log(f"Certificate valid for {days_left} more days", "OK")

        # Subject / SAN
        results["info"]["subject"] = dict(x[0] for x in cert.get("subject", []))
        results["info"]["issuer"] = dict(x[0] for x in cert.get("issuer", []))
        sans = [v for _, v in cert.get("subjectAltName", [])]
        results["info"]["san"] = sans

        # Weak protocol checks
        for old_proto, old_ver in [("TLSv1", ssl.TLSVersion.TLSv1),
                                    ("TLSv1.1", ssl.TLSVersion.TLSv1_1)]:
            try:
                old_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                old_ctx.check_hostname = False
                old_ctx.verify_mode = ssl.CERT_NONE
                old_ctx.maximum_version = old_ver
                with old_ctx.wrap_socket(socket.socket(), server_hostname=domain) as s2:
                    s2.settimeout(3)
                    s2.connect((domain, port))
                results["issues"].append(f"Weak protocol supported: {old_proto}")
                log(f"Weak protocol supported: {old_proto}", "WARN")
            except Exception:
                log(f"{old_proto} not supported ✓", "OK")

        log(f"Protocol: {proto} | Cipher: {cipher[0]}", "OK")

    except ssl.SSLCertVerificationError as e:
        results["issues"].append(f"SSL Verification Error: {e}")
        log(f"SSL cert verification failed: {e}", "ERR")
    except Exception as e:
        results["issues"].append(f"SSL check failed: {e}")
        log(f"SSL check error: {e}", "ERR")

    return results

# ─────────────────────────────────────────────
# MODULE 5: WEB VULNERABILITY CHECKS
# ─────────────────────────────────────────────
def check_web_vulns(domain):
    log(f"Web vulnerability checks → {domain}", "HEAD")
    results = {"sqli": [], "xss": [], "open_redirect": [], "exposed_files": []}

    base_url = f"https://{domain}" if not domain.startswith("http") else domain

    # Common exposed sensitive files
    sensitive_paths = [
        "/.git/config", "/.env", "/wp-config.php", "/config.php",
        "/phpinfo.php", "/adminer.php", "/server-status", "/.htaccess",
        "/robots.txt", "/sitemap.xml", "/backup.zip", "/dump.sql",
        "/.DS_Store", "/web.config", "/composer.json", "/package.json",
        "/api/swagger.json", "/api/openapi.json", "/.well-known/security.txt"
    ]

    def check_path(path):
        url = base_url + path
        resp, body = safe_request(url)
        if resp and resp.status == 200:
            size = len(body)
            results["exposed_files"].append({"path": path, "size": size, "status": 200})
            log(f"Exposed file: {path} ({size} bytes)", "WARN")

    with ThreadPoolExecutor(max_workers=10) as ex:
        ex.map(check_path, sensitive_paths)

    # SQL Injection test (GET parameter probe)
    test_url = base_url + "/search?q="
    for payload in SQLI_PAYLOADS[:3]:
        encoded = urllib.parse.quote(payload)
        resp, body = safe_request(test_url + encoded)
        if body:
            sql_errors = ["sql syntax", "mysql_fetch", "ORA-", "pg_query",
                          "sqlite_", "SQLSTATE", "unclosed quotation", "syntax error"]
            found = [e for e in sql_errors if e.lower() in body.lower()]
            if found:
                results["sqli"].append({"payload": payload, "indicators": found})
                log(f"SQLi indicator with payload '{payload}': {found}", "WARN")

    # XSS probe
    for payload in XSS_PAYLOADS[:2]:
        encoded = urllib.parse.quote(payload)
        resp, body = safe_request(test_url + encoded)
        if body and payload in body:
            results["xss"].append({"payload": payload, "reflected": True})
            log(f"Reflected XSS detected with payload!", "WARN")

    # Open redirect test
    redirect_test = base_url + "/redirect?url=https://evil.com"
    resp, _ = safe_request(redirect_test)
    if resp and str(resp.url).startswith("https://evil.com"):
        results["open_redirect"].append(redirect_test)
        log("Open redirect vulnerability detected!", "WARN")

    if not any([results["sqli"], results["xss"], results["exposed_files"]]):
        log("No obvious web vulnerabilities found", "OK")

    return results

# ─────────────────────────────────────────────
# MODULE 6: EMAIL OSINT
# ─────────────────────────────────────────────
def email_osint(email):
    log(f"Email OSINT → {email}", "HEAD")
    results = {"email": email, "issues": [], "info": {}}

    if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
        log("Invalid email format", "ERR")
        results["issues"].append("Invalid email format")
        return results

    user, domain = email.split("@", 1)
    results["info"]["username"] = user
    results["info"]["domain"] = domain

    # Gravatar check
    email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
    gravatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"
    resp, _ = safe_request(gravatar_url)
    if resp and resp.status == 200:
        results["info"]["gravatar"] = f"https://www.gravatar.com/avatar/{email_hash}"
        log("Gravatar profile found!", "OK")
    else:
        log("No Gravatar profile", "INFO")

    # Breach check (haveibeenpwned.com public API)
    try:
        breach_url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}"
        req = urllib.request.Request(breach_url, headers={
            "User-Agent": "ReconScanner/1.0",
            "hibp-api-key": "none"  # public endpoint may require key; returns 401 if so
        })
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                breaches = json.loads(r.read())
                results["info"]["breaches"] = [b["Name"] for b in breaches]
                log(f"Found in {len(breaches)} breach(es): {', '.join(results['info']['breaches'][:5])}", "WARN")
        except urllib.error.HTTPError as e:
            if e.code == 404:
                log("Not found in known breaches ✓", "OK")
                results["info"]["breaches"] = []
            elif e.code == 401:
                log("HIBP API key required for breach check", "INFO")
                results["info"]["breaches"] = "API key required"
            else:
                results["info"]["breaches"] = f"HTTP {e.code}"
    except Exception as ex:
        results["info"]["breaches"] = f"Error: {ex}"

    # MX record check for email domain
    try:
        mx_out = subprocess.run(["nslookup", "-type=MX", domain],
                                capture_output=True, text=True, timeout=5)
        mx_lines = [l.strip() for l in mx_out.stdout.splitlines()
                    if "mail exchanger" in l.lower() or "MX" in l]
        results["info"]["mx_records"] = mx_lines
        if mx_lines:
            log(f"MX records: {len(mx_lines)} found", "OK")
    except Exception:
        pass

    # SPF/DKIM/DMARC
    for rec_type, record_name in [("SPF", domain), ("DMARC", f"_dmarc.{domain}")]:
        try:
            out = subprocess.run(["nslookup", "-type=TXT", record_name],
                                 capture_output=True, text=True, timeout=5)
            txt = out.stdout
            if rec_type == "SPF" and "spf" in txt.lower():
                results["info"]["spf"] = "Present ✓"
                log("SPF record found ✓", "OK")
            elif rec_type == "SPF":
                results["info"]["spf"] = "Missing ⚠️"
                log("SPF record missing!", "WARN")
            if rec_type == "DMARC" and "dmarc" in txt.lower():
                results["info"]["dmarc"] = "Present ✓"
                log("DMARC record found ✓", "OK")
            elif rec_type == "DMARC":
                results["info"]["dmarc"] = "Missing ⚠️"
                log("DMARC record missing!", "WARN")
        except Exception:
            pass

    return results

# ─────────────────────────────────────────────
# MODULE 7: SOCIAL MEDIA SCRAPING
# ─────────────────────────────────────────────
def social_enum(domain):
    log(f"Social media enumeration → {domain}", "HEAD")
    results = {"found": [], "platforms_checked": list(SOCIAL_PATTERNS.keys())}
    base_url = f"https://{domain}"

    resp, body = safe_request(base_url)
    if not body:
        log("Could not fetch website content", "ERR")
        return results

    for platform, pattern in SOCIAL_PATTERNS.items():
        matches = re.findall(pattern, body, re.IGNORECASE)
        if matches:
            for handle in set(matches):
                results["found"].append({"platform": platform, "handle": handle})
                log(f"{platform}: @{handle}", "OK")

    # Check for contact/about page
    for page in ["/about", "/contact", "/team"]:
        _, page_body = safe_request(base_url + page)
        if page_body:
            for platform, pattern in SOCIAL_PATTERNS.items():
                matches = re.findall(pattern, page_body, re.IGNORECASE)
                for handle in set(matches):
                    entry = {"platform": platform, "handle": handle}
                    if entry not in results["found"]:
                        results["found"].append(entry)
                        log(f"{platform} (from {page}): @{handle}", "OK")

    if not results["found"]:
        log("No social profiles found in page source", "INFO")

    return results

# ─────────────────────────────────────────────
# MODULE 8: WHOIS / IP INFO
# ─────────────────────────────────────────────
def whois_lookup(target):
    log(f"WHOIS lookup → {target}", "HEAD")
    results = {}
    try:
        out = subprocess.run(["whois", target], capture_output=True, text=True, timeout=10)
        lines = out.stdout.splitlines()
        for line in lines:
            if ":" in line:
                k, _, v = line.partition(":")
                k, v = k.strip(), v.strip()
                if k and v and k not in results:
                    results[k] = v
        log(f"WHOIS data retrieved: {len(results)} fields", "OK")
    except Exception as e:
        log(f"WHOIS failed: {e}", "ERR")
    return results

# ─────────────────────────────────────────────
# HTML REPORT GENERATOR
# ─────────────────────────────────────────────
def generate_html_report(data, output_file="recon_report.html"):
    log(f"\nGenerating HTML report → {output_file}", "HEAD")

    scan_time = datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")
    target_display = data.get("target", "Unknown")

    def severity_badge(text, level="info"):
        colors = {"high": "#ff4757", "medium": "#ffa502", "low": "#2ed573", "info": "#1e90ff"}
        c = colors.get(level, "#999")
        return f'<span class="badge" style="background:{c}">{text}</span>'

    def section(title, icon, content_html):
        return f"""
        <section class="card">
          <h2><span class="icon">{icon}</span>{title}</h2>
          <div class="card-body">{content_html}</div>
        </section>"""

    def kv_table(d, highlight_keys=None):
        if not d:
            return "<p class='empty'>No data</p>"
        rows = ""
        for k, v in d.items():
            if isinstance(v, (list, dict)):
                v = json.dumps(v, indent=2)
            hl = " class='highlight'" if highlight_keys and k in highlight_keys else ""
            rows += f"<tr{hl}><td class='key'>{k}</td><td class='val'>{v}</td></tr>"
        return f"<table class='kv-table'>{rows}</table>"

    def list_items(lst):
        if not lst:
            return "<p class='empty'>None found</p>"
        return "<ul>" + "".join(f"<li>{i}</li>" for i in lst) + "</ul>"

    # ── PORT SECTION ──
    open_ports = data.get("ports", [])
    port_rows = ""
    for p in open_ports:
        risk = "high" if p["port"] in [21, 23, 3389, 5900] else "medium" if p["port"] in [80, 8080] else "low"
        port_rows += f"""<tr>
          <td><strong>{p['port']}</strong></td>
          <td>{p['service']}</td>
          <td>{severity_badge('OPEN', risk)}</td>
          <td class='banner'>{p.get('banner','')[:80]}</td>
        </tr>"""
    ports_html = f"""
    <table class='port-table'>
      <thead><tr><th>Port</th><th>Service</th><th>State</th><th>Banner</th></tr></thead>
      <tbody>{port_rows if port_rows else "<tr><td colspan='4' class='empty'>No open ports detected</td></tr>"}</tbody>
    </table>"""

    # ── DNS SECTION ──
    dns = data.get("dns", {})
    dns_html = ""
    for rtype, records in dns.get("records", {}).items():
        dns_html += f"<div class='dns-block'><strong>{rtype}</strong><ul>"
        for r in records:
            dns_html += f"<li>{r}</li>"
        dns_html += "</ul></div>"
    zt = dns.get("zone_transfer", {})
    if zt:
        color = "#ff4757" if "VULNERABLE" in zt.get("status","") else "#2ed573"
        dns_html += f"<div class='alert' style='border-left-color:{color}'>Zone Transfer: {zt.get('status','')}</div>"
    subs = dns.get("subdomains", [])
    if subs:
        dns_html += "<div class='dns-block'><strong>Subdomains Found</strong><ul>"
        for s in subs:
            dns_html += f"<li>{s['subdomain']} → {s['ip']}</li>"
        dns_html += "</ul></div>"

    # ── HEADERS SECTION ──
    headers = data.get("headers", {})
    missing = headers.get("missing_security", [])
    leaks = headers.get("info_leaks", [])
    headers_html = ""
    if missing:
        headers_html += "<div class='alert alert-warn'><strong>⚠ Missing Security Headers:</strong><ul>"
        headers_html += "".join(f"<li>{h}</li>" for h in missing)
        headers_html += "</ul></div>"
    if leaks:
        headers_html += "<div class='alert alert-danger'><strong>⚠ Info Leak Headers:</strong><ul>"
        for d in leaks:
            for k, v in d.items():
                headers_html += f"<li><code>{k}: {v}</code></li>"
        headers_html += "</ul></div>"
    cookie_issues = headers.get("cookie_issues", [])
    if cookie_issues:
        headers_html += "<div class='alert alert-warn'><strong>Cookie Issues:</strong><ul>"
        headers_html += "".join(f"<li>{i}</li>" for i in cookie_issues)
        headers_html += "</ul></div>"
    if not headers_html:
        headers_html = "<div class='alert alert-ok'>All security headers present ✓</div>"

    # ── SSL SECTION ──
    ssl_data = data.get("ssl", {})
    ssl_info = ssl_data.get("info", {})
    ssl_issues = ssl_data.get("issues", [])
    ssl_html = kv_table(ssl_info)
    if ssl_issues:
        ssl_html += "<div class='alert alert-danger'><strong>SSL Issues:</strong><ul>"
        ssl_html += "".join(f"<li>{i}</li>" for i in ssl_issues)
        ssl_html += "</ul></div>"

    # ── VULNS SECTION ──
    vulns = data.get("vulnerabilities", {})
    vulns_html = ""
    if vulns.get("sqli"):
        vulns_html += "<div class='alert alert-danger'><strong>⚠ SQL Injection Indicators</strong><ul>"
        for v in vulns["sqli"]:
            vulns_html += f"<li>Payload: <code>{v['payload']}</code> — Indicators: {v['indicators']}</li>"
        vulns_html += "</ul></div>"
    if vulns.get("xss"):
        vulns_html += "<div class='alert alert-danger'><strong>⚠ Reflected XSS Detected</strong><ul>"
        for v in vulns["xss"]:
            vulns_html += f"<li>Payload reflected: <code>{v['payload']}</code></li>"
        vulns_html += "</ul></div>"
    if vulns.get("exposed_files"):
        vulns_html += "<div class='alert alert-warn'><strong>⚠ Exposed Sensitive Files</strong><ul>"
        for f in vulns["exposed_files"]:
            vulns_html += f"<li><code>{f['path']}</code> ({f['size']} bytes)</li>"
        vulns_html += "</ul></div>"
    if not vulns_html:
        vulns_html = "<div class='alert alert-ok'>No obvious vulnerabilities detected</div>"

    # ── EMAIL SECTION ──
    email_data = data.get("email_osint", {})
    email_html = kv_table(email_data.get("info", {}))
    breaches = email_data.get("info", {}).get("breaches", [])
    if isinstance(breaches, list) and breaches:
        email_html += f"<div class='alert alert-danger'>⚠ Found in <strong>{len(breaches)}</strong> breach(es): {', '.join(breaches[:10])}</div>"
    elif isinstance(breaches, list):
        email_html += "<div class='alert alert-ok'>Not found in known data breaches ✓</div>"

    # ── SOCIAL SECTION ──
    social_data = data.get("socials", {}).get("found", [])
    social_html = ""
    if social_data:
        social_html = "<div class='social-grid'>"
        for s in social_data:
            social_html += f"<div class='social-card'><strong>{s['platform']}</strong><br>@{s['handle']}</div>"
        social_html += "</div>"
    else:
        social_html = "<p class='empty'>No social profiles detected in page source</p>"

    # ── WHOIS SECTION ──
    whois_data = data.get("whois", {})
    important_whois = ["Registrar", "Creation Date", "Registry Expiry Date",
                       "Name Server", "Registrant Organization", "Registrant Country",
                       "Updated Date", "DNSSEC"]
    whois_html = kv_table({k: v for k, v in whois_data.items() if k in important_whois})

    # ── SCORE CALCULATION ──
    score = 100
    score -= len(missing) * 8
    score -= len(leaks) * 5
    score -= len(ssl_issues) * 10
    score -= len(vulns.get("sqli", [])) * 20
    score -= len(vulns.get("xss", [])) * 15
    score -= len(vulns.get("exposed_files", [])) * 10
    if isinstance(breaches, list) and breaches:
        score -= min(len(breaches) * 5, 20)
    score = max(0, min(100, score))
    score_color = "#2ed573" if score >= 75 else "#ffa502" if score >= 50 else "#ff4757"
    score_label = "Good" if score >= 75 else "Fair" if score >= 50 else "Poor"

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>ReconScanner Report — {target_display}</title>
<style>
  @import url('https://fonts.googleapis.com/css2?family=Space+Mono:wght@400;700&family=IBM+Plex+Sans:wght@300;400;600&display=swap');

  :root {{
    --bg: #0a0c14;
    --surface: #111520;
    --surface2: #181d2e;
    --border: #1e2540;
    --accent: #00d2ff;
    --accent2: #7b2ff7;
    --text: #c8d6ef;
    --text-muted: #5a6a8a;
    --danger: #ff4757;
    --warn: #ffa502;
    --ok: #2ed573;
    --mono: 'Space Mono', monospace;
    --sans: 'IBM Plex Sans', sans-serif;
  }}

  * {{ margin: 0; padding: 0; box-sizing: border-box; }}

  body {{
    background: var(--bg);
    color: var(--text);
    font-family: var(--sans);
    font-size: 14px;
    line-height: 1.6;
    background-image:
      radial-gradient(ellipse 80% 50% at 20% -20%, rgba(0,210,255,0.06) 0%, transparent 60%),
      radial-gradient(ellipse 60% 40% at 80% 110%, rgba(123,47,247,0.07) 0%, transparent 60%);
  }}

  /* HEADER */
  .report-header {{
    background: linear-gradient(135deg, #0d1118 0%, #121828 100%);
    border-bottom: 1px solid var(--border);
    padding: 48px 40px 40px;
    position: relative;
    overflow: hidden;
  }}
  .report-header::before {{
    content: '';
    position: absolute;
    top: 0; left: 0; right: 0;
    height: 2px;
    background: linear-gradient(90deg, var(--accent), var(--accent2), var(--accent));
  }}
  .report-header::after {{
    content: 'RECON';
    position: absolute;
    right: -20px; top: 50%;
    transform: translateY(-50%);
    font-family: var(--mono);
    font-size: 140px;
    font-weight: 700;
    color: rgba(255,255,255,0.015);
    letter-spacing: -5px;
    user-select: none;
  }}

  .header-top {{ display: flex; align-items: flex-start; justify-content: space-between; }}
  .logo {{ font-family: var(--mono); font-size: 11px; color: var(--accent); letter-spacing: 3px; text-transform: uppercase; margin-bottom: 20px; }}
  
  h1 {{
    font-family: var(--mono);
    font-size: 28px;
    font-weight: 700;
    color: #fff;
    letter-spacing: -0.5px;
    margin-bottom: 8px;
  }}
  h1 span {{ color: var(--accent); }}

  .meta {{ font-size: 12px; color: var(--text-muted); font-family: var(--mono); }}
  .meta span {{ color: var(--text); }}

  /* SCORE RING */
  .score-ring {{
    display: flex; flex-direction: column; align-items: center; justify-content: center;
    width: 110px; height: 110px;
    border-radius: 50%;
    border: 3px solid var(--border);
    background: var(--surface);
    position: relative;
    flex-shrink: 0;
  }}
  .score-ring .score-num {{
    font-family: var(--mono);
    font-size: 30px;
    font-weight: 700;
    color: {score_color};
    line-height: 1;
  }}
  .score-ring .score-label {{
    font-size: 10px;
    text-transform: uppercase;
    letter-spacing: 1px;
    color: var(--text-muted);
    margin-top: 2px;
  }}

  /* SUMMARY PILLS */
  .summary-pills {{ display: flex; gap: 12px; flex-wrap: wrap; margin-top: 24px; }}
  .pill {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 20px;
    padding: 6px 16px;
    font-size: 12px;
    font-family: var(--mono);
    display: flex; gap: 8px; align-items: center;
  }}
  .pill .dot {{ width: 7px; height: 7px; border-radius: 50%; }}

  /* MAIN LAYOUT */
  main {{ max-width: 1100px; margin: 0 auto; padding: 40px 24px; }}

  /* CARDS */
  .card {{
    background: var(--surface);
    border: 1px solid var(--border);
    border-radius: 12px;
    margin-bottom: 24px;
    overflow: hidden;
    transition: border-color 0.2s;
  }}
  .card:hover {{ border-color: rgba(0,210,255,0.2); }}
  .card h2 {{
    font-family: var(--mono);
    font-size: 13px;
    font-weight: 700;
    text-transform: uppercase;
    letter-spacing: 2px;
    padding: 16px 24px;
    border-bottom: 1px solid var(--border);
    background: var(--surface2);
    display: flex; align-items: center; gap: 12px;
    color: #fff;
  }}
  .icon {{ font-size: 16px; }}
  .card-body {{ padding: 20px 24px; }}

  /* TABLES */
  .kv-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .kv-table tr {{ border-bottom: 1px solid var(--border); }}
  .kv-table tr:last-child {{ border-bottom: none; }}
  .kv-table td {{ padding: 8px 12px; vertical-align: top; }}
  .kv-table .key {{ color: var(--text-muted); font-family: var(--mono); font-size: 12px; width: 220px; }}
  .kv-table .val {{ color: var(--text); word-break: break-all; }}
  .kv-table tr.highlight td {{ background: rgba(255, 71, 87, 0.05); }}

  .port-table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
  .port-table th {{ text-align: left; padding: 10px 14px; border-bottom: 1px solid var(--border); font-family: var(--mono); font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; }}
  .port-table td {{ padding: 9px 14px; border-bottom: 1px solid rgba(30,37,64,0.7); }}
  .port-table .banner {{ color: var(--text-muted); font-family: var(--mono); font-size: 11px; max-width: 300px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }}

  /* ALERTS */
  .alert {{ padding: 12px 16px; border-radius: 8px; border-left: 3px solid; margin-bottom: 12px; font-size: 13px; }}
  .alert-danger {{ background: rgba(255,71,87,0.06); border-left-color: var(--danger); }}
  .alert-warn {{ background: rgba(255,165,2,0.06); border-left-color: var(--warn); }}
  .alert-ok {{ background: rgba(46,213,115,0.06); border-left-color: var(--ok); color: var(--ok); }}
  .alert ul {{ margin-top: 6px; padding-left: 20px; }}
  .alert li {{ margin-bottom: 4px; }}

  /* BADGES */
  .badge {{ padding: 3px 8px; border-radius: 4px; font-family: var(--mono); font-size: 11px; font-weight: 700; color: #fff; }}

  /* DNS */
  .dns-block {{ margin-bottom: 14px; }}
  .dns-block strong {{ font-family: var(--mono); font-size: 12px; color: var(--accent); text-transform: uppercase; letter-spacing: 1px; }}
  .dns-block ul {{ padding-left: 20px; margin-top: 4px; color: var(--text); font-size: 13px; }}

  /* SOCIAL */
  .social-grid {{ display: grid; grid-template-columns: repeat(auto-fill, minmax(160px, 1fr)); gap: 12px; }}
  .social-card {{
    background: var(--surface2);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 14px 16px;
    text-align: center;
    font-size: 13px;
  }}
  .social-card strong {{ color: var(--accent); display: block; margin-bottom: 4px; font-size: 12px; text-transform: uppercase; letter-spacing: 1px; }}

  .empty {{ color: var(--text-muted); font-style: italic; }}

  code {{ font-family: var(--mono); background: var(--surface2); padding: 1px 6px; border-radius: 3px; font-size: 12px; }}

  /* FOOTER */
  footer {{
    text-align: center;
    padding: 32px;
    color: var(--text-muted);
    font-family: var(--mono);
    font-size: 11px;
    border-top: 1px solid var(--border);
    letter-spacing: 1px;
  }}
  footer a {{ color: var(--accent); text-decoration: none; }}

  ul {{ padding-left: 18px; }}
  li {{ margin-bottom: 3px; }}
</style>
</head>
<body>

<header class="report-header">
  <div class="logo">◈ ReconScanner · Security Assessment Report</div>
  <div class="header-top">
    <div>
      <h1>Target: <span>{target_display}</span></h1>
      <div class="meta">
        Scan completed: <span>{scan_time}</span><br>
        IP resolved: <span>{data.get('ip', 'N/A')}</span> &nbsp;|&nbsp;
        Hostname: <span>{data.get('hostname', 'N/A')}</span>
      </div>
    </div>
    <div class="score-ring">
      <div class="score-num">{score}</div>
      <div class="score-label">{score_label}</div>
    </div>
  </div>

  <div class="summary-pills">
    <div class="pill"><div class="dot" style="background:#00d2ff"></div>{len(open_ports)} Open Ports</div>
    <div class="pill"><div class="dot" style="background:#ffa502"></div>{len(missing)} Missing Headers</div>
    <div class="pill"><div class="dot" style="background:#ff4757"></div>{len(ssl_data.get('issues', []))} SSL Issues</div>
    <div class="pill"><div class="dot" style="background:#ff4757"></div>{len(vulns.get('sqli', []))} SQLi Indicators</div>
    <div class="pill"><div class="dot" style="background:#ff4757"></div>{len(vulns.get('exposed_files', []))} Exposed Files</div>
    <div class="pill"><div class="dot" style="background:#7b2ff7"></div>{len(social_data)} Social Profiles</div>
  </div>
</header>

<main>
  {section("Port Scan Results", "🔌", ports_html)}
  {section("DNS Enumeration", "🌐", dns_html if dns_html else "<p class='empty'>No DNS data collected</p>")}
  {section("HTTP Security Headers", "🛡️", headers_html)}
  {section("SSL/TLS Analysis", "🔒", ssl_html)}
  {section("Web Vulnerability Scan", "⚡", vulns_html)}
  {section("Email OSINT", "📧", email_html if email_data else "<p class='empty'>No email target provided</p>")}
  {section("Social Media Profiles", "🔗", social_html)}
  {section("WHOIS Information", "📋", whois_html if whois_data else "<p class='empty'>No WHOIS data</p>")}
</main>

<footer>
  Generated by <a href="#">ReconScanner</a> · {scan_time} · For authorized security testing only
</footer>

</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)

    log(f"Report saved: {output_file}", "OK")
    return output_file

# ─────────────────────────────────────────────
# MAIN ORCHESTRATOR
# ─────────────────────────────────────────────
def main():
    print("""
\033[1;96m
  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
  \033[0;96mSCANNER\033[0m  — OSINT & Vulnerability Assessment
  \033[90mFor authorized use only | Educational purposes\033[0m
""")

    parser = argparse.ArgumentParser(description="ReconScanner — OSINT & Vuln Assessment")
    parser.add_argument("-d", "--domain", help="Target domain (e.g. example.com)")
    parser.add_argument("-i", "--ip", help="Target IP address")
    parser.add_argument("-e", "--email", help="Target email address")
    parser.add_argument("-o", "--output", default="recon_report.html", help="Output HTML report file")
    parser.add_argument("--ports", help="Custom ports (comma-separated, e.g. 80,443,8080)")
    parser.add_argument("--quick", action="store_true", help="Quick scan (fewer modules)")
    args = parser.parse_args()

    if not any([args.domain, args.ip, args.email]):
        # Interactive mode
        print("  \033[96mInteractive Mode\033[0m — Enter targets (leave blank to skip)\n")
        args.domain = input("  Domain  (e.g. example.com)  : ").strip() or None
        args.ip     = input("  IP      (e.g. 1.2.3.4)      : ").strip() or None
        args.email  = input("  Email   (e.g. you@example.com): ").strip() or None
        args.output = input("  Output  [recon_report.html]  : ").strip() or "recon_report.html"
        print()

    target = args.domain or args.ip
    if not target:
        print("  \033[91m✗\033[0m  No target specified. Exiting.")
        sys.exit(1)

    # Resolve IP
    ip, hostname = resolve_host(target)
    if not ip:
        print(f"  \033[91m✗\033[0m  Could not resolve {target}")
        sys.exit(1)

    report_data = {
        "target": target,
        "ip": ip,
        "hostname": hostname,
        "scan_time": datetime.now().isoformat(),
    }

    print(f"\n  \033[92m✓\033[0m  Target: {target} → {ip}\n")
    t0 = time.time()

    # Custom ports
    custom_ports = None
    if args.ports:
        try:
            custom_ports = [int(p.strip()) for p in args.ports.split(",")]
        except ValueError:
            pass

    # Run modules
    try:
        report_data["ports"] = port_scan(ip, ports=custom_ports)
    except Exception as e:
        log(f"Port scan failed: {e}", "ERR"); report_data["ports"] = []

    if args.domain:
        try:
            report_data["dns"] = dns_enum(args.domain)
        except Exception as e:
            log(f"DNS enum failed: {e}", "ERR"); report_data["dns"] = {}

        if not args.quick:
            try:
                report_data["headers"] = check_http_headers(args.domain)
            except Exception as e:
                log(f"Header check failed: {e}", "ERR"); report_data["headers"] = {}

            try:
                report_data["ssl"] = check_ssl(args.domain)
            except Exception as e:
                log(f"SSL check failed: {e}", "ERR"); report_data["ssl"] = {}

            try:
                report_data["vulnerabilities"] = check_web_vulns(args.domain)
            except Exception as e:
                log(f"Vuln check failed: {e}", "ERR"); report_data["vulnerabilities"] = {}

            try:
                report_data["socials"] = social_enum(args.domain)
            except Exception as e:
                log(f"Social enum failed: {e}", "ERR"); report_data["socials"] = {}

        try:
            report_data["whois"] = whois_lookup(args.domain)
        except Exception as e:
            log(f"WHOIS failed: {e}", "ERR"); report_data["whois"] = {}

    elif args.ip:
        try:
            report_data["whois"] = whois_lookup(args.ip)
        except Exception: report_data["whois"] = {}

    if args.email:
        try:
            report_data["email_osint"] = email_osint(args.email)
        except Exception as e:
            log(f"Email OSINT failed: {e}", "ERR"); report_data["email_osint"] = {}

    # Generate report
    out = generate_html_report(report_data, args.output)
    elapsed = time.time() - t0
    print(f"\n  \033[1;92m✓  Scan complete in {elapsed:.1f}s\033[0m")
    print(f"  \033[96m◈  Report:\033[0m {out}\n")

    # Save raw JSON too
    json_out = args.output.replace(".html", ".json")
    with open(json_out, "w") as f:
        json.dump(report_data, f, indent=2, default=str)
    print(f"  \033[90m◦  Raw JSON: {json_out}\033[0m\n")

if __name__ == "__main__":
    main()
