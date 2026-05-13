#!/usr/bin/env python3
"""
dns_fetch.py — Periodic DNS audit tool

Reads a list of customers/domains from customers.csv and writes one
Markdown file per domain into the ./dns_records/ output directory.

Optionally syncs each DNS note to 1Password as a Secure Note using the
1Password CLI (requires `op` to be installed and signed in).

Usage:
    python dns_fetch.py              # write .md files only
    python dns_fetch.py --op-sync   # write .md files AND push to 1Password

Requirements:
    pip install dnspython requests python-whois
    brew install 1password-cli      # for --op-sync
"""

import argparse
import csv
import subprocess
import sys
import time
import requests
import dns.resolver
import dns.exception
import dns.reversename
from datetime import date, datetime, timedelta
from pathlib import Path

try:
    import whois as whois_lib
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "SRV", "CAA"]

COMMON_SUBDOMAINS = [
    "www", "mail", "email", "webmail", "smtp", "imap", "pop", "ftp",
    "autodiscover", "autoconfig", "blog", "shop", "store", "app",
    "api", "cdn", "media", "static", "assets",
]

DKIM_SELECTORS = [
    "google", "selector1", "selector2", "default", "mail", "dkim",
    "k1", "k2", "smtp", "email", "s1", "s2", "key1", "key2",
    "mandrill", "mailchimp", "sendgrid", "amazonses", "mg",
    "mimecast", "zoho",
]

# Ordered most-specific first where patterns could overlap
NS_PROVIDERS = [
    ("awsdns",                "AWS Route 53"),
    ("cloudflare.com",        "Cloudflare"),
    ("googledomains.com",     "Google Cloud DNS"),
    ("domaincontrol.com",     "GoDaddy"),
    ("registrar-servers.com", "Namecheap"),
    ("azure-dns.com",         "Azure DNS"),
    ("azure-dns.net",         "Azure DNS"),
    ("azure-dns.org",         "Azure DNS"),
    ("azure-dns.info",        "Azure DNS"),
    ("digitalocean.com",      "DigitalOcean"),
    ("nsone.net",             "NS1"),
    ("dnsimple.com",          "DNSimple"),
    ("name.com",              "Name.com"),
    ("squarespace.com",       "Squarespace"),
    ("wixdns.net",            "Wix"),
    ("easydns.com",           "easyDNS"),
    ("linode.com",            "Linode/Akamai"),
    ("porkbun.com",           "Porkbun"),
    ("gandi.net",             "Gandi"),
    ("ovh.net",               "OVH"),
    ("ovh.ca",                "OVH"),
    ("dreamhost.com",         "DreamHost"),
    ("dynadot.com",           "Dynadot"),
    ("hover.com",             "Hover"),
    ("stabletransit.com",     "Rackspace"),
    ("dnsmadeeasy.com",       "DNS Made Easy"),
    ("pair.com",              "pair Networks"),
    ("pairnic.com",           "pair Networks"),
    ("inmotionhosting.com",   "InMotion Hosting"),
    ("siteground.net",        "SiteGround"),
    ("siteground.biz",        "SiteGround"),
    ("messagingengine.com",   "Fastmail"),
    ("sucuri.net",            "Sucuri"),
    ("ui-dns.de",             "IONOS/1&1"),
    ("ui-dns.com",            "IONOS/1&1"),
    ("ui-dns.org",            "IONOS/1&1"),
    ("ui-dns.biz",            "IONOS/1&1"),
]

MX_PROVIDERS = [
    ("google.com",                  "Google Workspace"),
    ("googlemail.com",              "Google Workspace"),
    ("mail.protection.outlook.com", "Microsoft 365"),
    ("pphosted.com",                "Proofpoint"),
    ("mimecast.com",                "Mimecast"),
    ("messagingengine.com",         "Fastmail"),
    ("zoho.com",                    "Zoho Mail"),
    ("zohomail.com",                "Zoho Mail"),
    ("emailsrvr.com",               "Rackspace Email"),
    ("secureserver.net",            "GoDaddy Email"),
    ("privateemail.com",            "Namecheap Email"),
    ("dreamhost.com",               "DreamHost Mail"),
    ("pair.com",                    "pair Networks Mail"),
    ("protonmail.ch",               "Proton Mail"),
    ("proton.me",                   "Proton Mail"),
    ("icloud.com",                  "Apple iCloud Mail"),
    ("yahoodns.net",                "Yahoo Mail"),
    ("yahoo.com",                   "Yahoo Mail"),
    ("mxroute.com",                 "MXroute"),
    ("mxlogin.com",                 "MXroute"),
    ("mandrillapp.com",             "Mandrill"),
    ("sendgrid.net",                "SendGrid"),
    ("amazonses.com",               "Amazon SES"),
    ("mailgun.org",                 "Mailgun"),
    ("mtasv.net",                   "Postmark"),
    ("titan.email",                 "Titan Mail"),
    ("inmotionhosting.com",         "InMotion Hosting Mail"),
    ("bluehost.com",                "Bluehost Mail"),
    ("unifiedlayer.com",            "Bluehost/Unified Layer Mail"),
]

OUTPUT_DIR = Path("dns_records")

REDIRECT_CODES = (301, 302, 307, 308)


def op_note_title(domain: str) -> str:
    return f"DNS: {domain}"


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

_dns_cache: dict[tuple[str, str], list[str]] = {}
_ttl_cache: dict[tuple[str, str], int | str] = {}


def query_record(domain: str, rtype: str) -> list[str]:
    """Return a list of string-formatted answers, or [] on any failure.
    Results are cached so repeated calls for the same name/type are free."""
    key = (domain.lower(), rtype)
    if key not in _dns_cache:
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 8
            answers = resolver.resolve(domain, rtype)
            _dns_cache[key] = [rdata.to_text() for rdata in answers]
            _ttl_cache[key] = answers.rrset.ttl if answers.rrset else "—"
        except (
            dns.resolver.NXDOMAIN,
            dns.resolver.NoAnswer,
            dns.resolver.NoNameservers,
            dns.exception.Timeout,
            dns.exception.DNSException,
        ):
            _dns_cache[key] = []
            _ttl_cache[key] = "—"
    return _dns_cache[key]


def get_ttl(domain: str, rtype: str) -> int | str:
    """Return the cached TTL for a record type, querying first if needed."""
    key = (domain.lower(), rtype)
    if key not in _ttl_cache:
        query_record(domain, rtype)
    return _ttl_cache.get(key, "—")


def get_subdomains_crtsh(domain: str) -> list[str]:
    """
    Fetch subdomains from Certificate Transparency logs via crt.sh, then
    supplement with a wordlist probe for common names that may lack certs.
    Returns a sorted, deduplicated list of subdomains (excluding the apex).
    """
    subdomains: set[str] = set()

    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=30)
        if resp.status_code == 200:
            for entry in resp.json():
                for name in entry.get("name_value", "").splitlines():
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") and name != domain:
                        subdomains.add(name.lower())
    except Exception as exc:
        print(f"    [warn] crt.sh lookup failed for {domain}: {exc}")

    # Probe common subdomain names that may not appear in cert logs.
    # Use a canary query to detect wildcard DNS (e.g. Cloudflare proxying all
    # subdomains) so we don't add bogus wordlist hits. crt.sh results above are
    # always kept — they represent real issued certificates.
    canary = f"__wildcard-canary__.{domain}"
    canary_a    = set(query_record(canary, "A"))
    canary_cname = query_record(canary, "CNAME")
    for label in COMMON_SUBDOMAINS:
        fqdn = f"{label}.{domain}"
        if fqdn in subdomains:
            continue
        cname = query_record(fqdn, "CNAME")
        a = set(query_record(fqdn, "A"))
        if not a and not cname:
            continue  # doesn't resolve at all
        if canary_a and a == canary_a and not cname:
            continue  # wildcard hit via A records
        if canary_cname and cname == canary_cname:
            continue  # wildcard hit via CNAME
        subdomains.add(fqdn)

    return sorted(subdomains)


# ---------------------------------------------------------------------------
# Hosting detection
# ---------------------------------------------------------------------------

def guess_dns_host(ns_records: list[str]) -> str:
    """Map NS records to a known DNS provider name."""
    for ns in ns_records:
        ns_lower = ns.lower()
        for pattern, name in NS_PROVIDERS:
            if pattern in ns_lower:
                return name
    return ns_records[0].rstrip(".") if ns_records else "Unknown"


def guess_email_provider(mx_records: list[str]) -> str:
    """Map MX records to a known email provider name."""
    for mx in mx_records:
        mx_lower = mx.lower()
        for pattern, name in MX_PROVIDERS:
            if pattern in mx_lower:
                return name
    # Fall back to the hostname of the first MX record (strip priority prefix)
    if mx_records:
        parts = mx_records[0].rstrip(".").split()
        return parts[-1] if len(parts) > 1 else parts[0]
    return "—"


def guess_web_host(a_records: list[str]) -> str:
    """PTR (reverse DNS) lookup on the first A record to identify the web host."""
    if not a_records:
        return "—"
    ip = a_records[0]
    try:
        rev = dns.reversename.from_address(ip)
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 5
        ptr = resolver.resolve(rev, "PTR")
        hostname = str(ptr[0]).rstrip(".")
        return f"{hostname} ({ip})"
    except Exception:
        return ip


# ---------------------------------------------------------------------------
# HTTP redirect detection
# ---------------------------------------------------------------------------

def check_http_redirects(domain: str) -> dict:
    """
    Returns:
      http_to_https: True | False | None (None = could not connect)
      www_redirect:  "src → dst (code)" string, or None
    """
    result: dict = {"http_to_https": None, "www_redirect": None}

    # HTTP → HTTPS on apex
    try:
        r = requests.head(f"http://{domain}", timeout=8, allow_redirects=False)
        loc = r.headers.get("Location", "")
        result["http_to_https"] = (
            r.status_code in REDIRECT_CODES and loc.startswith("https://")
        )
    except Exception:
        pass

    # apex → www or www → apex (try both directions)
    for src, dst in [(domain, f"www.{domain}"), (f"www.{domain}", domain)]:
        try:
            r = requests.head(f"https://{src}", timeout=8, allow_redirects=False)
            loc = r.headers.get("Location", "")
            if r.status_code in REDIRECT_CODES and dst in loc:
                result["www_redirect"] = f"{src} → {dst} ({r.status_code})"
                break
        except Exception:
            continue

    return result


# ---------------------------------------------------------------------------
# Email security
# ---------------------------------------------------------------------------

def get_spf(txt_records: list[str]) -> str | None:
    """Extract SPF record from TXT records (already queried)."""
    for r in txt_records:
        v = r.strip('"').replace('" "', '')
        if v.startswith("v=spf1"):
            return v
    return None


def get_dmarc(domain: str) -> str | None:
    """Query _dmarc.<domain> for a DMARC policy."""
    for r in query_record(f"_dmarc.{domain}", "TXT"):
        v = r.strip('"').replace('" "', '')
        if v.startswith("v=DMARC1"):
            return v
    return None


def get_dkim(domain: str) -> list[tuple[str, str]]:
    """
    Try common DKIM selectors. Returns list of (selector, record_value) for
    each selector that resolves.
    """
    found = []
    for selector in DKIM_SELECTORS:
        for r in query_record(f"{selector}._domainkey.{domain}", "TXT"):
            v = r.strip('"').replace('" "', '')
            if "v=DKIM1" in v or "p=" in v:
                found.append((selector, v))
                break
    return found


# ---------------------------------------------------------------------------
# WHOIS
# ---------------------------------------------------------------------------

def _first(value):
    """WHOIS fields are sometimes a list, sometimes scalar — normalize to scalar."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


def get_whois_info(domain: str) -> dict:
    """
    Return a dict of WHOIS fields. Any field may be None if WHOIS didn't
    return it or parsing failed.

    Keys: registrar, registrant_org, created, updated, expires, status,
          dnssec, nameservers
    """
    out: dict = {
        "registrar": None, "registrant_org": None,
        "created": None, "updated": None, "expires": None,
        "status": [], "dnssec": None, "nameservers": [],
    }
    try:
        w = whois_lib.whois(domain)
        out["registrar"]       = _first(w.registrar)
        out["registrant_org"]  = _first(w.org)
        out["created"]         = _first(w.creation_date)
        out["updated"]         = _first(w.updated_date)
        out["expires"]         = _first(w.expiration_date)
        out["dnssec"]          = _first(w.dnssec)
        status = w.status if isinstance(w.status, list) else ([w.status] if w.status else [])
        # Some registrars return both `…icann.org/epp#…` and `…www.icann.org/epp#…` variants —
        # dedupe by the EPP code (first whitespace-separated token).
        seen: set[str] = set()
        deduped: list[str] = []
        for s in status:
            if not s:
                continue
            code = s.split()[0].lower()
            if code in seen:
                continue
            seen.add(code)
            deduped.append(s)
        out["status"] = deduped
        ns = w.name_servers if isinstance(w.name_servers, list) else ([w.name_servers] if w.name_servers else [])
        out["nameservers"] = sorted({n.lower().rstrip(".") for n in ns if n})
    except Exception:
        pass
    return out


# ---------------------------------------------------------------------------
# TLS certificate
# ---------------------------------------------------------------------------

def get_cert_info(host: str, port: int = 443) -> dict | None:
    """
    Open a TLS connection to host:port and return certificate metadata.
    Uses an unverified handshake + DER parsing so we can still inspect
    expired, self-signed, or hostname-mismatched certs.

    Returns None on any failure (no DNS, no listener, handshake error, etc.).

    Keys: subject_cn, sans, issuer_org, issuer_cn, not_before, not_after,
          is_lets_encrypt
    """
    import socket
    import ssl
    from cryptography import x509
    from cryptography.x509.oid import NameOID, ExtensionOID

    try:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=8) as raw:
            with ctx.wrap_socket(raw, server_hostname=host) as tls:
                der = tls.getpeercert(binary_form=True)
        if not der:
            return None
        cert = x509.load_der_x509_certificate(der)
    except Exception:
        return None

    def _first_attr(name, oid):
        attrs = name.get_attributes_for_oid(oid)
        return attrs[0].value if attrs else None

    subject_cn = _first_attr(cert.subject, NameOID.COMMON_NAME)
    issuer_cn  = _first_attr(cert.issuer,  NameOID.COMMON_NAME)
    issuer_org = _first_attr(cert.issuer,  NameOID.ORGANIZATION_NAME)

    sans: list[str] = []
    try:
        ext = cert.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME)
        sans = ext.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        pass

    is_le = bool(
        (issuer_org and "let's encrypt" in issuer_org.lower())
        or (issuer_cn and "let's encrypt" in issuer_cn.lower())
    )

    return {
        "subject_cn":      subject_cn,
        "sans":            sans,
        "issuer_org":      issuer_org,
        "issuer_cn":       issuer_cn,
        "not_before":      cert.not_valid_before_utc.replace(tzinfo=None),
        "not_after":       cert.not_valid_after_utc.replace(tzinfo=None),
        "is_lets_encrypt": is_le,
    }


def pick_cert(domain: str) -> dict | None:
    """Return cert info for apex if available, otherwise www.<domain>, else None."""
    for host in (domain, f"www.{domain}"):
        info = get_cert_info(host)
        if info:
            info["host"] = host
            return info
    return None


# ---------------------------------------------------------------------------
# ICS calendar
# ---------------------------------------------------------------------------

def _vevent(kind: str, customer_name: str, domain: str, when: datetime, alarms: list[int]) -> list[str]:
    """
    Build a single VEVENT block. `kind` is "Domain renewal" or "TLS cert renewal".
    `alarms` is a list of days-before-event for DISPLAY alarms.
    """
    dtstart = when.strftime("%Y%m%d")
    dtend   = (when + timedelta(days=1)).strftime("%Y%m%d")
    slug    = "domain" if kind.startswith("Domain") else "cert"
    uid     = f"dns-audit-{slug}-{domain}-{dtstart}@dns-audit"
    desc    = (
        f"{kind}\\n"
        f"Domain: {domain}\\n"
        f"Customer: {customer_name}\\n"
        f"Expires: {when.strftime('%Y-%m-%d')}"
    )
    block = [
        "BEGIN:VEVENT",
        f"UID:{uid}",
        f"DTSTART;VALUE=DATE:{dtstart}",
        f"DTEND;VALUE=DATE:{dtend}",
        f"SUMMARY:{kind}: {domain}",
        f"DESCRIPTION:{desc}",
    ]
    for days in alarms:
        block += [
            "BEGIN:VALARM",
            f"TRIGGER:-P{days}D",
            "ACTION:DISPLAY",
            f"DESCRIPTION:{days}-day reminder ({kind.lower()}): {domain}",
            "END:VALARM",
        ]
    block.append("END:VEVENT")
    return block


def write_ics(
    domain_expiries: list[tuple[str, str, datetime]],
    cert_expiries: list[tuple[str, str, datetime]],
    output_path: Path,
) -> None:
    """
    Write a single .ics file with VEVENTs for both domain renewals and
    non-auto-renewing TLS cert expiries.

    domain_expiries: list of (customer_name, domain, expiry_datetime) — 60/30/15/1-day alarms
    cert_expiries:   list of (customer_name, domain, not_after)       — 30/15/1-day alarms
    """
    lines = [
        "BEGIN:VCALENDAR",
        "VERSION:2.0",
        "PRODID:-//dns-audit//EN",
        "CALSCALE:GREGORIAN",
        "X-WR-CALNAME:Domain & TLS Renewal Reminders",
    ]
    for customer_name, domain, expiry in domain_expiries:
        lines += _vevent("Domain renewal", customer_name, domain, expiry, [60, 30, 15, 1])
    for customer_name, domain, not_after in cert_expiries:
        lines += _vevent("TLS cert renewal", customer_name, domain, not_after, [30, 15, 1])
    lines.append("END:VCALENDAR")
    output_path.write_text("\r\n".join(lines) + "\r\n", encoding="utf-8")


# ---------------------------------------------------------------------------
# Markdown generation
# ---------------------------------------------------------------------------

def compute_risk_flags(
    records: dict[str, list[str]],
    email_sec: dict | None,
    whois_info: dict | None,
    cert: dict | None,
) -> list[str]:
    """Return a list of human-readable risk flags. Empty list = clean."""
    flags: list[str] = []
    today = date.today()

    # Domain expiry < 60 days
    if whois_info and whois_info.get("expires"):
        exp = whois_info["expires"]
        if isinstance(exp, datetime):
            days = (exp.date() - today).days
            if days < 60:
                flags.append(f"Domain expires in {days} days ({exp.strftime('%Y-%m-%d')})")

    # Cert expiry < 30 days (skip Let's Encrypt — auto-renews)
    if cert and cert.get("not_after") and not cert.get("is_lets_encrypt"):
        days = (cert["not_after"].date() - today).days
        if days < 30:
            flags.append(f"TLS cert expires in {days} days ({cert['not_after'].strftime('%Y-%m-%d')})")

    # Transfer lock missing
    if whois_info:
        status = " ".join(whois_info.get("status") or []).lower()
        if status and "clienttransferprohibited" not in status:
            flags.append("No clientTransferProhibited status (transfer lock missing)")

    # DNSSEC
    if whois_info:
        dnssec = (whois_info.get("dnssec") or "")
        if isinstance(dnssec, str) and dnssec.lower() in ("", "unsigned", "no"):
            flags.append("DNSSEC not enabled")

    # Email security
    if email_sec:
        if not email_sec.get("spf"):
            flags.append("No SPF record")
        dmarc = email_sec.get("dmarc") or ""
        if not dmarc:
            flags.append("No DMARC record")
        elif "p=none" in dmarc.lower():
            flags.append("DMARC policy is p=none (monitoring only)")

    # CAA
    if not records.get("CAA"):
        flags.append("No CAA records (any CA may issue certificates)")

    return flags


def build_markdown(
    customer_name: str,
    domain: str,
    notes: str,
    records: dict[str, list[str]],
    subdomains: list[str],
    hosting: dict | None = None,
    email_sec: dict | None = None,
    redirects: dict | None = None,
    whois_info: dict | None = None,
    cert: dict | None = None,
) -> str:
    today = date.today().strftime("%Y-%m-%d")
    lines: list[str] = []

    expires = whois_info.get("expires") if whois_info else None

    # --- Header ---
    lines += [
        f"# {domain}",
        "",
        f"**Customer:** {customer_name}  ",
        f"**Last updated:** {today}  ",
    ]
    if isinstance(expires, datetime):
        days = (expires.date() - date.today()).days
        lines.append(f"**Domain expires:** {expires.strftime('%Y-%m-%d')} ({days} days)  ")
    if notes:
        lines.append(f"**Notes:** {notes}  ")
    lines.append("")

    # --- Risk Flags ---
    flags = compute_risk_flags(records, email_sec, whois_info, cert)
    if flags:
        lines += ["## Risk Flags", ""]
        for f in flags:
            lines.append(f"- ⚠ {f}")
        lines.append("")

    # --- Registration (WHOIS) ---
    if whois_info and any(whois_info.get(k) for k in ("registrar", "registrant_org", "created", "updated", "expires", "status", "dnssec")):
        lines += ["## Registration", ""]
        if whois_info.get("registrar"):
            lines.append(f"**Registrar:** {whois_info['registrar']}  ")
        if whois_info.get("registrant_org"):
            lines.append(f"**Registrant org:** {whois_info['registrant_org']}  ")
        for label, key in [("Created", "created"), ("Updated", "updated"), ("Expires", "expires")]:
            v = whois_info.get(key)
            if isinstance(v, datetime):
                lines.append(f"**{label}:** {v.strftime('%Y-%m-%d')}  ")
        if whois_info.get("dnssec"):
            lines.append(f"**DNSSEC:** {whois_info['dnssec']}  ")
        if whois_info.get("status"):
            status_list = whois_info["status"]
            if len(status_list) == 1:
                lines.append(f"**Status:** {status_list[0]}  ")
            else:
                lines.append("**Status:**  ")
                for s in status_list:
                    lines.append(f"- {s}")
        lines.append("")

    # --- TLS Certificate ---
    if cert:
        lines += ["## TLS Certificate", ""]
        lines.append(f"**Checked host:** {cert.get('host', domain)}  ")
        if cert.get("subject_cn"):
            lines.append(f"**Subject CN:** {cert['subject_cn']}  ")
        issuer = cert.get("issuer_org") or cert.get("issuer_cn") or "—"
        le_tag = " (auto-renew)" if cert.get("is_lets_encrypt") else ""
        lines.append(f"**Issuer:** {issuer}{le_tag}  ")
        nb, na = cert.get("not_before"), cert.get("not_after")
        if isinstance(nb, datetime):
            lines.append(f"**Not before:** {nb.strftime('%Y-%m-%d')}  ")
        if isinstance(na, datetime):
            days = (na.date() - date.today()).days
            lines.append(f"**Not after:** {na.strftime('%Y-%m-%d')} ({days} days)  ")
        sans = cert.get("sans") or []
        if sans:
            shown = sans[:10]
            extra = f" (+{len(sans) - 10} more)" if len(sans) > 10 else ""
            lines.append(f"**SANs:** {', '.join(shown)}{extra}  ")
        lines.append("")

    # --- Hosting ---
    if hosting:
        lines += [
            "## Hosting",
            "",
            f"**DNS provider:** {hosting['dns_host']}  ",
            f"**Web host:** {hosting['web_host']}  ",
            f"**Email provider:** {hosting['email_host']}  ",
            "",
        ]

    # --- HTTP Redirects ---
    if redirects:
        lines += ["## HTTP Redirects", ""]
        http_https = redirects.get("http_to_https")
        if http_https is True:
            lines.append("**HTTP → HTTPS:** Yes  ")
        elif http_https is False:
            lines.append("**HTTP → HTTPS:** No  ")
        else:
            lines.append("**HTTP → HTTPS:** (could not check)  ")
        www = redirects.get("www_redirect")
        lines.append(f"**www redirect:** {www if www else 'None detected'}  ")
        lines.append("")

    # --- Email Security ---
    if email_sec:
        lines += ["## Email Security", ""]

        spf = email_sec.get("spf")
        dmarc = email_sec.get("dmarc")
        dkim_hits: list[tuple[str, str]] = email_sec.get("dkim", [])

        if spf:
            lines += ["**SPF:** ✓  ", "```", spf, "```", ""]
        else:
            lines += ["**SPF:** ✗ (none found)  ", ""]

        if dmarc:
            lines += ["**DMARC:** ✓  ", "```", dmarc, "```", ""]
        else:
            lines += ["**DMARC:** ✗ (none found)  ", ""]

        if dkim_hits:
            selectors = ", ".join(s for s, _ in dkim_hits)
            lines += [f"**DKIM:** ✓ (selectors: {selectors})  ", "```"]
            for selector, value in dkim_hits:
                lines += [f"{selector}._domainkey", f"  {value}"]
            lines += ["```", ""]
        else:
            lines += ["**DKIM:** ? (no common selectors matched)  ", ""]

    # --- DNS Records ---
    lines += ["## DNS Records", ""]

    any_records = False
    for rtype in RECORD_TYPES:
        values = records.get(rtype, [])
        if not values:
            continue
        any_records = True

        ttl = get_ttl(domain, rtype)

        lines += [f"### {rtype}  (TTL: {ttl})", "", "```"]
        # Strip surrounding quotes and join multi-chunk strings (dnspython renders
        # long TXT records as "chunk1" "chunk2"; we want them as one clean string)
        lines += [v.strip('"').replace('" "', '') if rtype == "TXT" else v for v in values]
        lines += ["```", ""]

    if not any_records:
        lines += ["_No standard DNS records found._", ""]

    # --- Subdomains ---
    lines += ["## Subdomains (via crt.sh)", ""]

    if subdomains:
        lines.append("```")
        for sub in subdomains:
            a     = ", ".join(query_record(sub, "A"))     or "—"
            aaaa  = ", ".join(query_record(sub, "AAAA"))  or "—"
            cname = ", ".join(query_record(sub, "CNAME")) or "—"
            lines += [sub, f"  A:     {a}", f"  AAAA:  {aaaa}", f"  CNAME: {cname}", ""]
        lines += ["```", ""]
    else:
        lines += ["_None found in certificate transparency logs._", ""]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 1Password sync
# ---------------------------------------------------------------------------

def op_item_exists(title: str, vault: str) -> bool:
    result = subprocess.run(
        ["op", "item", "get", title, "--vault", vault, "--format", "json"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def op_upsert_note(title: str, vault: str, content: str) -> bool:
    if op_item_exists(title, vault):
        result = subprocess.run(
            ["op", "item", "edit", title, "--vault", vault, f"notesPlain={content}"],
            capture_output=True,
            text=True,
        )
        action = "Updated"
    else:
        result = subprocess.run(
            ["op", "item", "create",
             "--category", "Secure Note",
             "--title", title,
             "--vault", vault,
             f"notesPlain={content}"],
            capture_output=True,
            text=True,
        )
        action = "Created"

    if result.returncode == 0:
        print(f"    1Password: {action} note '{title}' in vault '{vault}'")
        return True
    else:
        print(f"    [warn] 1Password sync failed for '{title}': {result.stderr.strip()}")
        return False


def check_op_cli() -> bool:
    result = subprocess.run(["op", "whoami"], capture_output=True, text=True)
    if result.returncode != 0:
        print("Error: 1Password CLI not signed in.")
        print("Run `op signin` and try again.")
        return False
    return True


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="DNS audit tool")
    parser.add_argument(
        "--op-sync",
        action="store_true",
        help="Push DNS notes to 1Password as Secure Notes (requires op CLI)",
    )
    parser.add_argument(
        "--archive",
        action="store_true",
        help="Copy the existing dns_records/ to dns_records_YYYY-MM-DD/ before overwriting",
    )
    args = parser.parse_args()

    if args.op_sync and not check_op_cli():
        sys.exit(1)

    customers_file = Path("customers.csv")
    if not customers_file.exists():
        print("Error: customers.csv not found.")
        print("Columns required: customer_name, domain, vault, notes")
        sys.exit(1)

    # Archive existing output before overwriting
    if args.archive and OUTPUT_DIR.exists():
        run_date_file = OUTPUT_DIR / ".run_date"
        if run_date_file.exists():
            import shutil
            run_stamp = run_date_file.read_text().strip()
            archive_path = Path(f"{OUTPUT_DIR}_{run_stamp}")
            shutil.copytree(OUTPUT_DIR, archive_path)
            print(f"✓ Archived previous output → {archive_path}/\n")

    OUTPUT_DIR.mkdir(exist_ok=True)

    with open(customers_file, newline="", encoding="utf-8") as f:
        customers = list(csv.DictReader(f))

    print(f"Found {len(customers)} customer(s) in customers.csv\n")

    if not HAS_WHOIS:
        print("[warn] python-whois not installed — domain expiry dates will be skipped.")
        print("       Run: pip install python-whois\n")

    domain_expiries: list[tuple[str, str, datetime]] = []
    cert_expiries:   list[tuple[str, str, datetime]] = []

    for row in customers:
        customer_name = row.get("customer_name", "Unknown").strip()
        domain        = row.get("domain", "").strip().lower()
        vault         = row.get("vault", "").strip()
        notes         = row.get("notes", "").strip()

        if not domain:
            print(f"  [skip] Empty domain for customer '{customer_name}'")
            continue

        if args.op_sync and not vault:
            print(f"  [skip] No vault specified for {domain} — skipping 1Password sync")

        print(f"→ {domain}  ({customer_name})")

        # DNS records
        records: dict[str, list[str]] = {}
        for rtype in RECORD_TYPES:
            records[rtype] = query_record(domain, rtype)
            if records[rtype]:
                print(f"    {rtype}: {len(records[rtype])} record(s)")

        # Hosting
        dns_host   = guess_dns_host(records.get("NS", []))
        web_host   = guess_web_host(records.get("A", []))
        email_host = guess_email_provider(records.get("MX", []))
        hosting = {"dns_host": dns_host, "web_host": web_host, "email_host": email_host}
        print(f"  DNS host: {dns_host}  |  Web host: {web_host}  |  Email: {email_host}")

        # HTTP redirects
        print("  Checking HTTP redirects…", end=" ", flush=True)
        redirects = check_http_redirects(domain)
        http_https_str = {True: "HTTP→HTTPS ✓", False: "HTTP→HTTPS ✗", None: "HTTP→HTTPS ?"}[redirects["http_to_https"]]
        www_str = redirects["www_redirect"] or "no www redirect"
        print(f"{http_https_str}  |  {www_str}")

        # Email security
        print("  Checking email security…", end=" ", flush=True)
        spf       = get_spf(records.get("TXT", []))
        dmarc     = get_dmarc(domain)
        dkim_hits = get_dkim(domain)
        email_sec = {"spf": spf, "dmarc": dmarc, "dkim": dkim_hits}
        print(
            f"SPF={'✓' if spf else '✗'}  "
            f"DMARC={'✓' if dmarc else '✗'}  "
            f"DKIM={'✓ (' + ', '.join(s for s, _ in dkim_hits) + ')' if dkim_hits else '?'}"
        )

        # WHOIS
        whois_info: dict | None = None
        if HAS_WHOIS:
            print("  Checking WHOIS…", end=" ", flush=True)
            whois_info = get_whois_info(domain)
            exp = whois_info.get("expires")
            if isinstance(exp, datetime):
                days = (exp.date() - date.today()).days
                reg = whois_info.get("registrar") or "?"
                print(f"{reg}, expires {exp.strftime('%Y-%m-%d')} ({days} days)")
                domain_expiries.append((customer_name, domain, exp))
            else:
                print(whois_info.get("registrar") or "no data")

        # TLS certificate
        print("  Checking TLS cert…", end=" ", flush=True)
        cert = pick_cert(domain)
        if cert and cert.get("not_after"):
            na = cert["not_after"]
            days = (na.date() - date.today()).days
            issuer = cert.get("issuer_org") or cert.get("issuer_cn") or "unknown"
            le = " (LE auto-renew)" if cert.get("is_lets_encrypt") else ""
            print(f"{issuer}, expires {na.strftime('%Y-%m-%d')} ({days} days){le}")
            if not cert.get("is_lets_encrypt"):
                cert_expiries.append((customer_name, domain, na))
        else:
            print("not reachable")

        # Subdomains
        print("  Checking crt.sh for subdomains…", end=" ", flush=True)
        subdomains = get_subdomains_crtsh(domain)
        print(f"{len(subdomains)} found")

        # Build and write markdown
        md = build_markdown(
            customer_name, domain, notes, records, subdomains,
            hosting=hosting, email_sec=email_sec, redirects=redirects,
            whois_info=whois_info, cert=cert,
        )
        safe_name = domain.replace(".", "_")
        out_path = OUTPUT_DIR / f"{safe_name}.md"
        out_path.write_text(md, encoding="utf-8")
        print(f"  ✓ Saved → {out_path}")

        if args.op_sync and vault:
            op_upsert_note(op_note_title(domain), vault, md)

        print()
        time.sleep(1.5)

    # Write renewal calendar
    if domain_expiries or cert_expiries:
        ics_path = OUTPUT_DIR / "dns_renewals.ics"
        write_ics(domain_expiries, cert_expiries, ics_path)
        print(
            f"✓ Renewal calendar → {ics_path}  "
            f"({len(domain_expiries)} domain, {len(cert_expiries)} cert event(s))"
        )

    (OUTPUT_DIR / ".run_date").write_text(datetime.now().strftime("%Y-%m-%d_%H-%M-%S"))
    print(f"\nDone. Markdown files written to ./{OUTPUT_DIR}/")
    if args.op_sync:
        print("1Password notes created/updated where vault was specified.")


if __name__ == "__main__":
    main()
