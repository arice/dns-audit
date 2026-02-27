#!/usr/bin/env python3
"""
dns_fetch.py — Quarterly DNS audit tool

Reads a list of customers/domains from customers.csv and writes one
Markdown file per domain into the ./dns_records/ output directory.

Optionally syncs each DNS note to 1Password as a Secure Note using the
1Password CLI (requires `op` to be installed and signed in).

Usage:
    python dns_fetch.py              # write .md files only
    python dns_fetch.py --op-sync   # write .md files AND push to 1Password

Requirements:
    pip install dnspython requests
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
from datetime import date
from pathlib import Path


# Record types to query for every domain
RECORD_TYPES = ["A", "AAAA", "MX", "TXT", "CNAME", "NS", "SOA", "SRV", "CAA"]

# Output directory for .md files
OUTPUT_DIR = Path("dns_records")

# Naming convention for 1Password Secure Notes
def op_note_title(domain: str) -> str:
    return f"DNS: {domain}"


# ---------------------------------------------------------------------------
# DNS helpers
# ---------------------------------------------------------------------------

def query_record(domain: str, rtype: str) -> list[str]:
    """Return a list of string-formatted answers, or [] on any failure."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.lifetime = 8  # seconds
        answers = resolver.resolve(domain, rtype)
        return [rdata.to_text() for rdata in answers]
    except (
        dns.resolver.NXDOMAIN,
        dns.resolver.NoAnswer,
        dns.resolver.NoNameservers,
        dns.exception.Timeout,
        dns.exception.DNSException,
    ):
        return []


def get_subdomains_crtsh(domain: str) -> list[str]:
    """
    Fetch subdomains from Certificate Transparency logs via crt.sh.
    Returns a sorted, deduplicated list of subdomains (excluding the apex).
    """
    try:
        url = f"https://crt.sh/?q=%.{domain}&output=json"
        resp = requests.get(url, timeout=30)
        if resp.status_code != 200:
            return []
        entries = resp.json()
        subdomains: set[str] = set()
        for entry in entries:
            for name in entry.get("name_value", "").splitlines():
                name = name.strip().lstrip("*.")
                if name.endswith(f".{domain}") and name != domain:
                    subdomains.add(name.lower())
        return sorted(subdomains)
    except Exception as exc:
        print(f"    [warn] crt.sh lookup failed for {domain}: {exc}")
        return []


# ---------------------------------------------------------------------------
# Markdown generation
# ---------------------------------------------------------------------------

def build_markdown(customer_name: str, domain: str, op_reference: str,
                   notes: str, records: dict[str, list[str]],
                   subdomains: list[str]) -> str:
    today = date.today().strftime("%Y-%m-%d")
    lines: list[str] = []

    # Header
    lines += [
        f"# {domain}",
        "",
        f"**Customer:** {customer_name}  ",
        f"**Last updated:** {today}  ",
    ]
    if op_reference:
        lines.append(f"**1Password login item:** `{op_reference}`  ")
    if notes:
        lines.append(f"**Notes:** {notes}  ")
    lines.append("")

    # --- DNS Records ---
    lines += ["## DNS Records", ""]

    any_records = False
    for rtype in RECORD_TYPES:
        values = records.get(rtype, [])
        if not values:
            continue
        any_records = True

        # Fetch TTL (one per RRset)
        try:
            resolver = dns.resolver.Resolver()
            resolver.lifetime = 8
            raw = resolver.resolve(domain, rtype)
            ttl = raw.rrset.ttl if raw.rrset else "—"
        except Exception:
            ttl = "—"

        lines.append(f"### {rtype}  (TTL: {ttl})")
        lines.append("")
        lines.append("```")
        for v in values:
            lines.append(v)
        lines.append("```")
        lines.append("")

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
            lines.append(sub)
            lines.append(f"  A:     {a}")
            lines.append(f"  AAAA:  {aaaa}")
            lines.append(f"  CNAME: {cname}")
            lines.append("")
        lines.append("```")
        lines.append("")
    else:
        lines += ["_None found in certificate transparency logs._", ""]

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# 1Password sync
# ---------------------------------------------------------------------------

def op_item_exists(title: str, vault: str) -> bool:
    """Return True if a 1Password item with this title exists in the vault."""
    result = subprocess.run(
        ["op", "item", "get", title, "--vault", vault, "--format", "json"],
        capture_output=True,
        text=True,
    )
    return result.returncode == 0


def op_upsert_note(title: str, vault: str, content: str) -> bool:
    """
    Create or update a Secure Note in 1Password.
    Returns True on success, False on failure.
    """
    if op_item_exists(title, vault):
        result = subprocess.run(
            ["op", "item", "edit", title, "--vault", vault,
             f"notesPlain={content}"],
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
    """Verify that `op` is installed and the user is signed in."""
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
    parser = argparse.ArgumentParser(description="Quarterly DNS audit tool")
    parser.add_argument(
        "--op-sync",
        action="store_true",
        help="Push DNS notes to 1Password as Secure Notes (requires op CLI)",
    )
    args = parser.parse_args()

    if args.op_sync and not check_op_cli():
        sys.exit(1)

    customers_file = Path("customers.csv")
    if not customers_file.exists():
        print("Error: customers.csv not found.")
        print("Columns required: customer_name, domain, op_reference, vault, notes")
        sys.exit(1)

    OUTPUT_DIR.mkdir(exist_ok=True)

    with open(customers_file, newline="", encoding="utf-8") as f:
        customers = list(csv.DictReader(f))

    print(f"Found {len(customers)} customer(s) in customers.csv\n")

    for row in customers:
        customer_name = row.get("customer_name", "Unknown").strip()
        domain        = row.get("domain", "").strip().lower()
        op_reference  = row.get("op_reference", "").strip()
        vault         = row.get("vault", "").strip()
        notes         = row.get("notes", "").strip()

        if not domain:
            print(f"  [skip] Empty domain for customer '{customer_name}'")
            continue

        if args.op_sync and not vault:
            print(f"  [skip] No vault specified for {domain} — skipping 1Password sync")

        print(f"→ {domain}  ({customer_name})")

        # Query all standard record types
        records: dict[str, list[str]] = {}
        for rtype in RECORD_TYPES:
            records[rtype] = query_record(domain, rtype)
            found = len(records[rtype])
            if found:
                print(f"    {rtype}: {found} record(s)")

        # Subdomain discovery
        print(f"  Checking crt.sh for subdomains…", end=" ", flush=True)
        subdomains = get_subdomains_crtsh(domain)
        print(f"{len(subdomains)} found")

        # Build markdown
        md = build_markdown(customer_name, domain, op_reference, notes,
                            records, subdomains)

        # Write .md file
        safe_name = domain.replace(".", "_")
        out_path = OUTPUT_DIR / f"{safe_name}.md"
        out_path.write_text(md, encoding="utf-8")
        print(f"  ✓ Saved → {out_path}")

        # Optionally push to 1Password
        if args.op_sync and vault:
            op_upsert_note(op_note_title(domain), vault, md)

        print()
        time.sleep(1.5)

    print(f"Done. Markdown files written to ./{OUTPUT_DIR}/")
    if args.op_sync:
        print("1Password notes created/updated where vault was specified.")


if __name__ == "__main__":
    main()
