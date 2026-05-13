# DNS Audit Tool

A lightweight script for managed service providers and consultants who need to periodically snapshot DNS records across a portfolio of client domains.

For each domain it:

- Queries standard DNS record types (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, CAA)
- Identifies the DNS provider (from nameservers), web host (from reverse DNS), and email provider (from MX)
- Pulls registrar, registrant, created/updated/expires dates, status codes, and DNSSEC flag from WHOIS
- Inspects the live TLS certificate on the apex (falling back to `www.`) for issuer, validity dates, and SANs
- Checks HTTP→HTTPS redirect behavior and apex/www redirect
- Checks email security: SPF, DMARC, and DKIM (common selectors)
- Discovers subdomains via Certificate Transparency logs (crt.sh) plus a 19-name wordlist probe, with wildcard-DNS detection to suppress false positives
- Surfaces risk flags at the top of each report (imminent expiries, missing transfer lock, no DNSSEC/SPF/DMARC/CAA, etc.)
- Writes one Markdown file per domain to `./dns_records/`
- Writes a `dns_records/dns_renewals.ics` calendar with renewal alarms for domain registrations (60/30/15/1-day) and non-auto-renewing TLS certs (30/15/1-day; Let's Encrypt certs are skipped since they auto-renew)
- Optionally creates or updates a Secure Note in 1Password via the `op` CLI

See [sample-output.md](sample-output.md) for a real example (output from `apple.com`).

---

## Requirements

- Python 3.10+
- (Optional) [1Password CLI](https://developer.1password.com/docs/cli/) for `--op-sync`

---

## Setup

Do this once when you first clone the repo:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install dnspython requests python-whois cryptography

cp customers.example.csv customers.csv  # then edit to add your domains
```

`customers.csv` is gitignored. Columns:

| Column | Required | Description |
|--------|----------|-------------|
| `customer_name` | Yes | Display name for the customer |
| `domain` | Yes | Apex domain to audit (e.g. `example.com`) |
| `vault` | If using `--op-sync` | 1Password vault to write the Secure Note into. Must match the vault name exactly — run `op vault list` to check. |
| `notes` | No | Free-form notes (included in the output `.md` and 1Password note) |

Multiple rows per customer are fine (e.g. a client with several domains).

---

## Usage

Activate the virtualenv each session:

```bash
source .venv/bin/activate
```

If you're using `--op-sync`, also sign in to 1Password (`op signin`).

```bash
python dns_fetch.py                       # write .md files only
python dns_fetch.py --op-sync             # also push to 1Password
python dns_fetch.py --archive             # snapshot previous run first
python dns_fetch.py --archive --op-sync   # all three together
```

Output goes to `./dns_records/<domain>.md`, with `dns_renewals.ics` written alongside for any domains that had a discoverable expiry date. Re-runs overwrite, so the script is safe to run as often as you like. The script sleeps 1.5s between domains to be polite to crt.sh.

`--archive` copies the existing `dns_records/` to `dns_records_<timestamp>/` (e.g. `dns_records_2026-05-13_10-30-45/`) using the timestamp recorded at the end of the previous run, so snapshots are labelled by when their data was captured. The archive will fail if the destination directory already exists — delete or rename it first if you need to re-archive.

With `--op-sync`, a Secure Note named `DNS: <domain>` is created or updated in the vault from `customers.csv`. Rows with no vault are skipped for sync but still get a `.md` file.

---

## Possible future improvements

- **Recursive SPF expansion.** Walk `include:` / `redirect=` chains to produce a flat list of authorized sending IPs and a DNS-lookup count. Would catch hitting the 10-lookup limit (which silently breaks deliverability) and would make SPF drift visible across archived runs (e.g. a new SendGrid include appearing without warning). Costs: more DNS queries per domain and a much longer SPF section. Worth doing if email-spoofing posture becomes a focus.
