# DNS Audit Tool

A lightweight script for managed service providers and consultants who need to periodically snapshot DNS records across a portfolio of client domains.

For each domain it:

- Queries all standard DNS record types (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, CAA)
- Discovers subdomains via Certificate Transparency logs (crt.sh)
- Resolves A, AAAA, and CNAME for each subdomain
- Writes one Markdown file per domain to `./dns_records/`
- Optionally creates or updates a Secure Note in 1Password via the `op` CLI

---

## Requirements

- Python 3.10+
- `dnspython` and `requests` (`pip install dnspython requests`)
- (Optional) [1Password CLI](https://developer.1password.com/docs/cli/) for `--op-sync`

---

## Setup

```bash
# Create a virtualenv and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install dnspython requests

# Copy the example and fill in your domains
cp customers.example.csv customers.csv
```

---

## Usage

```bash
# Write .md files only
python dns_fetch.py

# Write .md files AND push to 1Password
python dns_fetch.py --op-sync
```

Output files are written to `./dns_records/<domain>.md`.

When `--op-sync` is used, a Secure Note named `DNS: <domain>` is created or updated in the 1Password vault specified in `customers.csv`. Requires `op` to be installed and signed in (`op whoami` should return your account).

---

## customers.csv

`customers.csv` is not included in this repo (it contains client data). Create one based on `customers.example.csv`:

| Column | Required | Description |
|--------|----------|-------------|
| `customer_name` | Yes | Display name for the customer |
| `domain` | Yes | Apex domain to audit (e.g. `example.com`) |
| `op_reference` | No | Name of the 1Password login item for this client's DNS admin account — shown in the output as a cross-reference only |
| `vault` | No* | 1Password vault to write the Secure Note into. Must match the vault name exactly. Required if using `--op-sync`. |
| `notes` | No | Free-form notes shown in the output file |

Multiple rows for the same customer are fine (e.g. if they have more than one domain).

---

## Output format

Each `dns_records/<domain>.md` file looks like:

```
# example.com

**Customer:** Acme Corp
**Last updated:** 2026-02-27
**1Password login item:** `Acme DNS Admin`

## DNS Records

### A  (TTL: 300)
```
93.184.216.34
```

### MX  (TTL: 3600)
```
10 mail.example.com.
```

## Subdomains (via crt.sh)

```
mail.example.com
  A:     93.184.216.34
  AAAA:  —
  CNAME: —
```
```

---

## Tips

- **Re-run safely**: the script overwrites existing output files, so it's safe to run as often as you like.
- **Quarterly snapshots**: before each run, copy `dns_records/` somewhere dated (e.g. `dns_records_2026-Q1/`) to keep a history.
- **Rate limiting**: the script waits 1.5 seconds between crt.sh lookups. For large portfolios this adds up but keeps the requests polite.
- **1Password vault names** must match exactly — run `op vault list` to check.

---

## Limitations

- Subdomain discovery only finds names that have had a TLS certificate issued. Subdomains that have never had a cert won't appear.
- Zone transfers (AXFR) are not attempted — public resolvers almost never allow them.
- TTLs shown are live at query time and may reflect upstream caching.
