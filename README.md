# DNS Audit Tool

A lightweight script for managed service providers and consultants who need to periodically snapshot DNS records across a portfolio of client domains.

For each domain it:

- Queries all standard DNS record types (A, AAAA, MX, TXT, CNAME, NS, SOA, SRV, CAA)
- Identifies the DNS provider (from nameservers) and web host (from reverse DNS)
- Checks HTTP→HTTPS redirect behavior and apex/www redirect
- Checks email security: SPF, DMARC, and DKIM (common selectors)
- Looks up domain expiry via WHOIS
- Discovers subdomains via Certificate Transparency logs (crt.sh) and a common-name wordlist probe
- Resolves A, AAAA, and CNAME for each subdomain
- Writes one Markdown file per domain to `./dns_records/`
- Writes a `dns_renewals.ics` calendar file with 60- and 30-day renewal alarms
- Optionally creates or updates a Secure Note in 1Password via the `op` CLI

---

## Requirements

- Python 3.10+
- `dnspython`, `requests`, and `python-whois` (`pip install dnspython requests python-whois`)
- (Optional) [1Password CLI](https://developer.1password.com/docs/cli/) for `--op-sync`

---

## Setup

Do this once when you first clone the repo:

```bash
# Create a virtualenv and install dependencies
python3 -m venv .venv
source .venv/bin/activate
pip install dnspython requests python-whois

# Copy the example and fill in your domains
cp customers.example.csv customers.csv
```

---

## Usage

Each session, activate the virtualenv before running the script (no need to reinstall dependencies):

```bash
source .venv/bin/activate
```

If you're using `--op-sync`, sign in to 1Password first:

```bash
op signin
```

Then run the script:

```bash
# Write .md files only
python dns_fetch.py

# Write .md files AND push to 1Password
python dns_fetch.py --op-sync

# Archive the previous run's output before overwriting
python dns_fetch.py --archive

# All three together
python dns_fetch.py --archive --op-sync
```

Output files are written to `./dns_records/<domain>.md`. A single `dns_records/dns_renewals.ics` calendar file is also written containing renewal reminders for every domain where expiry was found, with 60- and 30-day alarms.

When `--op-sync` is used, a Secure Note named `DNS: <domain>` is created or updated in the 1Password vault specified in `customers.csv`. Requires `op` to be installed and signed in (`op whoami` should return your account).

---

## customers.csv

`customers.csv` is not included in this repo. Create one based on `customers.example.csv`:

| Column | Required | Description |
|--------|----------|-------------|
| `customer_name` | Yes | Display name for the customer |
| `domain` | Yes | Apex domain to audit (e.g. `example.com`) |
| `vault` | No* | 1Password vault to write the Secure Note into. Must match the vault name exactly. Required if using `--op-sync`. |
| `notes` | No | Free-form notes (e.g. "Redirects to main domain"). Included in the output `.md` file and in the 1Password note if `--op-sync` is used. |

Multiple rows for the same customer/vault are fine (e.g. if they have more than one domain).

---

## Output format

Each `dns_records/<domain>.md` file looks like:

~~~
# example.com

**Customer:** Acme Corp
**Last updated:** 2026-02-27
**Domain expires:** 2027-03-15 (382 days)

## Hosting

**DNS provider:** Cloudflare
**Web host:** cloudflare.net (93.184.216.34)
**Email provider:** Google Workspace

## HTTP Redirects

**HTTP → HTTPS:** Yes
**www redirect:** example.com → www.example.com (301)

## Email Security

**SPF:** ✓
```
v=spf1 include:_spf.google.com ~all
```

**DMARC:** ✓
```
v=DMARC1; p=reject; rua=mailto:dmarc@example.com
```

**DKIM:** ✓ (selectors: google)
```
google._domainkey
  v=DKIM1; k=rsa; p=MIGfMA0G...
```

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
~~~

---

## Tips

- **Re-run safely**: the script overwrites existing output files, so it's safe to run as often as you like.
- **Snapshots**: pass `--archive` to save a copy of the previous results before overwriting them. The archive folder is named after the date of the previous run (e.g. `dns_records_2026-01-15/`), so your snapshots stay organized by when the data was captured. If you run `--archive` twice in the same day, the second run will skip the copy since the archive already exists.
- **Rate limiting**: the script waits 1.5 seconds between crt.sh lookups. For large portfolios this adds up but keeps the requests polite.
- **1Password vault names** must match exactly — run `op vault list` to check.

---

## Limitations

- Subdomain discovery combines crt.sh (certificate transparency) with a wordlist probe of ~20 common names (`www`, `mail`, `api`, etc.). Subdomains outside both sources won't appear. Domains using wildcard DNS (e.g. Cloudflare proxying all subdomains) are detected and wordlist false-positives are suppressed.
- Zone transfers (AXFR) are not attempted — public resolvers almost never allow them.
- TTLs shown are live at query time and may reflect upstream caching.
