# DNS Audit Tool

Quarterly tool that queries DNS records for all customer domains and writes one Markdown file per domain into `./dns_records/`. Optionally syncs each file to 1Password as a Secure Note via the `op` CLI.

## Environment setup

Always use the virtualenv. If it doesn't exist yet:

```bash
/opt/homebrew/bin/python3 -m venv .venv --clear
source .venv/bin/activate
pip install requests dnspython
```

To activate an existing venv:

```bash
source .venv/bin/activate
```

## Running

```bash
# DNS records to .md files only
python3 dns_fetch.py

# DNS records to .md files AND push to 1Password
python3 dns_fetch.py --op-sync
```

The `--op-sync` flag requires the 1Password CLI to be installed and signed in (`op whoami` should return your account). It creates or updates a Secure Note named `DNS: <domain>` in the vault specified in `customers.csv`.

## Files

- `dns_fetch.py` — main script
- `customers.csv` — list of customer domains to audit
- `dns_records/` — output directory, one `.md` file per domain (created on first run)
- `README.md` — full documentation

## customers.csv columns

| Column | Notes |
|--------|-------|
| `customer_name` | Display name for the customer |
| `domain` | Apex domain to audit |
| `op_reference` | Name of the 1Password login item for this client's DNS admin account (cross-reference only, not used programmatically) |
| `vault` | 1Password vault name for `--op-sync`. Must match exactly (case-sensitive). Some clients have dedicated vaults; others go in `Clients`. |
| `notes` | Free-form notes shown in the output file |

Multiple rows for the same customer are fine (e.g. Redacted Client 2 has both `redacted-client-2.example` and `redacted-client-2.example`).

## Known gotchas

- Vault names in `customers.csv` must match 1Password exactly — run `op vault list` to check
- `redacted-client-1.example` has many users and likely many subdomains; expect it to take longer and produce a large file
- crt.sh subdomain lookup is rate-limited; the script waits 1.5s between domains
- The venv must be active before running — system Python won't have the dependencies