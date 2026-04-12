# Learnings

## `op signin` not `eval $(op signin)`

The modern 1Password CLI (v2+) uses plain `op signin` — no `eval $(...)` wrapper needed. The eval pattern is from v1. When documenting op CLI usage, default to `op signin`.

## Wildcard DNS filtering must not discard crt.sh results

crt.sh entries represent real TLS certificates that were issued — they prove the subdomain existed. Wildcard IP filtering (to suppress Cloudflare wildcard hits) must only be applied to wordlist-probed subdomains, never to crt.sh results.

## Archive naming must not rely on filesystem timestamps

`st_mtime` is updated every time a file is written. If the script runs twice in one day, the second run sees today's date as the mtime, creates an archive named after today, and every future run hits that same archive name and skips. Use an explicit `.run_date` marker file written at the end of each run. Name archives from the marker, not from mtime.

## Cloudflare wildcard detection requires canary, not apex comparison

Comparing a subdomain's A records against the apex A records is unreliable — the apex is a real record and may differ from the wildcard pool. Use a guaranteed-nonexistent canary subdomain (e.g. `__wildcard-canary__.<domain>`) instead. Also check CNAME on the canary: some CDNs use CNAME-only wildcards where no A record is returned for the canary at all.
