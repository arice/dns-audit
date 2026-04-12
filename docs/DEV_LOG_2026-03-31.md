# Dev Log — 2026-03-31

Previous logs: [2026-02-28](DEV_LOG_2026-02-28.md)

## Where We Are

- **Tests:** No test runner — validated by running the script against live data
- **Latest commit:** `55af726` — Update dev log (dns_fetch.py has uncommitted changes)

## Session 1 — README usage clarifications

**What was asked:** (1) Document that `op signin` is required before `--op-sync`; (2) clarify that venv setup is one-time only and daily usage just needs `source .venv/bin/activate`.

**What was built:**
- Added "Do this once when you first clone the repo" framing to Setup section
- Split Usage section to show venv activation as a per-session step (not setup)
- Added `op signin` step with note it's only needed for `--op-sync`
- Corrected `eval $(op signin)` (old v1 pattern) to plain `op signin` after user correction

**Decisions made:**
- `op signin` not `eval $(op signin)` — v2 CLI doesn't require the eval wrapper

**Files modified (1):** `README.md`

**Tests:** No code changes; README reviewed for correctness

**What could have gone better:**
- Used `eval $(op signin)` initially — that's the v1 pattern. Should have defaulted to plain `op signin` for the modern CLI.

## Session 2 — Subdomain discovery improvements + bug fixes

**What was asked:** Add wordlist-based subdomain probing to catch subdomains missing from crt.sh (e.g. those without TLS certs). Fix false positives caused by Cloudflare wildcard DNS. Then fix three bugs identified in a senior code review.

**What was built:**
- Added `COMMON_SUBDOMAINS` wordlist (19 entries) probed after crt.sh lookup
- Canary query (`__wildcard-canary__.<domain>`) to detect wildcard DNS — checks both A records and CNAME to handle CNAME-only wildcards (e.g. some CDNs)
- Module-level `_dns_cache` and `_ttl_cache` — all `query_record()` calls are now cached, eliminating redundant queries for the same name/type
- `get_ttl()` helper reads TTL from cache; `build_markdown` now uses it instead of re-querying each record type for its TTL
- Wildcard filter applied only to wordlist probes; crt.sh results always kept (they represent real issued certs)

**Decisions made:**
- crt.sh results are unconditionally trusted — certificate issuance proves the subdomain existed; wildcard filtering only applies to wordlist guesses
- Canary subdomain (`__wildcard-canary__`) is guaranteed not to be a real name, so any resolution it returns is definitively a wildcard
- Cache is module-level (not per-run) which is fine since the script is a single-shot process

**Files modified (1):** `dns_fetch.py`

**Tests:** Syntax check passes; runtime validation pending live run

**What could have gone better:**
- First wildcard fix applied the filter in `build_markdown` to all subdomains including crt.sh results — user correctly pointed out that discards valid subdomains. Should have distinguished crt.sh vs wordlist sources from the start.
- First canary implementation only checked A records, missing CNAME-only wildcards — caught in code review.
