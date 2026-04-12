# Dev Log — 2026-04-12

Previous logs: [2026-03-31](DEV_LOG_2026-03-31.md)

## Where We Are

- **Tests:** No test runner — validated by running the script against live data
- **Latest commit:** `3bde655` — Update README to reflect wordlist subdomain probing (dns_fetch.py has uncommitted changes)

## Session 1 — Fix archive naming bug

**What was asked:** The `--archive` flag was producing "Archive already exists — skipping" on every run after March 31, preventing the current `dns_records/` from being backed up before overwrite.

**What was built:**
- Replaced filesystem mtime-based archive naming with an explicit `.run_date` marker file written to `dns_records/` at the end of each run
- Archive name now uses a full `YYYY-MM-DD_HH-MM-SS` timestamp from the marker file, making collisions essentially impossible
- Seeded the existing `dns_records/.run_date` with `2026-03-31_00-00-00` so the next run archives current records correctly

**Decisions made:**
- Used a `.run_date` marker file instead of filesystem timestamps — mtime is unreliable because re-running on the same day updates mtime and causes naming collisions with the archive created by the second run
- Full datetime timestamp instead of date-only — eliminates the need for a counter-suffix fallback; any number of runs per day produce distinct archives
- Archive is named after *when the records were fetched* (not when the archive is being created) — preserves the original semantic intent of the code

**Files modified (1):** `dns_fetch.py`

**Tests:** No test runner; logic reviewed manually

**What could have gone better:**
- Initially fixed the archive date to use `date.today()` without fully considering that the user wanted the archive named after the fetch date, not the current date — required a second round of changes
- Proposed the counter-suffix approach before the user suggested the simpler timestamp solution
