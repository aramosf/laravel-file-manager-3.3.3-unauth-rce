# lfm_scanner — exposure scanner (LFM-2026-ADV-01)

Checks whether a URL, or a list of URLs, exposes `alexusmai/laravel-file-manager`
with an insecure configuration. Stdlib Python 3, no dependencies.

> **Authorized use only.** Run it only against systems you own or are explicitly
> authorized in writing to test. Passive mode is non-intrusive; the active tiers
> write test files and require `--authorized`.

## How it decides

**Passive (default).** One request per host — `GET /<prefix>/initialize`. If the
component answers with its JSON config, the host is reachable **without
authentication** and the scanner reports the `acl` flag and disk list. Nothing is
written. This alone classifies most hosts.

**`--active` (needs `--authorized`).** Uploads a single **inert** marker file
(`.txt`, random content, no code), fetches it back from `/storage/` to prove the
unrestricted-upload + public-read primitive, then **deletes** it. It never plants a
web shell.

**`--confirm-exec` (implies `--active`, needs `--authorized`).** Additionally
uploads a minimal **inert** PHP marker — `<?php echo "<random>";` — that takes no
parameters and runs no commands, to confirm the host actually *executes* PHP under
the storage path. It is deleted afterwards. This is the only tier that writes an
executing file; use it only where a full, authorized confirmation is required.

By default the active probe is **skipped when `acl=true`** is reported (add
`--ignore-acl` to force it).

## Verdicts

| Verdict | Risk | Meaning |
|---|---|---|
| `EXEC_CONFIRMED` | CRITICAL | inert PHP marker executed — RCE-grade exposure |
| `UPLOAD_CONFIRMED` | CRITICAL | inert file written and read back publicly |
| `EXPOSED_UNAUTH` | HIGH | `initialize` reachable without auth (acl/disks reported) |
| `AUTH_REQUIRED` | LOW | component gated (401/403 or redirect to login) |
| `NOT_DETECTED` | – | component not present / not the expected response |
| `ERROR` | – | network/parse error |

Exit code is `2` when any exposed/confirmed host is found, else `0` — convenient for
CI and pipelines.

## Usage

```bash
# Single host, passive
python3 lfm_scanner.py --url https://target.example

# List of hosts (one per line, # comments allowed)
python3 lfm_scanner.py --list targets.txt

# From stdin, only print exposed hosts, JSON lines
cat targets.txt | python3 lfm_scanner.py --only-vuln --json

# Authorized active confirmation (writes + deletes an inert file)
python3 lfm_scanner.py --url https://target.example --active --authorized

# Authorized full confirmation incl. PHP execution test
python3 lfm_scanner.py --url https://target.example --confirm-exec --authorized

# CSV report of a batch
python3 lfm_scanner.py --list targets.txt --csv results.csv
```

Useful options: `--prefix a,b,c` (route prefixes to try; default
`file-manager,filemanager,admin/file-manager,laravel-filemanager`), `--disk NAME`,
`--threads N`, `--delay S` (per-worker pacing), `--timeout S`.

## Quick self-test against the lab

With the local lab running (`cd ../lab && docker compose up -d`):

```bash
python3 lfm_scanner.py --url 127.0.0.1:18080                      # -> EXPOSED_UNAUTH
python3 lfm_scanner.py --url 127.0.0.1:18080 --confirm-exec --authorized   # -> EXEC_CONFIRMED
```
