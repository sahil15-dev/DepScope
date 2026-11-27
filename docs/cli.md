# Command-line guide

Install DepScope using the [quickstart](../README.md#quickstart). The CLI and _python -m depscope_ run the same scanner. The frontend is optional. Run database commands from an initialized workspace. A wheel install can scan from any working directory when supplied a manifest.

## Scan and export

~~~powershell
$cli = '.\.venv\Scripts\depscope.exe'
& $cli --help
& $cli --version
& $cli scan .\samples\requirements-vulnerable.txt --offline
& $cli scan .\samples\package-lock-vulnerable.json --offline --format json
& $cli scan .\samples\requirements-clean.txt --offline --fail-on high
New-Item -Path .\artifacts -ItemType Directory -Force | Out-Null
$out = '.\artifacts\scan-' + [guid]::NewGuid().ToString('N') + '.json'
& $cli scan .\samples\requirements-vulnerable.txt --offline --output $out
~~~

Select `--offline` or `--live` explicitly. Offline mode uses the bundled advisory subset and reports coordinates outside it as unassessed. Live mode transmits exact package names, ecosystems, and versions to OSV. The scanner reads the selected manifest as UTF-8 data and never invokes its package manager.

Use `--manifest-format requirements` or `--manifest-format npm-lock` if the file has a different name. `--format json` writes one JSON document to stdout containing the result and its exit code. Errors without a result go to stderr. `--output` writes the same JSON to a new file using exclusive creation.

The defaults are 1,000,000 manifest bytes, 5,000 parsed occurrences, 2,000 distinct exact coordinates, and a lockfile depth of 40. `--max-bytes` accepts up to 10,000,000 bytes. `--max-occurrences` and `--max-coordinates` can lower the default caps. For live lookup, `--timeout` is the total OSV budget in seconds (default 45, range 1–300) and `--request-timeout` is the per-request budget (default 8, range 1–60). A timeout may leave partial evidence.

## Read and compare saved history

Database commands use `data/depscope.sqlite3` by default. Pass `--database` with a SQLite file inside the current workspace or set `DEPSCOPE_DB_PATH`. Initialize it with Alembic. History, report, and compare open SQLite read-only and can run while the API is running.

~~~powershell
& .\.venv\Scripts\python.exe -m alembic upgrade head
& $cli history --provenance offline_fixture --page-size 10
$baseline = (& $cli scan .\samples\requirements-clean.txt --offline --save --format json | ConvertFrom-Json).scan_id
$target = (& $cli scan .\samples\requirements-vulnerable.txt --offline --save --format json | ConvertFrom-Json).scan_id
& $cli report $target --format json
& $cli compare $baseline $target --fail-on medium
~~~

The last command exits 1 because the target has a newly detected medium finding. `--save` records normalized evidence and returns a scan ID. Stop the API before saving to its database or use a separate migrated database. For offline persistence, the file must match a bundled sample in the source checkout. This keeps saved history labeled with the fixture that ran.

A comparison policy requires two finished scans with the same provenance and manifest format. It detects new package and advisory identities using aliases and detects findings whose severity crossed the selected threshold. A changed version with the same advisory identity can still represent an existing finding. Review version changes and coverage in the output. [CI policy example](ci-policy.md)

## Exit codes

| Code | Meaning |
| --- | --- |
| 0 | Command completed. If a policy was requested, the available evidence passed it. |
| 1 | A finding met the selected severity threshold. Comparison applies it to newly detected or newly elevated advisory identities. |
| 2 | Invalid arguments, unsupported or unreadable manifest, invalid manifest contents, or unavailable scan selection. |
| 3 | Insufficient evidence. Includes partial or failed lookups, unresolved input, no assessed versions, pending scans, and unknown severity when a threshold is active. With a comparison threshold, both scans must satisfy the coverage conditions. |
| 4 | Operational failure, such as migration or schema readiness, storage ownership, setup, or an unwritable export. |

Without a policy, a completed lookup can contain unknown severity. The result preserves it as unknown. Read-only history and report commands return success when they can retrieve the requested records, including records of failed scans. The legacy `python -m depscope FILE` invocation retains its original codes of 0 for completed lookups, 1 for incomplete lookups, and 2 for input or export errors.
