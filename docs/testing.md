# Testing DepScope

Run PowerShell from the repository root after [installing the development dependencies](../README.md#windows-setup). Standard tests use injected HTTPX mock transports and an in-process FastAPI test client. The test suite rejects use of HTTPX's live transport.

```powershell
$python = '.\.venv\Scripts\python.exe'
New-Item -ItemType Directory -Path .\artifacts -Force | Out-Null
$testRun = '.\artifacts\pytest-' + [guid]::NewGuid().ToString('N')
& $python -m ruff check backend migrations
& $python -m ruff format --check backend migrations
& $python -m mypy
& $python -m pytest --basetemp $testRun --cov=depscope --cov-report=term-missing
& $python -m pip check
```

The suite exercises the scanner, SQLite migration from an empty file, transaction rollback, persisted advisory versions, REST response shapes and filters, input limits, concurrent submissions, and restart reconciliation. Tests use disposable workspace database files. The reported total includes branch coverage.

To verify migrations against a fresh database manually, use a new path in `artifacts`. The subprocess reads that path from the same configuration as the API.

```powershell
$testDb = '.\artifacts\migration-' + [guid]::NewGuid().ToString('N') + '.sqlite3'
$env:DEPSCOPE_DB_PATH = $testDb
& $python -m alembic upgrade head
& $python -m alembic current
& $python -m alembic check
Remove-Item Env:\DEPSCOPE_DB_PATH
```

## Phase 1 verification

- On Windows with Python 3.12.6, Ruff lint passed, all 22 Python files were formatted, Mypy found no issues in 22 files, and `pip check` found no broken requirements.
- Pytest passed **115 tests** with **96.60% combined statement and branch coverage** for the `depscope` package. The coverage report lists 1,246 statements with 30 missed and 430 branches with 27 partially covered.
- The temporary interface produced five verified JSON exports covering Python, npm, zero fixture findings, mixed resolution, and partial failure. The malformed-lockfile sample returned exit code `2` with `invalid_lockfile`.
- The single live Jinja smoke scan returned exit code `1` with one failed coordinate and `request_failed`. The result retained an unavailable risk index. Live end-to-end success remains unverified.

## Phase 2 verification

- On Windows with Python 3.12.6 and SQLite 3.45.3, `alembic upgrade head` migrated an empty database to `0001_scan_history`. Running the upgrade again succeeded and `alembic check` found no new operations.
- Pytest passed **128 tests** with **96.00% combined statement and branch coverage** for `depscope`. This includes checks for upload limits, scan admission and concurrency, rate limiting, job timeouts, rollback, persisted advisory versions, and restart recovery.
- Ruff lint and formatting passed. Mypy found no issues in 39 Python files and `pip check` found no broken requirements.
- A loopback Uvicorn smoke test exercised all six API routes with offline fixtures. Startup reconciled two interrupted records. A partial scan and its findings remained identical after restarting the process. SQLite integrity and foreign-key checks passed.
- Starlette emitted one deprecation warning for using HTTPX with its test client. Live OSV connectivity remains unverified and is outside the offline verification gate.

## Optional live smoke scan

An explicitly requested smoke scan sends the bundled historical Jinja coordinate to OSV. Results may change as upstream records are updated. Keep this check separate from the offline suite.

```powershell
$python = '.\.venv\Scripts\python.exe'
New-Item -ItemType Directory -Path .\artifacts -Force | Out-Null
$liveReport = '.\artifacts\live-' + [guid]::NewGuid().ToString('N') + '.json'
& $python -m depscope .\samples\requirements-vulnerable.txt --live --json $liveReport
```
