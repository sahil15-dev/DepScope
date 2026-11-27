# Testing DepScope

Run PowerShell from the repository root after [installing the development dependencies](../README.md#windows-setup). Standard tests use injected HTTPX mock transports and an in-process FastAPI test client. The test suite rejects use of HTTPX's live transport.

```powershell
$python = '.\.venv\Scripts\python.exe'
New-Item -ItemType Directory -Path .\artifacts -Force | Out-Null
$testRun = '.\artifacts\pytest-' + [guid]::NewGuid().ToString('N')
& $python -m ruff check backend migrations e2e
& $python -m ruff format --check backend migrations e2e
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

## Frontend checks

Install the locked dependencies and run these commands from `frontend`. Component tests use an in-memory router and mock the local API. They exercise dashboard totals, source switching, loading and error states, manifest submission, status polling, saved results, history pagination, explorer filters, and safe advisory links.

```powershell
npm.cmd ci --ignore-scripts --cache ..\artifacts\npm-cache --no-audit --no-fund
npm.cmd run lint
npm.cmd run typecheck
npm.cmd run test
npm.cmd run build
```

The [browser check](#browser-and-packaging-checks) starts a disposable loopback server against the production build and exercises the offline sample workflows.

### Phase 3 verification

- ESLint and `tsc --noEmit` passed. Vitest 3.2.7 passed all 11 component tests in one suite. Vite 7.3.8 built the production assets in `frontend/dist`.
- Chromium passed a loopback check on the production build at 1440 × 1000 and 390 × 844. The check seeded an isolated SQLite database with offline samples, submitted a partial scan through the UI, verified its advisory evidence and fix, filtered the explorer, reopened history, and switched themes. Mobile navigation and layout fit the viewport. This check made no live OSV requests.

## Phase 4 verification

Backend verification passed **139 tests** with **95.17% combined statement and branch coverage**. Ruff lint and formatting passed, Mypy checked 42 files without issues, and `pip check` found no broken requirements. The empty database upgraded to `0001_scan_history`, a repeated upgrade succeeded, and `alembic check` found no new operations. Starlette emitted one existing HTTPX test-client deprecation warning.

ESLint and `tsc --noEmit` passed, Vitest 3.2.7 passed **16 component tests**, and Vite 7.3.8 built the production dashboard. The [audit](phase4-audit.md) records the pre-change baseline and the saved live evidence.

Phase 4 captured the prior dashboard before and after implementation under `artifacts/phase4-visuals`. The browser check now runs the expanded Phase 5 suite.

## Browser and packaging checks

Build the frontend first. The suite serves the production dashboard and the API from the same loopback test origin on port 41736. It creates a new workspace database and uses a mock advisory provider for upload and paste. Run it from the workspace root in PowerShell.

```powershell
$env:PLAYWRIGHT_BROWSERS_PATH = Join-Path (Resolve-Path .).Path 'artifacts\phase5-browsers'
node .\frontend\node_modules\playwright\cli.js install chromium firefox webkit
$env:DEPSCOPE_E2E_BUNDLED = '1'
$env:DEPSCOPE_E2E_BROWSERS = 'chromium,firefox,webkit'
node .\frontend\e2e\smoke.mjs
```

The suite checks 1440 × 1000 desktop, 900 × 900 tablet, and 390 × 844 mobile. It exercises scan inputs, grouped findings, remediation, history, comparison, report downloads, and print layout. Chromium also produces a PDF. Captures and exports are under `artifacts/phase5-browser`. Linux may require Playwright system libraries. The default run uses installed Chrome when no browser override is given.

To verify packaging outside the source tree, build a wheel and source archive, then create a separate virtual environment inside `artifacts`. Run from the workspace root after the locked [developer install](../README.md#windows-setup).

```powershell
$python = '.\.venv\Scripts\python.exe'
$trial = '.\artifacts\package-' + [guid]::NewGuid().ToString('N')
& $python -m build --no-isolation --outdir "$trial\dist"
& $python -m venv "$trial\install"
$installed = "$trial\install\Scripts\python.exe"
& $installed -m pip install --require-hashes --only-binary=:all: -r requirements/runtime.txt
$wheel = (Get-ChildItem "$trial\dist\*.whl").FullName
& $installed -m pip install --no-deps $wheel
& $installed -m pip check
$cli = (Resolve-Path "$trial\install\Scripts\depscope.exe").Path
$sample = (Resolve-Path .\samples\requirements-clean.txt).Path
Push-Location $trial
& $cli scan $sample --offline --fail-on high --format json
Pop-Location
```

See the [deployment guide](deployment.md) for the Compose configuration and runtime checks and the [CI guide](ci-policy.md) for workflow semantics.

### Phase 5 verification

The Windows baseline passed 139 backend tests with 95.17% coverage, 16 frontend tests, Ruff, Mypy, ESLint, TypeScript, the Vite build, and the prior Chromium smoke check.

| Check | Phase 5 result |
| --- | --- |
| Backend | 150 passed. Combined statement and branch coverage was 95.44%. Ruff lint and format checks and Mypy passed across 47 files. The existing Starlette test-client deprecation warning remains. |
| SQLite | A fresh database upgraded to `0001_scan_history`. Alembic reported no missing schema changes. |
| Frontend | All 16 Vitest tests passed. ESLint, TypeScript, and the Vite production build passed. |
| Browser | 14 workflows per engine, 42 total, using Playwright Chromium 159.0.8154.6, Firefox 159.0, and WebKit 27.2. |
| Packaging | Built `depscope-0.5.0.tar.gz` and `depscope-0.5.0-py3-none-any.whl`, rebuilt the wheel from the source archive, and installed it in a fresh Windows virtual environment. CLI help, version, and fixture scan exits 0, 1 and 3 passed outside the source tree. |
| Docker | Compose configuration, image build, non-root startup, health, offline scan, and restart persistence passed on Docker Desktop with the Linux engine. |
| CI | GitHub’s official action pins and the workflow passed local verification with actionlint 1.7.12. A hosted run remains pending. |

## Phase 6 verification

Pytest passed 151 tests at 95.44% combined statement and branch coverage on Windows. Ruff lint and formatting and Mypy passed. A new SQLite database upgraded to `0001_scan_history` and Alembic found no pending operations. ESLint, TypeScript, all 16 Vitest 5.1.2 tests, and the Vite production build passed.

The Linux CI steps were reproduced locally on CPython 3.12.16, 3.13.18, and 3.14.10. Each passed all 151 tests, lint, formatting, types, and schema checks. Node.js 22.22.0 also passed frontend lint, types, and all 16 tests in a network-disabled container. A new Windows installation rebuilt the wheel from the source archive, initialized SQLite, started the loopback API, and completed the offline demo and CLI history, report, and comparison checks. Docker passed health and repeat report checks across a restart. The Action pins and workflow passed local verification. Hosted CI awaits owner authorization.

Linux coverage was 95.44% on Python 3.12 and 3.13 and 95.18% on Python 3.14. Explicit SQLite fixture teardown eliminated the resource warnings on 3.13 and 3.14. The existing Starlette test-client deprecation warning remains.

Playwright passed 42 checks, with 14 on each of Chromium 159.0.8154.6, Firefox 159.0, and WebKit 27.2. The navigation waits for document readiness and each workflow verifies its own rendered controls and results.

The original Windows OSV failure occurred during certificate validation. DNS resolved the OSV host and TCP connected. The bundled CA list alone could not validate the certificate chain, while the platform trust store negotiated TLS successfully. The client now uses both CA stores and keeps hostname and certificate verification enabled. The public Jinja rerun completed with exit 0, one exact version assessed, and five findings at observation time. Incomplete coverage still produces a nonzero CLI policy result. [OSV batch API](https://google.github.io/osv.dev/post-v1-querybatch/)

The release audit updated Vitest to 5.1.2, setuptools to 84.2.1, and wheel to 0.48.0. After updating the locks, the official npm registry reported zero matching vulnerabilities, and PyPI reported zero active advisories for the 41 exact Python package pins checked. These results are limited to the registries and package versions checked. [Vitest advisory](https://github.com/advisories/GHSA-82fw-gwwq-j7x9) · [setuptools advisory](https://github.com/advisories/GHSA-h35f-9h28-mq5c) · [wheel advisory](https://github.com/advisories/GHSA-8rrh-rw8j-w5fx)

## Optional live smoke scan

An explicitly requested smoke scan sends the bundled historical Jinja coordinate to OSV. Results may change as upstream records are updated. Keep this check separate from the offline suite.

The Phase 5 smoke returned exit 3 with zero assessed coordinates and a `request_failed` diagnostic. The Phase 6 result and its diagnosis are recorded above.

```powershell
$python = '.\.venv\Scripts\python.exe'
New-Item -ItemType Directory -Path .\artifacts -Force | Out-Null
$liveReport = '.\artifacts\live-' + [guid]::NewGuid().ToString('N') + '.json'
& $python -m depscope scan .\samples\requirements-vulnerable.txt --live --output $liveReport
```
