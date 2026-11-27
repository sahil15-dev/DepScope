# Changelog

## Release-readiness fixes

- Use the platform and bundled CA stores together for verified OSV requests.
- Update the Vitest, setuptools, and wheel pins to patched versions.
- Wait for the Docker service to become healthy before the documented health check.
- Close SQLite test connections during fixture teardown and make browser navigation wait for document readiness.
- Declare the offline fixture package explicitly and verify it in wheels rebuilt from the source archive.

## 0.5.0

- Added the installable CLI with scan, history, report and compare commands, text and JSON output, explicit modes, bounded options, and fail-closed policies.
- Shipped the offline advisory catalog as Python package data so installed scans work outside a source checkout.
- Added a hash-locked Python build and runtime environment, wheel and source builds, and offline CI verification.
- Added a same-origin production server with a content security policy and a non-root loopback Docker Compose deployment backed by persistent SQLite.
- Expanded the browser tests to cover upload, paste, filter and group interactions, comparison, reporting, and incomplete results.

## 0.4 project milestone

- Added exact-version grouping, remediation evidence, saved-scan comparisons, and JSON and printable reports.
- Separated offline sample trends from independent live risk observations and documented the scoring cap.

## 0.2 project milestone

- Added bounded local scan jobs, transaction-safe SQLite history, schema migrations and restart reconciliation.
