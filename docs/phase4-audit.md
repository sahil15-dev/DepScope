# Phase 4 audit

## Baseline

The existing engine and dashboard passed the offline baseline on Windows. Pytest passed 128 tests with 95.93% combined statement and branch coverage. Ruff lint and formatting and Mypy passed. The frontend passed ESLint, TypeScript checks, all 11 Vitest tests, and the Vite production build. Chrome rendered the offline dashboard at desktop, tablet, and mobile sizes before implementation.

## Saved live scan

The SQLite snapshot contained six dependency occurrences, six distinct exact coordinates, six complete lookups, and no unresolved occurrences or incomplete lookups. All six exact coordinates had findings. The 121 saved findings consisted of 16 critical, 62 high, 36 medium, 5 low, and 2 unknown-severity findings. The weighted total under scoring revision 1 was 1,089 before capping at 100.

The audit matched stored coordinates to normalized occurrences and checked each coordinate's finding IDs, aliases, and observed IDs for intersections. No identity sets overlapped within a coordinate. This establishes consistency with the saved evidence. Historical request bytes and an independent upstream completeness check are unavailable. The Phase 4 upload regression test exercises the current byte transport with synthetic content, verifies exact lookup coordinates and unresolved counts, and checks that a raw comment is absent from the stored database.

## Pillow fix evidence

The saved advisory `PYSEC-2022-42980` includes alias `CVE-2022-45199`. It explicitly lists the assessed Pillow version, normalized to `8.2`, as affected. Its ecosystem range begins at `9.2.0` and ends at the fix boundary `9.3.0`. That interval excludes `8.2`. Git ranges are retained as evidence but cannot supply a Python package fix proof. The saved finding correctly records no applicable fix for the scanned version. A synthetic regression fixture covers this case and the interface now explains how a fixed boundary can belong to a different version range.

## Corrections

- The score reached 100 with ten high findings and could no longer distinguish larger counts. The dashboard now labels the cap, displays the recorded severity distribution, and reserves green for successful lookup and remediation indicators. Scoring revision 1 remains comparable to saved results.
- The former chart connected independent scans and could render one point as a trend. The dashboard now connects repeated runs of the same offline sample on one scoring revision and plots live scans as independent observations. Single scores get their own label.
- The previous findings view showed one row per advisory and made it difficult to tell how many exact versions were affected. The new dependency view groups the same filtered findings by exact coordinate, expands to advisory evidence, and supplies the same counts to the overview and remediation.
- Remediation, comparisons, and reports use saved data. Candidates identify the stored lookup used for validation. Comparison retains package membership, version changes, and lookup coverage. The JSON and printable report read the same stored snapshot.
