# Threat model

DepScope serves one user on a trusted workstation. The local browser can submit hostile files, unrelated web pages may try to reach local endpoints, and external advisory data can be malformed or unavailable. The design protects local files, scan history, service availability, and the integrity of findings. A compromised operating system or another user with access to the account's files is outside the trust model.

The local API adds bounded streaming, submission limits, Host and Origin checks, and transaction-safe storage. The documented Uvicorn command disables access logs so query strings and request paths stay out of those logs. The dashboard uses a fixed loopback proxy, renders advisory values as text, and restricts reference links to HTTP(S) without embedded credentials. Live lookup requires approval in the form. The browser persists only the theme preference.

## Data and trust boundaries

| Boundary | Data and security control |
| --- | --- |
| Browser to local API | User-selected file bytes, pasted text, or a bundled sample ID. Bind to loopback by default. Validate the host on every request and check browser origins on submissions. Allow only explicitly configured development origins and cap input bytes before parsing. |
| Parser to engine | Typed package coordinates and bounded diagnostics. Treat all manifest content as data. The parser has no dependency installation, subprocess, file inclusion, or external fetch capability. |
| Engine to OSV | Exact package names, versions, and ecosystems for live queries. Require certificate and hostname verification using the platform and bundled CA stores. Use a fixed HTTPS host, disable redirects and ambient HTTP proxies, and skip targets obtained from input or advisory content. |
| OSV to UI and exports | Advisory IDs, aliases, summaries, ranges, CVSS evidence, and links. Validate response shape and size. Render text through framework escaping. Limit clickable external references to validated HTTP(S) URLs and preserve their provenance. |
| Engine to local storage | Normalized occurrences, lookup states, provenance, and advisory evidence. Keep raw input in memory through parsing, with no persisted upload or body logging. Keep local paths, source URLs, and rejected lines out of scan history. |

## Threats and controls

| Threat | Consequence | Control and verification |
| --- | --- | --- |
| Requirements directives, external URLs, or lockfile paths are interpreted as commands or files | Execution, local file disclosure, or unintended network requests | Parse as data and capture only recognized metadata. Test that include, editable, URL, local-source, and path-like values stay unresolved or are rejected without filesystem or network side effects. |
| Oversized, deeply nested, or very large manifests and request floods | Memory, CPU, storage, or OSV quota exhaustion | Start with a configurable 1,000,000-byte limit. Bound nesting, entry counts, unique queries, pending jobs, scan creation rate, and outbound work. Test streaming size enforcement and saturation behavior. |
| Forged browser submissions or DNS rebinding | Unauthorized scans from another origin | Use loopback binding, a configured Host allowlist, and Origin checks for browser mutations. Permit direct local clients with absent Origin subject to the other checks. Test mismatched origins and hosts. |
| HTML or unsafe links in manifest metadata or advisory text | Script execution or unexpected navigation in the app and printable report | Render escaped plain text, validate link schemes, and open external links without opener access. Test hostile rendered values in UI and print views. |
| Incomplete, inconsistent, or stale OSV data | False confidence in a clean scan or an incorrect upgrade recommendation | Track per-coordinate lookup and advisory fetch state. Use bounded cache lifetimes, suppress unverified fixes, and retain evidence, timestamps, and visible coverage caveats. Mock failure and inconsistency cases. |
| Process death or partial database writes | Stuck jobs, incomplete snapshots, or divergent totals | Write results and final status atomically, recover interrupted queued/running jobs on startup, and test failed transactions and restart behavior. |
| Logs or history retain private identifiers or embedded credentials | Local data disclosure | Log operational counts and sanitized codes. Exclude original content and embedded repository or file references from persistence. Review logs and exports against test inputs with marker strings. |
| Fixture data is mistaken for a live scan | Misleading security judgments or reports | Attach provenance at the provider boundary, display it throughout the UI, and include it in exports. Verify the offline fixture path issues no live requests. |

## Residual exposure

The production server serves known dashboard paths and build assets under the same loopback host validation as the API. Its content security policy permits same-origin resources and inline styles needed by the dashboard, and blocks framing and cross-origin fetches. The container runs without Linux capabilities and writes scan data only to a named volume. CLI database readers use read-only SQLite connections.

The Phase 5 review checked file and request limits, parameterized SQLite queries, output encoding and reference links, redacted diagnostics, excluded local files, and the permissions of the CI and Docker configurations. Local tests exercised origin and host rejection, unknown static paths, safe error states, and database ownership. The Docker smoke confirmed loopback binding and persisted data. The workspace scan found no matching secret patterns in release files. Dependency locks and third-party notices record the material examined. [Verification](testing.md) · [Third-party notices](third-party.md)

Live queries disclose package coordinates to OSV. The local database and user-exported reports contain package names and versions and should be treated as project data. DepScope's results reflect supported inputs and available advisory coverage at the observation time. Reachability, exploitability in a particular environment, local workstation compromise, and remote multi-user hosting remain outside the initial design.
