# Contributing to DepScope

Use the [workspace quickstart](README.md#quickstart) and [verification commands](docs/testing.md). Keep changes focused and preserve the standalone scanning engine and the API’s existing contracts. Run Ruff, Mypy, Pytest with coverage, frontend lint and type checks, and the production build. Run the browser suite for changes that affect workflows or presentation.

Use public or synthetic fixture manifests. Never install their dependencies. When changing matching logic, include evidence for affected versions, aliases, severity and fix handling. Preserve incomplete lookups in results, logs and exports as safe diagnostic codes.

Review staged files for credentials, private environment values, databases, scan exports and local development files. Use a short commit message that describes the behavior change. Describe actual verification results and known limitations in the change description.

Project licensing is pending. Resolve the licensing terms with the owner before redistributing project code. Existing third-party notices still apply. [Third-party notices](docs/third-party.md)
