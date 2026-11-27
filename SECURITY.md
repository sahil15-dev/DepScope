# Security policy

DepScope is a local single-user scanner. Keep the API and dashboard bound to loopback and run one worker per SQLite database. External users must have no route to private scan history. Treat the data directory, backups, and report exports as sensitive.

Live requests send exact package names, ecosystem identifiers, and versions to OSV. The scanner does not transmit the original upload, follow manifest paths or advisory URLs, or invoke a package manager. Offline samples use a bundled advisory subset.

Disclose suspected DepScope vulnerabilities privately to the project owner. A public issue tracker and reporting address have yet to be established. Include the affected version, a description of the behavior and its impact, and steps using a sanitized fixture. Do not include private manifests, databases, exports, or credentials. [Threat model](docs/threat-model.md)
