# Phase 1 offline fixtures

These files are scanner inputs. Use the offline mode with them. Keep intentionally vulnerable dependencies out of the development environment.

| Input | Expected offline behavior |
| --- | --- |
| `requirements-vulnerable.txt` | One historical Jinja advisory. |
| `package-lock-vulnerable.json` | One historical lodash advisory. |
| `requirements-clean.txt` | One assessed coordinate with zero matches in this fixture subset. |
| `requirements-mixed.txt` | One assessed pin and four entries that require manual review. |
| `requirements-partial.txt` | A hydrated Jinja finding and a synthetic discovery ID whose detail endpoint returns 404. |
| `package-lock-malformed.json` | Invalid input with a safe parsing error. |

`osv.json` contains selected and shortened fields from public advisories for the two affected packages in the samples. It also defines synthetic responses for zero matches and a missing advisory. Its results are static and omit additional packages and advisories. The manual smoke scan uses only the historical Jinja sample.

- Jinja `3.1.2` and its advisory-specific fix `3.1.3`. [OSV GHSA-h5c8-rqwp-cp95](https://osv.dev/vulnerability/GHSA-h5c8-rqwp-cp95) · [GitHub advisory](https://github.com/advisories/GHSA-h5c8-rqwp-cp95)
- lodash `4.17.20` and its advisory-specific fix `4.17.21`. [OSV GHSA-35jh-r3h4-6jhm](https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm) · [GitHub advisory](https://github.com/advisories/GHSA-35jh-r3h4-6jhm)
