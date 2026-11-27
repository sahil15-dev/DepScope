# Risk prioritization

DepScope keeps advisory severity, CVSS, and its own risk index as distinct fields. Scan results carry a scoring revision so historical values can be explained.

## Advisory evidence

- Preserve the upstream scheme, vector, and source. Compute a base score with the `cvss` library for valid CVSS v2, v3.0, v3.1, and v4.0 vectors. CVSS v4 base scoring uses only the base metrics. The numeric result records `base_vector` provenance. Use v2's low, medium, and high bands and v3/v4's additional critical and none bands. Preserve explicitly known `none` separately from unknown. [CVSS library](https://pypi.org/project/cvss/3.6/) · [NVD severity ratings](https://nvd.nist.gov/vuln-metrics/cvss)
- Within each advisory, apply supported evidence from a matching package and version entry first. Otherwise use supported advisory-level evidence. Among equally scoped sources and merged records, use the highest supported severity while preserving the underlying evidence. Use `unknown` when no supported source supplies a severity and flag it for manual review.
- Suggest a fixed version when the exact scanned version falls in an applicable range that ends at that `fixed` boundary. If another matching record for the same finding also identifies the candidate as affected, suppress the suggestion. Preserve the advisory ID, range type, and introduction boundary. A suggestion applies to this finding. Other findings, compatibility, and test outcomes inform the upgrade decision.

## Scan-level index

```text
risk_index = min(100, 20 × critical + 10 × high + 4 × medium + low)
```

Each input is a finding count after deduplication by package coordinate and advisory identity. The index is a local triage heuristic on a 0–100 scale. Its weights express a preference for investigating higher-severity findings first. It does not evaluate exploitability, reachability, business impact, or probability of compromise.

`unknown` and `none` contribute zero weight and have separate counts. The index is unavailable when no coordinate completed an assessment or all observed findings have unknown severity. A zero represents zero weighted findings within the scan's coverage. When a partial scan has a numeric index, interpret it in the context of its coverage. Trend views should retain scan provenance and distinguish unavailable values from zero.

## Recommendation order

1. Present rated findings by descending severity.
2. Within the same severity, place findings with an advisory-supported fix first so the user can identify actionable work. Use normalized ecosystem, package, version, and advisory ID as deterministic tie breakers.
3. Show unknown-severity findings and unresolved dependencies in the manual-review queue. Surface missing or uncertain fix evidence within each finding.

For each item, describe the recorded severity, fix evidence, and next review step. No recommendation rewrites the input manifest.
