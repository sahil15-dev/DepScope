import { useQuery } from '@tanstack/react-query'
import { ChevronDown, ExternalLink, Search } from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { api, type Advisory, type FindingView, type PackageGroup } from './api'
import { Link } from 'react-router-dom'
import { dateLabel, safeReference, severities, wordLabel } from './presentation'
import {
  Busy,
  Empty,
  ErrorState,
  Pager,
  PanelHeader,
  SeverityBadge,
} from './ui'

function AdvisoryEvidence({
  advisory,
  entry,
}: {
  advisory: Advisory
  entry: FindingView
}) {
  const { coordinate } = entry.finding
  const normalize = (name: string) =>
    coordinate.ecosystem === 'PyPI'
      ? name.toLowerCase().replace(/[-_.]+/g, '-')
      : name
  const affected = advisory.affected.filter(
    (item) =>
      item.ecosystem === coordinate.ecosystem &&
      item.name &&
      normalize(item.name) === coordinate.name,
  )
  const references = advisory.references.flatMap((reference) => {
    const url = safeReference(reference.url)
    return url ? [{ ...reference, url }] : []
  })
  return (
    <section className="advisory-evidence">
      <h4>{advisory.id}</h4>
      {advisory.summary && <p>{advisory.summary}</p>}
      <p className="muted">Updated {dateLabel(advisory.modified)}</p>
      <h5>Affected versions</h5>
      {affected.length ? (
        <ul className="plain-list">
          {affected.map((scope, index) => (
            <li key={index}>
              {scope.versions.length > 0 && (
                <p className="version-list">{scope.versions.join(', ')}</p>
              )}
              {scope.ranges.map((range, rangeIndex) => (
                <p className="version-list" key={rangeIndex}>
                  {range.kind} ·{' '}
                  {range.events
                    .map((event) => `${wordLabel(event.kind)} ${event.version}`)
                    .join(' → ')}
                </p>
              ))}
              {!scope.versions.length && !scope.ranges.length && (
                <p>Version bounds unavailable.</p>
              )}
            </li>
          ))}
        </ul>
      ) : (
        <p>Version bounds for this package are unavailable.</p>
      )}
      {references.length > 0 && (
        <>
          <h5>Advisory references</h5>
          <ul className="reference-list">
            {references.map(({ url, kind }, index) => (
              <li key={`${url}-${index}`}>
                <a href={url} target="_blank" rel="noopener noreferrer">
                  <ExternalLink size={14} aria-hidden="true" />
                  <span>
                    {kind} · {new URL(url).hostname}
                  </span>
                  <span className="sr-only"> (opens in new tab)</span>
                </a>
              </li>
            ))}
          </ul>
        </>
      )}
    </section>
  )
}

export function FindingRow({
  entry,
  advisories,
}: {
  entry: FindingView
  advisories: Record<string, Advisory>
}) {
  const { finding, observations } = entry
  const { coordinate, priority } = finding
  const evidence = priority.severity_evidence
  const fixes = [...new Set(finding.fixes.map((fix) => fix.version))]
  return (
    <details className="finding-row">
      <summary>
        <div className="finding-name">
          <strong>{coordinate.name}</strong>
          <span className="table-note">
            {coordinate.ecosystem} · {coordinate.version} ·{' '}
            {finding.advisory_id}
          </span>
        </div>
        <div className="finding-summary-badges">
          <SeverityBadge value={priority.severity} />
          <span className={fixes.length ? 'fix-label' : 'muted'}>
            {fixes.length ? `Fix ${fixes.join(', ')}` : 'Fix unavailable'}
          </span>
          <ChevronDown
            className="disclosure-arrow"
            size={17}
            aria-hidden="true"
          />
        </div>
      </summary>
      <div className="finding-content">
        {fixes.length === 0 && (
          <p className="muted">
            No applicable fixed version was verified for {coordinate.version}.
            Saved advisory ranges can describe other versions.
          </p>
        )}
        {finding.evidence_level === 'discovery_only' && (
          <p className="notice notice-warning">
            Advisory ID discovered. Full matching evidence is unavailable.
          </p>
        )}
        <dl className="definition-grid">
          <div>
            <dt>Aliases</dt>
            <dd>
              {finding.aliases.length
                ? finding.aliases.join(', ')
                : 'None supplied'}
            </dd>
          </div>
          <div>
            <dt>CVSS base score</dt>
            <dd>
              {evidence?.score == null
                ? 'Unavailable'
                : `${evidence.score.toFixed(1)} · ${evidence.scheme}`}
            </dd>
          </div>
          <div>
            <dt>Severity evidence</dt>
            <dd>
              {evidence ? wordLabel(evidence.source) : 'Unavailable'}
              {evidence?.upstream_source && (
                <small>Source {evidence.upstream_source}</small>
              )}
            </dd>
          </div>
          <div>
            <dt>Priority rationale</dt>
            <dd>{wordLabel(priority.reason)}</dd>
          </div>
        </dl>
        {evidence?.vector && <p className="code-block">{evidence.vector}</p>}
        {finding.fixes.length > 0 && (
          <div className="fix-evidence">
            <h4>Advisory-supported fixed versions</h4>
            <ul className="plain-list">
              {finding.fixes.map((fix, index) => (
                <li key={index}>
                  <strong>{fix.version}</strong> · {fix.advisory_id} ·{' '}
                  {fix.range_type} range introduced at {fix.introduced}
                </li>
              ))}
            </ul>
          </div>
        )}
        {observations
          .filter((item) => item.error_code)
          .map((item) => (
            <p className="muted" key={item.discovery.id}>
              {item.discovery.id} · {wordLabel(item.error_code ?? '')}
            </p>
          ))}
        {finding.observed_ids.map(
          (id) =>
            advisories[id] && (
              <AdvisoryEvidence
                key={id}
                advisory={advisories[id]}
                entry={entry}
              />
            ),
        )}
      </div>
    </details>
  )
}

type GroupFilters = { severity?: string; fix_available?: string }

function CandidateDetails({
  scanId,
  item,
}: {
  scanId: string
  item: PackageGroup
}) {
  const response = useQuery({
    queryKey: ['candidates', scanId, item.coordinate],
    queryFn: ({ signal }) => api.candidates(scanId, item.coordinate, signal),
  })
  if (response.isPending)
    return <Busy label="Checking saved upgrade evidence" />
  if (response.isError)
    return (
      <ErrorState
        error={response.error}
        retry={() => void response.refetch()}
      />
    )
  if (!response.data.length)
    return <p>No advisory-specific fix is recorded for this version.</p>
  return (
    <div className="candidate-list">
      <h4>Candidate upgrades</h4>
      <p>
        Each candidate comes from a saved advisory fix. History checks use the
        same scan source and show the latest exact-version lookup available.
      </p>
      <ul>
        {response.data.map((candidate) => (
          <li key={candidate.version}>
            <strong>{candidate.version}</strong>
            <span>
              {candidate.evidence === 'no_known_findings'
                ? 'No known findings in saved lookup'
                : candidate.evidence === 'known_findings'
                  ? `${candidate.finding_count} findings recorded`
                  : 'Insufficient lookup evidence'}
            </span>
            <small>
              Advisory-specific fix · {candidate.advisory_ids.join(', ')}
            </small>
            {candidate.lookup_status && (
              <small>
                Lookup {candidate.lookup_status} ·{' '}
                {dateLabel(candidate.observed_at)}
              </small>
            )}
            {candidate.scan_id && (
              <Link to={`/scans/${encodeURIComponent(candidate.scan_id)}`}>
                Open lookup scan
              </Link>
            )}
          </li>
        ))}
      </ul>
      <p>
        Verify any change against your dependency constraints and application
        tests.
      </p>
    </div>
  )
}

function GroupAdvisories({
  scanId,
  item,
  filters,
  remediation,
}: {
  scanId: string
  item: PackageGroup
  filters: GroupFilters
  remediation: boolean
}) {
  const [page, setPage] = useState(1)
  const params = {
    ...filters,
    ecosystem: item.coordinate.ecosystem,
    name: item.coordinate.name,
    version: item.coordinate.version,
    page,
  }
  const data = useQuery({
    queryKey: ['findings', scanId, params],
    queryFn: ({ signal }) => api.findings(scanId, params, signal),
  })
  return (
    <div className="group-content">
      {remediation && <CandidateDetails scanId={scanId} item={item} />}
      {data.isPending ? (
        <Busy label="Loading package advisories" />
      ) : data.isError ? (
        <ErrorState error={data.error} retry={() => void data.refetch()} />
      ) : (
        <>
          {data.data.items.map((entry) => (
            <FindingRow
              key={entry.finding.advisory_id}
              entry={entry}
              advisories={data.data.advisories}
            />
          ))}
          <Pager
            page={data.data}
            label="Package advisories"
            onChange={setPage}
          />
        </>
      )}
    </div>
  )
}

export function PackageRow({
  scanId,
  item,
  filters = {},
  remediation = false,
}: {
  scanId: string
  item: PackageGroup
  filters?: GroupFilters
  remediation?: boolean
}) {
  const [open, setOpen] = useState(false)
  const { coordinate } = item
  return (
    <details
      className="package-row finding-row"
      onToggle={(event) => setOpen(event.currentTarget.open)}
    >
      <summary>
        <div className="finding-name">
          <strong>{coordinate.name}</strong>
          <span className="table-note">
            {coordinate.ecosystem} · {coordinate.version} · {item.finding_count}{' '}
            {item.finding_count === 1 ? 'finding' : 'findings'}
          </span>
        </div>
        <div className="finding-summary-badges">
          <SeverityBadge value={item.highest_severity} />
          <span className="muted">
            {item.fixable_count}/{item.finding_count} with a fix
          </span>
          <ChevronDown
            size={16}
            className="disclosure-arrow"
            aria-hidden="true"
          />
        </div>
      </summary>
      <div className="package-profile" aria-label="Severity distribution">
        {severities
          .filter((severity) => item.severity_counts[severity] > 0)
          .map((severity) => (
            <span key={severity} className={`severity-${severity}`}>
              <span className="indicator" />
              {item.severity_counts[severity]} {severity}
            </span>
          ))}
      </div>
      {remediation && (
        <p className="package-priority">
          <strong>Why this is prioritized</strong> ·{' '}
          {item.highest_severity === 'unknown'
            ? 'Severity needs manual review'
            : `Highest recorded severity is ${item.highest_severity}`}{' '}
          · {item.finding_count - item.fixable_count} findings need fix review
          {item.status !== 'complete' && ' · Lookup incomplete'}
        </p>
      )}
      {open && (
        <GroupAdvisories
          scanId={scanId}
          item={item}
          filters={filters}
          remediation={remediation}
        />
      )}
    </details>
  )
}

export function FindingsPanel({ scanId }: { scanId: string }) {
  const [view, setView] = useState<'advisory' | 'dependency'>('advisory')
  const [search, setSearch] = useState('')
  const [filter, setFilter] = useState('')
  const [severity, setSeverity] = useState('')
  const [ecosystem, setEcosystem] = useState('')
  const [fix, setFix] = useState('')
  const [sort, setSort] = useState('priority')
  const [page, setPage] = useState(1)
  const parameters = {
    package: filter,
    severity,
    ecosystem,
    fix_available: fix,
    sort,
    page,
  }
  const result = useQuery({
    queryKey: ['findings', scanId, parameters],
    queryFn: ({ signal }) => api.findings(scanId, parameters, signal),
    enabled: view === 'advisory',
  })
  const packages = useQuery({
    queryKey: ['packages', scanId, parameters],
    queryFn: ({ signal }) => api.packages(scanId, parameters, signal),
    enabled: view === 'dependency',
  })
  const filtered = Boolean(filter || severity || ecosystem || fix)

  function runSearch(event: FormEvent) {
    event.preventDefault()
    setFilter(search.trim())
    setPage(1)
  }
  function reset() {
    setSearch('')
    setFilter('')
    setSeverity('')
    setEcosystem('')
    setFix('')
    setPage(1)
  }

  return (
    <section className="panel">
      <PanelHeader
        title="Advisory findings"
        description={
          view === 'dependency' && packages.data
            ? `${packages.data.total} package versions · ${packages.data.finding_count} matching findings`
            : result.data && view === 'advisory'
              ? `${result.data.total} ${filtered ? 'matching ' : ''}${result.data.total === 1 ? 'finding' : 'findings'}`
              : 'Search and filter the evidence saved for this scan'
        }
        action={
          <div
            className="segmented"
            role="group"
            aria-label="Group findings by"
          >
            <button
              type="button"
              onClick={() => {
                setView('advisory')
                setPage(1)
                setSort('priority')
              }}
              aria-pressed={view === 'advisory'}
            >
              Advisory
            </button>
            <button
              type="button"
              onClick={() => {
                setView('dependency')
                setPage(1)
                setSort('priority')
              }}
              aria-pressed={view === 'dependency'}
            >
              Dependency
            </button>
          </div>
        }
      />
      <div className="filters finding-filters">
        <form className="search-form" onSubmit={runSearch}>
          <label>
            Package search
            <input
              value={search}
              maxLength={214}
              onChange={(e) => setSearch(e.target.value)}
              placeholder="Find a package"
              type="search"
            />
          </label>
          <button
            className="icon-button search-button"
            aria-label="Search packages"
            type="submit"
          >
            <Search size={17} aria-hidden="true" />
          </button>
        </form>
        <label>
          Severity
          <select
            value={severity}
            onChange={(e) => {
              setSeverity(e.target.value)
              setPage(1)
            }}
          >
            <option value="">All severities</option>
            {severities.map((item) => (
              <option key={item} value={item}>
                {item}
              </option>
            ))}
          </select>
        </label>
        <label>
          Ecosystem
          <select
            value={ecosystem}
            onChange={(e) => {
              setEcosystem(e.target.value)
              setPage(1)
            }}
          >
            <option value="">All ecosystems</option>
            <option>PyPI</option>
            <option>npm</option>
          </select>
        </label>
        <label>
          Fix evidence
          <select
            value={fix}
            onChange={(e) => {
              setFix(e.target.value)
              setPage(1)
            }}
          >
            <option value="">Any</option>
            <option value="true">Fix available</option>
            <option value="false">Fix unavailable</option>
          </select>
        </label>
        <label>
          Sort by
          <select
            value={sort}
            onChange={(e) => {
              setSort(e.target.value)
              setPage(1)
            }}
          >
            <option value="priority">Priority</option>
            <option value="package">Package name</option>
            {view === 'dependency' && (
              <option value="findings">Most findings</option>
            )}
          </select>
        </label>
      </div>
      {view === 'dependency' ? (
        packages.isPending ? (
          <Busy label="Loading package groups" />
        ) : packages.isError ? (
          <ErrorState
            error={packages.error}
            retry={() => void packages.refetch()}
          />
        ) : (
          <>
            {packages.data.items.length ? (
              packages.data.items.map((item) => (
                <PackageRow
                  key={JSON.stringify(item.coordinate)}
                  item={item}
                  scanId={scanId}
                  filters={{ severity, fix_available: fix }}
                />
              ))
            ) : (
              <Empty title="No matching packages">
                {filtered && (
                  <button
                    type="button"
                    onClick={reset}
                    className="button secondary small"
                  >
                    Clear filters
                  </button>
                )}
              </Empty>
            )}
            <Pager page={packages.data} label="Packages" onChange={setPage} />
          </>
        )
      ) : result.isPending ? (
        <Busy label="Loading advisory findings" />
      ) : result.isError ? (
        <div className="panel-body">
          <ErrorState
            error={result.error}
            retry={() => void result.refetch()}
          />
        </div>
      ) : (
        <>
          {result.data.items.length ? (
            <div className="findings-list">
              {result.data.items.map((entry) => (
                <FindingRow
                  key={`${entry.finding.coordinate.ecosystem}:${entry.finding.coordinate.name}:${entry.finding.coordinate.version}:${entry.finding.advisory_id}`}
                  entry={entry}
                  advisories={result.data.advisories}
                />
              ))}
            </div>
          ) : (
            <Empty
              title={filtered ? 'No matching findings' : 'No findings recorded'}
            >
              <p>
                {filtered
                  ? 'Try a different package or adjust the filters.'
                  : 'Review the scan coverage and diagnostics for the limits of this result.'}
              </p>
              {filtered && (
                <button
                  className="button secondary small"
                  type="button"
                  onClick={reset}
                >
                  Clear filters
                </button>
              )}
            </Empty>
          )}
          <Pager page={result.data} label="Findings" onChange={setPage} />
        </>
      )}
    </section>
  )
}
