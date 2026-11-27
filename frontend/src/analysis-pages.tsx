import { useQuery } from '@tanstack/react-query'
import { ArrowRight, GitCompareArrows } from 'lucide-react'
import { useState } from 'react'
import { Link, useSearchParams } from 'react-router-dom'
import { api, pending, type Comparison, type Scan } from './api'
import { PackageRow } from './findings'
import type { SourceProps } from './overview'
import {
  dateLabel,
  displayNumber,
  scanName,
  scanRoute,
  wordLabel,
} from './presentation'
import {
  Busy,
  Empty,
  ErrorState,
  PageTitle,
  Pager,
  PanelHeader,
  SeverityBadge,
  SourceBadge,
  SourceControl,
  Status,
} from './ui'

function useSavedScans(source: SourceProps['source'], page: number) {
  return useQuery({
    queryKey: ['analysis-scans', source, page],
    queryFn: ({ signal }) => api.scans({ provenance: source, page }, signal),
  })
}

function chosenSource(
  params: URLSearchParams,
  fallback: SourceProps['source'],
) {
  const value = params.get('source')
  return value === 'live_osv' || value === 'offline_fixture' ? value : fallback
}

function ScanPicker({
  label,
  selected,
  records,
  onChange,
}: {
  label: string
  selected: string
  records: Scan[]
  onChange: (id: string) => void
}) {
  return (
    <label>
      {label}
      <select
        value={selected}
        onChange={(event) => onChange(event.target.value)}
      >
        <option value="">Choose a scan</option>
        {selected && !records.some((scan) => scan.id === selected) && (
          <option value={selected}>
            Selected scan · {selected.slice(0, 8)}
          </option>
        )}
        {records.map((scan) => (
          <option value={scan.id} key={scan.id}>
            {scanName(scan)} · {dateLabel(scan.requested_at)} ·{' '}
            {scan.id.slice(0, 8)}
          </option>
        ))}
      </select>
    </label>
  )
}

function ManualReview({ scanId }: { scanId: string }) {
  const [page, setPage] = useState(1)
  const result = useQuery({
    queryKey: ['manual-review', scanId, page],
    queryFn: ({ signal }) => api.review(scanId, page, signal),
  })
  return (
    <section className="panel">
      <PanelHeader
        title="Manual review"
        description="Entries without an exact assessable package version"
      />
      {result.isPending ? (
        <Busy />
      ) : result.isError ? (
        <ErrorState error={result.error} retry={() => void result.refetch()} />
      ) : result.data.items.length ? (
        <>
          <div
            className="table-scroll"
            tabIndex={0}
            role="region"
            aria-label="Entries needing manual review"
          >
            <table>
              <thead>
                <tr>
                  <th scope="col">Dependency</th>
                  <th scope="col">Entry</th>
                  <th scope="col">Review reason</th>
                </tr>
              </thead>
              <tbody>
                {result.data.items.map((item, index) => (
                  <tr key={index}>
                    <th scope="row">
                      {item.name ?? 'Unidentified entry'}
                      <span className="table-note">
                        {item.ecosystem} {item.constraint}
                      </span>
                    </th>
                    <td>
                      {item.dependency_path ??
                        (item.line != null
                          ? `Line ${item.line}`
                          : `Entry ${item.entry_number ?? '—'}`)}
                    </td>
                    <td>{wordLabel(item.reason ?? item.resolution)}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={result.data} label="Manual review" onChange={setPage} />
        </>
      ) : (
        <Empty title="No unresolved entries" />
      )}
    </section>
  )
}

function RemediationResults({ scanId }: { scanId: string }) {
  const [page, setPage] = useState(1)
  const [filter, setFilter] = useState('')
  const scan = useQuery({
    queryKey: ['scan', scanId, 1],
    queryFn: ({ signal }) => api.detail(scanId, 1, signal),
  })
  const groups = useQuery({
    queryKey: ['remediation-packages', scanId, page, filter],
    queryFn: ({ signal }) =>
      api.packages(
        scanId,
        { page, sort: 'priority', fix_available: filter },
        signal,
      ),
    enabled: Boolean(scan.data?.scan.coverage),
  })
  const totals = useQuery({
    queryKey: ['remediation-totals', scanId],
    queryFn: ({ signal }) => api.packages(scanId, { page_size: 1 }, signal),
    enabled: Boolean(scan.data?.scan.coverage),
  })
  if (scan.isPending) return <Busy label="Loading scan coverage" />
  if (scan.isError)
    return <ErrorState error={scan.error} retry={() => void scan.refetch()} />
  const record = scan.data.scan
  if (!record.coverage)
    return (
      <Empty title="No saved remediation evidence">
        <Link className="button secondary" to={scanRoute(scanId)}>
          Review the scan status
        </Link>
      </Empty>
    )
  const incomplete =
    record.coverage.partial_coordinates + record.coverage.failed_coordinates
  return (
    <>
      <div className="result-labels">
        <SourceBadge value={record.provenance} />
        <Status value={record.status} />
        {incomplete > 0 && <span>{incomplete} incomplete lookups</span>}
        <Link className="row-link" to={scanRoute(scanId)}>
          Open scan results <ArrowRight size={14} />
        </Link>
      </div>
      <section className="panel analysis-panel">
        <PanelHeader
          title="Remediation coverage"
          description="Findings with at least one applicable advisory-specific fix"
        />
        {totals.isPending ? (
          <Busy />
        ) : totals.isError ? (
          <ErrorState
            error={totals.error}
            retry={() => void totals.refetch()}
          />
        ) : (
          <div className="analysis-metrics">
            <div>
              <span>Fix evidence available</span>
              <strong>{totals.data.fixable_count}</strong>
            </div>
            <div>
              <span>Fix review needed</span>
              <strong>
                {totals.data.finding_count - totals.data.fixable_count}
              </strong>
            </div>
            <div>
              <span>Unresolved entries</span>
              <strong>{record.coverage.unresolved_occurrences}</strong>
            </div>
          </div>
        )}
      </section>
      <section className="panel">
        <PanelHeader
          title="Prioritized packages"
          description="Highest recorded severity first. Findings with an applicable fix come first at the same severity."
          action={
            <label>
              Fix evidence
              <select
                value={filter}
                onChange={(event) => {
                  setFilter(event.target.value)
                  setPage(1)
                }}
              >
                <option value="">All findings</option>
                <option value="true">Recorded fix</option>
                <option value="false">Needs fix review</option>
              </select>
            </label>
          }
        />
        {groups.isPending ? (
          <Busy />
        ) : groups.isError ? (
          <ErrorState
            error={groups.error}
            retry={() => void groups.refetch()}
          />
        ) : (
          <>
            {groups.data.items.length ? (
              groups.data.items.map((item) => (
                <PackageRow
                  scanId={scanId}
                  item={item}
                  key={JSON.stringify(item.coordinate)}
                  filters={{ fix_available: filter }}
                  remediation
                />
              ))
            ) : (
              <Empty title="No matching packages" />
            )}
            <Pager
              page={groups.data}
              label="Prioritized packages"
              onChange={setPage}
            />
          </>
        )}
      </section>
      <ManualReview scanId={scanId} />
    </>
  )
}

export function RemediationPage({ source, changeSource }: SourceProps) {
  const [params, setParams] = useSearchParams()
  const [page, setPage] = useState(1)
  const scope = chosenSource(params, source)
  const saved = useSavedScans(scope, page)
  const available =
    saved.data?.items.filter((scan) => !pending(scan.status)) ?? []
  const id = params.get('scan') || available[0]?.id || ''
  return (
    <>
      <PageTitle
        title="Remediation center"
        description="Prioritize affected packages, review fix evidence, and check candidate versions against saved lookups."
      />
      <div className="workspace-toolbar">
        <SourceControl
          value={scope}
          onChange={(value) => {
            setPage(1)
            setParams({})
            changeSource(value)
          }}
        />
      </div>
      <section className="panel analysis-panel">
        <PanelHeader title="Saved scan" />
        <div className="panel-body">
          <ScanPicker
            label="Scan to review"
            selected={id}
            records={available}
            onChange={(scan) => setParams({ scan, source: scope })}
          />
        </div>
        {saved.isError && (
          <ErrorState error={saved.error} retry={() => void saved.refetch()} />
        )}
        {saved.data && (
          <Pager
            page={saved.data}
            label="Remediation scans"
            onChange={setPage}
          />
        )}
      </section>
      {id ? (
        <RemediationResults key={id} scanId={id} />
      ) : saved.isPending ? (
        <Busy />
      ) : (
        <Empty title="No saved scans for this source" />
      )}
    </>
  )
}

const findingLabels = {
  newly_detected: 'Newly detected',
  no_longer_detected: 'No longer detected',
  unchanged: 'Unchanged findings',
} as const
type FindingKind = keyof typeof findingLabels
const contexts = {
  observed: 'Saved evidence',
  incomplete_coverage: 'Incomplete coverage',
  package_absent: 'Package absent from other input',
  versions_changed: 'Exact versions differ',
}
const pageSize = 20

function FindingChanges({ comparison }: { comparison: Comparison }) {
  const [kind, setKind] = useState<FindingKind>('newly_detected')
  const [page, setPage] = useState(1)
  const items = comparison.findings.filter((item) => item.kind === kind)
  return (
    <section className="panel">
      <PanelHeader title="Changes in advisory findings" />
      <div className="panel-body">
        <div
          className="segmented comparison-tabs"
          role="group"
          aria-label="Finding changes"
        >
          {(Object.keys(findingLabels) as FindingKind[]).map((key) => (
            <button
              type="button"
              key={key}
              aria-pressed={kind === key}
              onClick={() => {
                setKind(key)
                setPage(1)
              }}
            >
              <span>{findingLabels[key]}</span>
              <strong>
                {comparison.findings.filter((item) => item.kind === key).length}
              </strong>
            </button>
          ))}
        </div>
      </div>
      {items.length ? (
        <div
          className="table-scroll"
          tabIndex={0}
          role="region"
          aria-label="Compared findings"
        >
          <table>
            <thead>
              <tr>
                <th scope="col">Package and advisory</th>
                <th scope="col">Baseline</th>
                <th scope="col">Target</th>
                <th scope="col">Context</th>
              </tr>
            </thead>
            <tbody>
              {items
                .slice((page - 1) * pageSize, page * pageSize)
                .map((item) => (
                  <tr
                    key={`${item.package.ecosystem}:${item.package.name}:${item.advisory_ids.join(',')}`}
                  >
                    <th scope="row">
                      {item.package.name} · {item.package.ecosystem}
                      <span className="table-note">
                        {item.advisory_ids.join(', ')}
                      </span>
                    </th>
                    <td>
                      {item.before_versions.join(', ') || '—'}
                      {item.before_severity && (
                        <div>
                          <SeverityBadge value={item.before_severity} />
                        </div>
                      )}
                    </td>
                    <td>
                      {item.after_versions.join(', ') || '—'}
                      {item.after_severity && (
                        <div>
                          <SeverityBadge value={item.after_severity} />
                        </div>
                      )}
                    </td>
                    <td>{contexts[item.context]}</td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty title="No findings in this category" />
      )}
      <Pager
        page={{ items: [], page_size: pageSize, page, total: items.length }}
        label="Finding changes"
        onChange={setPage}
      />
    </section>
  )
}

function DependencyChanges({ items }: { items: Comparison['dependencies'] }) {
  const [page, setPage] = useState(1)
  return (
    <section className="panel">
      <PanelHeader
        title="Dependency changes"
        description={`${items.length} package identities differ`}
      />
      {items.length ? (
        <div
          className="table-scroll"
          tabIndex={0}
          role="region"
          aria-label="Compared dependencies"
        >
          <table>
            <thead>
              <tr>
                <th scope="col">Dependency</th>
                <th scope="col">Change</th>
                <th scope="col">Baseline</th>
                <th scope="col">Target</th>
              </tr>
            </thead>
            <tbody>
              {items
                .slice((page - 1) * pageSize, page * pageSize)
                .map((item) => (
                  <tr key={`${item.package.ecosystem}:${item.package.name}`}>
                    <th scope="row">
                      {item.package.name} · {item.package.ecosystem}
                    </th>
                    <td>{wordLabel(item.kind)}</td>
                    <td>
                      {item.before_versions.join(', ') || '—'}
                      {item.before_unresolved > 0 && (
                        <span className="table-note">
                          {item.before_unresolved} unresolved
                        </span>
                      )}
                    </td>
                    <td>
                      {item.after_versions.join(', ') || '—'}
                      {item.after_unresolved > 0 && (
                        <span className="table-note">
                          {item.after_unresolved} unresolved
                        </span>
                      )}
                    </td>
                  </tr>
                ))}
            </tbody>
          </table>
        </div>
      ) : (
        <Empty title="No dependency changes in the saved inputs" />
      )}
      <Pager
        page={{ items: [], page_size: pageSize, page, total: items.length }}
        label="Dependency changes"
        onChange={setPage}
      />
    </section>
  )
}

function ComparisonResult({ comparison }: { comparison: Comparison }) {
  return (
    <>
      <section className="panel">
        <PanelHeader
          title="Scan scope and completeness"
          description="A difference in saved results does not establish that an advisory was remediated."
        />
        <div className="analysis-metrics">
          {[comparison.baseline, comparison.target].map((scan, index) => (
            <div key={scan.id}>
              <span>{index === 0 ? 'Baseline' : 'Target'}</span>
              <Link to={scanRoute(scan.id)}>{scanName(scan)}</Link>
              <Status value={scan.status} />
              <SourceBadge value={scan.provenance} />
              <small>
                {scan.coverage
                  ? `${scan.coverage.assessed_coordinates}/${scan.coverage.exact_coordinates} assessed · ${scan.coverage.unresolved_occurrences} unresolved · ${scan.coverage.partial_coordinates + scan.coverage.failed_coordinates} incomplete`
                  : 'Coverage unavailable'}
              </small>
              <small>Risk index {displayNumber(scan.risk_index)}</small>
            </div>
          ))}
          <div>
            <span>Risk index difference</span>
            <strong>
              {comparison.risk_delta == null
                ? '—'
                : `${comparison.risk_delta > 0 ? '+' : ''}${comparison.risk_delta}`}
            </strong>
            <small>Target minus baseline</small>
          </div>
        </div>
      </section>
      <FindingChanges comparison={comparison} />
      <DependencyChanges items={comparison.dependencies} />
    </>
  )
}

export function ComparePage({ source, changeSource }: SourceProps) {
  const [params, setParams] = useSearchParams()
  const [page, setPage] = useState(1)
  const baseline = params.get('baseline') ?? ''
  const target = params.get('target') ?? ''
  const scope = chosenSource(params, source)
  const saved = useSavedScans(scope, page)
  const available =
    saved.data?.items.filter(
      (scan) => scan.coverage && !pending(scan.status),
    ) ?? []
  const result = useQuery({
    queryKey: ['comparison', baseline, target],
    queryFn: ({ signal }) => api.compare(baseline, target, signal),
    enabled: Boolean(baseline && target && baseline !== target),
  })
  return (
    <>
      <PageTitle
        title="Scan comparison"
        description="Compare two saved manifests and see changes in packages, advisory findings, severity, and coverage."
      />
      <div className="workspace-toolbar">
        <SourceControl
          value={scope}
          onChange={(value) => {
            setPage(1)
            setParams({})
            changeSource(value)
          }}
        />
        <span className="toolbar-note">
          <GitCompareArrows size={15} />
          Choose scans for the inputs you want to compare.
        </span>
      </div>
      <section className="panel analysis-panel">
        <PanelHeader title="Select the comparison scope" />
        <div className="panel-body settings-grid">
          <ScanPicker
            label="Baseline scan"
            records={available}
            selected={baseline}
            onChange={(scan) =>
              setParams({ baseline: scan, target, source: scope })
            }
          />
          <ScanPicker
            label="Target scan"
            records={available}
            selected={target}
            onChange={(scan) =>
              setParams({ baseline, target: scan, source: scope })
            }
          />
        </div>
        {saved.isError && (
          <ErrorState error={saved.error} retry={() => void saved.refetch()} />
        )}
        {saved.data && (
          <Pager
            page={saved.data}
            label="Comparison scans"
            onChange={setPage}
          />
        )}
      </section>
      {!baseline || !target ? (
        <Empty title="Select a baseline and a target" />
      ) : baseline === target ? (
        <p className="notice notice-warning" role="alert">
          Choose two different saved scans.
        </p>
      ) : result.isPending ? (
        <Busy label="Comparing saved scans" />
      ) : result.isError ? (
        <ErrorState error={result.error} retry={() => void result.refetch()} />
      ) : (
        <ComparisonResult
          key={`${baseline}:${target}`}
          comparison={result.data}
        />
      )}
    </>
  )
}
