import { useQuery } from '@tanstack/react-query'
import { AlertTriangle, ArrowRight, Clock3 } from 'lucide-react'
import { useState } from 'react'
import { Link, useParams, useSearchParams } from 'react-router-dom'
import { api, pending, type Scan, type ScanDetail } from './api'
import { FindingsPanel } from './findings'
import type { SourceProps } from './overview'
import {
  dateLabel,
  displayNumber,
  failureMessage,
  scanName,
  wordLabel,
} from './presentation'
import {
  Busy,
  Empty,
  ErrorState,
  PageTitle,
  Pager,
  PanelHeader,
  SourceBadge,
  SourceControl,
  Status,
} from './ui'

function useScan(id: string, page = 1) {
  return useQuery({
    queryKey: ['scan', id, page],
    queryFn: ({ signal }) => api.detail(id, page, signal),
    enabled: Boolean(id),
    refetchInterval: ({ state }) =>
      pending(state.data?.scan.status) ? 1200 : false,
  })
}

function PendingScan({ scan }: { scan: Scan }) {
  return (
    <div className="notice notice-info" role="status">
      <Clock3 size={19} aria-hidden="true" />
      <div>
        <strong>
          {scan.status === 'queued'
            ? 'Waiting for the scan worker'
            : 'Analyzing the manifest'}
        </strong>
        <p>This view updates automatically while the scan is active.</p>
      </div>
    </div>
  )
}

function CoveragePanel({ scan }: { scan: Scan }) {
  const coverage = scan.coverage
  const stats = [
    ['Dependency entries', coverage?.occurrences],
    ['Unresolved entries', coverage?.unresolved_occurrences],
    ['Exact versions', coverage?.exact_coordinates],
    ['Fully assessed', coverage?.assessed_coordinates],
    [
      'Incomplete lookups',
      coverage && coverage.partial_coordinates + coverage.failed_coordinates,
    ],
    ['Affected coordinates', coverage?.coordinates_with_findings],
  ] as const
  return (
    <section className="panel coverage-panel">
      <PanelHeader
        title="Scan coverage"
        description="Scope and completeness of the saved result"
        action={
          <span className="score-tag">
            Risk index <strong>{displayNumber(scan.risk_index)}</strong>
          </span>
        }
      />
      <dl className="coverage-stats">
        {stats.map(([label, value]) => (
          <div key={label}>
            <dt>{label}</dt>
            <dd>{displayNumber(value)}</dd>
          </div>
        ))}
      </dl>
      {scan.limitations && (
        <ul className="coverage-notes">
          {scan.limitations.map((note) => (
            <li key={note}>{wordLabel(note)}</li>
          ))}
        </ul>
      )}
    </section>
  )
}

function DependencyPanel({
  detail,
  onPage,
}: {
  detail: ScanDetail
  onPage: (page: number) => void
}) {
  const page = detail.dependencies
  return (
    <section className="panel">
      <PanelHeader
        title="Dependency entries"
        description={`${page.total} entries in the normalized manifest`}
      />
      {page.items.length === 0 ? (
        <Empty title="No dependency entries" />
      ) : (
        <div
          className="table-scroll"
          tabIndex={0}
          role="region"
          aria-label="Dependency entries"
        >
          <table>
            <thead>
              <tr>
                <th scope="col">Package</th>
                <th scope="col">Version</th>
                <th scope="col">Resolution</th>
                <th scope="col">Location</th>
              </tr>
            </thead>
            <tbody>
              {page.items.map((item, index) => (
                <tr key={index}>
                  <th scope="row">
                    {item.name ?? 'Unidentified entry'}
                    <span className="table-note">
                      {item.ecosystem} · {item.directness}
                    </span>
                  </th>
                  <td className="numeric">
                    {item.coordinate?.version ?? item.constraint ?? '—'}
                  </td>
                  <td>
                    {wordLabel(item.resolution)}
                    {item.reason && (
                      <span className="table-note">
                        {wordLabel(item.reason)}
                      </span>
                    )}
                  </td>
                  <td className="path-cell">
                    {item.dependency_path ??
                      (item.line != null
                        ? `Line ${item.line}`
                        : `Entry ${item.entry_number ?? '—'}`)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Pager page={page} label="Dependency entries" onChange={onPage} />
    </section>
  )
}

function LookupPanel({
  detail,
  onPage,
}: {
  detail: ScanDetail
  onPage: (page: number) => void
}) {
  const page = detail.assessments
  return (
    <section className="panel">
      <PanelHeader
        title="Advisory lookups"
        description={`${page.total} normalized package coordinates`}
      />
      {page.items.length === 0 ? (
        <Empty title="No advisory lookups" />
      ) : (
        <div
          className="table-scroll"
          tabIndex={0}
          role="region"
          aria-label="Advisory lookups"
        >
          <table>
            <thead>
              <tr>
                <th scope="col">Package version</th>
                <th scope="col">Status</th>
                <th scope="col">Diagnostics</th>
              </tr>
            </thead>
            <tbody>
              {page.items.map((item) => (
                <tr
                  key={`${item.coordinate.ecosystem}:${item.coordinate.name}:${item.coordinate.version}`}
                >
                  <th scope="row">
                    {item.coordinate.name} @ {item.coordinate.version}
                    <span className="table-note">
                      {item.coordinate.ecosystem}
                    </span>
                  </th>
                  <td>
                    <Status value={item.status} />
                  </td>
                  <td>
                    {item.diagnostics.length
                      ? item.diagnostics.map(wordLabel).join(', ')
                      : '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
      <Pager page={page} label="Advisory lookups" onChange={onPage} />
    </section>
  )
}

type Section = 'Findings' | 'Dependencies' | 'Lookups'
const sections: Section[] = ['Findings', 'Dependencies', 'Lookups']

function ScanResult({ id }: { id: string }) {
  const [section, setSection] = useState<Section>('Findings')
  const [page, setPage] = useState(1)
  const result = useScan(id)
  const paged = useQuery({
    queryKey: ['scan', id, page],
    queryFn: ({ signal }) => api.detail(id, page, signal),
    enabled: page > 1,
  })
  const detail = page > 1 ? paged.data : result.data
  const scan = result.data?.scan
  return (
    <>
      <PageTitle
        title={scan ? scanName(scan) : 'Scan results'}
        description={
          scan
            ? `Submitted ${dateLabel(scan.requested_at)} · ${scan.id.slice(0, 8)}`
            : 'Review scan status and the saved report.'
        }
        action={
          <Link className="button secondary" to="/history">
            Scan history
            <ArrowRight size={16} aria-hidden="true" />
          </Link>
        }
      />
      {result.isPending ? (
        <div className="panel">
          <Busy label="Loading scan results" />
        </div>
      ) : result.isError ? (
        <ErrorState error={result.error} retry={() => void result.refetch()} />
      ) : (
        scan && (
          <>
            <div className="result-labels">
              <Status value={scan.status} />
              <SourceBadge value={scan.provenance} />
              {!pending(scan.status) && (
                <Link
                  className="button secondary small"
                  to={`/scans/${encodeURIComponent(id)}/report`}
                >
                  Security report
                </Link>
              )}
              {scan.coverage && (
                <Link
                  className="button secondary small"
                  to={`/remediation?scan=${encodeURIComponent(id)}&source=${scan.provenance}`}
                >
                  Review remediation
                </Link>
              )}
              {!pending(scan.status) && (
                <Link
                  className="button secondary small"
                  to={`/compare?baseline=${encodeURIComponent(id)}&source=${scan.provenance}`}
                >
                  Compare scan
                </Link>
              )}
            </div>
            {pending(scan.status) ? (
              <PendingScan scan={scan} />
            ) : (
              <>
                {scan.status === 'failed' && (
                  <div className="notice notice-error" role="alert">
                    <AlertTriangle size={19} aria-hidden="true" />
                    <div>
                      <strong>{failureMessage(scan.error_code)}</strong>
                      {scan.error_code && <p>{wordLabel(scan.error_code)}</p>}
                    </div>
                  </div>
                )}
                {scan.status === 'partial' && (
                  <div className="notice notice-warning" role="status">
                    <AlertTriangle size={19} aria-hidden="true" />
                    <div>
                      <strong>Some advisory checks could not finish.</strong>
                      <p>
                        The saved results show available evidence and lookup
                        diagnostics.
                      </p>
                    </div>
                  </div>
                )}
                {scan.coverage && (
                  <>
                    <CoveragePanel scan={scan} />
                    <div className="workspace-toolbar">
                      <div
                        className="segmented"
                        role="group"
                        aria-label="Result section"
                      >
                        {sections.map((item) => (
                          <button
                            key={item}
                            type="button"
                            aria-pressed={section === item}
                            onClick={() => {
                              setSection(item)
                              setPage(1)
                            }}
                          >
                            {item}
                          </button>
                        ))}
                      </div>
                      <Link
                        className="button secondary small"
                        to={`/explorer?scan=${encodeURIComponent(id)}`}
                      >
                        Open in explorer
                        <ArrowRight size={15} aria-hidden="true" />
                      </Link>
                    </div>
                    {section === 'Findings' ? (
                      <FindingsPanel scanId={id} />
                    ) : paged.isError && page > 1 ? (
                      <ErrorState
                        error={paged.error}
                        retry={() => void paged.refetch()}
                      />
                    ) : !detail ? (
                      <Busy />
                    ) : section === 'Dependencies' ? (
                      <DependencyPanel detail={detail} onPage={setPage} />
                    ) : (
                      <LookupPanel detail={detail} onPage={setPage} />
                    )}
                  </>
                )}
              </>
            )}
          </>
        )
      )}
    </>
  )
}

export function ResultsPage() {
  const { id } = useParams()
  return id ? <ScanResult key={id} id={id} /> : null
}

export function ExplorerPage({ source, changeSource }: SourceProps) {
  const [params, setParams] = useSearchParams()
  const [page, setPage] = useState(1)
  const scans = useQuery({
    queryKey: ['explorer-scans', source, page],
    queryFn: ({ signal }) => api.scans({ provenance: source, page }, signal),
  })
  const id = params.get('scan') || scans.data?.items[0]?.id || ''
  const selected = useScan(id)
  const scan = selected.data?.scan
  const available = scans.data?.items ?? []

  return (
    <>
      <PageTitle
        title="Vulnerability explorer"
        description="Search findings and trace severity, fixes, and affected versions to their advisory evidence."
      />
      <div className="workspace-toolbar">
        <SourceControl
          value={source}
          onChange={(value) => {
            setPage(1)
            setParams({})
            changeSource(value)
          }}
        />
      </div>
      {scans.isError && (
        <ErrorState error={scans.error} retry={() => void scans.refetch()} />
      )}
      <section className="panel explorer-picker">
        <PanelHeader title="Choose a scan" />
        {scans.isPending && !id ? (
          <Busy label="Loading scans" />
        ) : available.length || id ? (
          <div className="panel-body picker-row">
            <label>
              Saved scan
              <select
                value={id}
                onChange={(e) => setParams({ scan: e.target.value })}
              >
                {id && !available.some((item) => item.id === id) && (
                  <option value={id}>
                    {scan ? scanName(scan) : 'Selected scan'}
                  </option>
                )}
                {available.map((item) => (
                  <option key={item.id} value={item.id}>
                    {scanName(item)} · {dateLabel(item.requested_at)}
                  </option>
                ))}
              </select>
            </label>
            {scan && (
              <>
                <Status value={scan.status} />
                <SourceBadge value={scan.provenance} />
              </>
            )}
          </div>
        ) : (
          !scans.isError && (
            <Empty title="No scans available">
              <p>Choose the other scan source or start a new scan.</p>
              <Link className="button secondary small" to="/scans/new">
                New scan
              </Link>
            </Empty>
          )
        )}
        {scans.data && (
          <Pager page={scans.data} label="Available scans" onChange={setPage} />
        )}
      </section>
      {id &&
        (selected.isPending ? (
          <Busy label="Loading selected scan" />
        ) : selected.isError ? (
          <ErrorState
            error={selected.error}
            retry={() => void selected.refetch()}
          />
        ) : (
          scan &&
          (pending(scan.status) ? (
            <PendingScan scan={scan} />
          ) : scan.coverage ? (
            <FindingsPanel key={id} scanId={id} />
          ) : (
            <div className="notice notice-error" role="alert">
              {failureMessage(scan.error_code)}
            </div>
          ))
        ))}
    </>
  )
}
