import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  ArrowRight,
  Box,
  CircleCheck,
  Plus,
  Radar,
  ShieldAlert,
  type LucideIcon,
} from 'lucide-react'
import { lazy, Suspense } from 'react'
import { Link } from 'react-router-dom'
import { api, pending, type Provenance, type Scan } from './api'
import { displayNumber, scanName, scanRoute, severities } from './presentation'
import {
  Busy,
  Empty,
  ErrorState,
  PageTitle,
  PanelHeader,
  ScanTable,
  SourceBadge,
  SourceControl,
  Status,
  SeverityBadge,
} from './ui'

const RiskChart = lazy(() => import('./risk-chart'))

export interface SourceProps {
  source: Provenance
  changeSource: (source: Provenance) => void
}

function Metric({
  name,
  icon: Icon,
  value,
  unit,
  note,
}: {
  name: string
  icon: LucideIcon
  value?: number | null
  unit?: string
  note: string
}) {
  return (
    <div className="metric panel">
      <div className="metric-top">
        <span>{name}</span>
        <Icon size={17} aria-hidden="true" />
      </div>
      <div className="metric-value">
        {displayNumber(value)}
        {value != null && unit && <small>{unit}</small>}
      </div>
      <p>{note}</p>
    </div>
  )
}

function RiskSummary({ scan }: { scan: Scan | null }) {
  const value = scan?.risk_index
  const highest =
    severities.find((level) => (scan?.severity_counts?.[level] ?? 0) > 0) ??
    'none'
  const caption =
    value == null
      ? 'Score unavailable'
      : value === 100
        ? 'Scoring cap reached'
        : 'Weighted advisory evidence'
  return (
    <section className={`metric panel risk-summary severity-${highest}`}>
      <div className="metric-top">
        <span title="Revision 1 adds 20 per critical, 10 per high, 4 per medium and 1 per low finding. The total is capped at 100.">
          Risk index
        </span>
        <Activity size={18} aria-hidden="true" />
      </div>
      <div className="risk-reading">
        <div className="metric-value">
          {displayNumber(value)}
          {value != null && <small>/ 100</small>}
        </div>
        {value != null && highest !== 'none' && (
          <SeverityBadge value={highest} />
        )}
      </div>
      {value != null && (
        <div
          className="risk-meter"
          role="meter"
          aria-label="DepScope risk index"
          aria-valuemin={0}
          aria-valuemax={100}
          aria-valuenow={value}
        >
          <span style={{ width: `${value}%` }} />
        </div>
      )}
      <p>
        {caption}
        {value === 100 && ' · read the severity counts for detail'}
      </p>
    </section>
  )
}

function Breakdown({ scan }: { scan: Scan }) {
  const groups = useQuery({
    queryKey: ['overview-packages', scan.id],
    queryFn: ({ signal }) =>
      api.packages(scan.id, { sort: 'findings', page_size: 5 }, signal),
    enabled: Boolean(scan.coverage?.coordinates_with_findings),
  })
  const coverage = scan.coverage
  const fixTotal = groups.data?.fixable_count ?? 0
  const findingTotal = groups.data?.finding_count ?? 0
  return (
    <div className="analytics-grid insight-grid">
      <section className="panel">
        <PanelHeader
          title="Most affected dependencies"
          description="Package versions ranked by saved finding count"
        />
        {!coverage?.coordinates_with_findings ? (
          <Empty title="No affected versions recorded" />
        ) : groups.isPending ? (
          <Busy />
        ) : groups.isError ? (
          <ErrorState
            error={groups.error}
            retry={() => void groups.refetch()}
          />
        ) : (
          <ul className="top-packages">
            {groups.data.items.map((item) => (
              <li key={JSON.stringify(item.coordinate)}>
                <div>
                  <strong>{item.coordinate.name}</strong>
                  <small>
                    {item.coordinate.ecosystem} · {item.coordinate.version}
                  </small>
                </div>
                <SeverityBadge value={item.highest_severity} />
                <strong>{item.finding_count}</strong>
              </li>
            ))}
          </ul>
        )}
      </section>
      <section className="panel">
        <PanelHeader
          title="Coverage & fix evidence"
          action={
            <Link
              className="button secondary small"
              to={`/remediation?scan=${encodeURIComponent(scan.id)}&source=${scan.provenance}`}
            >
              Remediation
              <ArrowRight size={14} aria-hidden="true" />
            </Link>
          }
        />
        <div className="panel-body overview-coverage">
          <div>
            <span>Fully assessed</span>
            <strong>
              {coverage
                ? `${coverage.assessed_coordinates} / ${coverage.exact_coordinates}`
                : 'Unavailable'}
            </strong>
          </div>
          <div>
            <span>Unresolved entries</span>
            <strong>{displayNumber(coverage?.unresolved_occurrences)}</strong>
          </div>
          <div>
            <span>Findings with a verified fix</span>
            <strong>
              {groups.data || coverage?.coordinates_with_findings === 0
                ? `${fixTotal} / ${findingTotal}`
                : groups.isError
                  ? 'Unavailable'
                  : 'Loading…'}
            </strong>
          </div>
        </div>
      </section>
    </div>
  )
}

function SeverityProfile({ scan }: { scan: Scan | null }) {
  const counts = scan?.severity_counts
  if (!counts)
    return (
      <Empty title="No severity data yet">
        <p>Severity counts appear after a scan produces results.</p>
      </Empty>
    )
  const total = Object.values(counts).reduce((sum, value) => sum + value, 0)
  return (
    <div className="severity-profile">
      <div className="profile-total">
        <strong>{total}</strong>
        <span>
          {total === 1 ? 'finding' : 'findings'} across all severities
        </span>
      </div>
      <ul>
        {severities.map((severity) => {
          const count = counts[severity] ?? 0
          return (
            <li key={severity} className={`severity-${severity}`}>
              <span className="severity-name">
                <span className="indicator" />
                {severity}
              </span>
              <span className="bar-track" aria-hidden="true">
                <span
                  style={{ width: `${total ? (100 * count) / total : 0}%` }}
                />
              </span>
              <strong>{count}</strong>
            </li>
          )
        })}
      </ul>
    </div>
  )
}

export function OverviewPage({ source, changeSource }: SourceProps) {
  const result = useQuery({
    queryKey: ['overview', source],
    queryFn: ({ signal }) => api.overview(source, signal),
    refetchInterval: ({ state }) =>
      state.data?.recent_scans.some((scan) => pending(scan.status))
        ? 1500
        : false,
  })
  const latest = result.data?.latest_result ?? null
  const coverage = latest?.coverage
  const recent = result.data?.recent_scans ?? []
  const scores = result.data?.risk_trend ?? []
  const offline = source === 'offline_fixture'
  const trend = offline
    ? latest?.sample_id
      ? scores.filter(
          (scan) =>
            scan.sample_id === latest.sample_id &&
            scan.scoring_revision === latest.scoring_revision,
        )
      : []
    : scores
  const plottable = trend.filter((scan) => scan.risk_index != null)
  const latestAttempt = recent[0]

  return (
    <>
      <PageTitle
        title="Security overview"
        description="Review dependency exposure and the evidence behind your scans."
        action={
          <Link className="button primary" to="/scans/new">
            <Plus size={17} aria-hidden="true" />
            New scan
          </Link>
        }
      />
      <div className="workspace-toolbar">
        <SourceControl value={source} onChange={changeSource} />
        <span className="toolbar-note">
          <Radar size={15} aria-hidden="true" />
          {source === 'offline_fixture'
            ? 'Bundled sample data · no network lookups'
            : 'Advisory data from OSV'}
        </span>
      </div>
      {result.isPending ? (
        <div className="panel">
          <Busy label="Loading overview" />
        </div>
      ) : result.isError ? (
        <ErrorState error={result.error} retry={() => void result.refetch()} />
      ) : (
        <>
          <div className="metrics" aria-label="Latest scan metrics">
            <RiskSummary scan={latest} />
            <Metric
              name="Exact versions"
              icon={Box}
              value={coverage?.exact_coordinates}
              note={
                coverage
                  ? `${coverage.unresolved_occurrences} unresolved entries`
                  : 'Normalized package coordinates'
              }
            />
            <Metric
              name="Affected versions"
              icon={ShieldAlert}
              value={coverage?.coordinates_with_findings}
              note="Exact versions with findings"
            />
            <Metric
              name="Fully assessed"
              icon={CircleCheck}
              value={coverage?.assessed_coordinates}
              note={
                coverage
                  ? `${coverage.partial_coordinates} partial · ${coverage.failed_coordinates} failed`
                  : 'Completed advisory lookups'
              }
            />
          </div>
          {latest && (
            <div className="snapshot-line">
              <span>
                Metrics from{' '}
                <Link to={scanRoute(latest.id)}>{scanName(latest)}</Link>
              </span>
              <Status value={latest.status} />
              <SourceBadge value={latest.provenance} />
              {latestAttempt?.status === 'failed' &&
                latestAttempt.id !== latest.id && (
                  <Link to={scanRoute(latestAttempt.id)}>
                    Review latest failed scan
                  </Link>
                )}
            </div>
          )}
          <div className="analytics-grid">
            <section className="panel chart-panel">
              <PanelHeader
                title={
                  offline ? 'Sample risk history' : 'Saved live risk scores'
                }
                description={
                  offline
                    ? latest
                      ? `Recent runs of ${scanName(latest)} under the same scoring revision`
                      : 'Repeated scans of the same bundled sample'
                    : 'Each point represents an independent scan. Project targets are unassigned.'
                }
              />
              <div className="panel-body">
                {plottable.length >= 2 ? (
                  <Suspense fallback={<Busy label="Loading risk trend" />}>
                    <RiskChart scans={trend} connected={offline} />
                  </Suspense>
                ) : (
                  <Empty
                    title={
                      plottable.length === 1
                        ? 'One recorded score'
                        : 'No scores available'
                    }
                  >
                    <p>
                      {plottable.length === 1
                        ? `The saved score is ${plottable[0].risk_index} / 100. At least two scores are needed for the chart.`
                        : 'Scans with assessed dependencies can contribute recorded scores.'}
                    </p>
                  </Empty>
                )}
              </div>
            </section>
            <section className="panel">
              <PanelHeader
                title="Severity profile"
                description="Findings in the latest available result"
              />
              <div className="panel-body">
                <SeverityProfile scan={latest} />
              </div>
            </section>
          </div>
          {latest && <Breakdown scan={latest} />}
          <section className="panel history-panel">
            <PanelHeader
              title="Recent scans"
              description={
                source === 'offline_fixture'
                  ? 'Saved sample runs from this workspace'
                  : 'Saved live runs from this workspace'
              }
              action={
                <Link className="button secondary small" to="/history">
                  Scan history
                  <ArrowRight size={15} aria-hidden="true" />
                </Link>
              }
            />
            {recent.length ? (
              <ScanTable scans={recent.slice(0, 5)} />
            ) : (
              <Empty
                title={
                  source === 'offline_fixture'
                    ? 'No sample scans yet'
                    : 'No live scans yet'
                }
              >
                <p>Submit a manifest or run a bundled sample to begin.</p>
                <Link className="button secondary small" to="/scans/new">
                  {source === 'offline_fixture'
                    ? 'Choose a sample'
                    : 'Start a scan'}
                  <ArrowRight size={15} aria-hidden="true" />
                </Link>
              </Empty>
            )}
          </section>
        </>
      )}
    </>
  )
}
