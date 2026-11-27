import {
  AlertCircle,
  ArrowDownRight,
  ArrowRight,
  ChevronLeft,
  ChevronRight,
  LoaderCircle,
} from 'lucide-react'
import type { ReactNode } from 'react'
import { Link } from 'react-router-dom'
import {
  ApiError,
  type Page,
  type Provenance,
  type Scan,
  type ScanStatus,
  type Severity,
} from './api'
import {
  dateLabel,
  displayNumber,
  formatNames,
  scanName,
  scanRoute,
} from './presentation'

export function PageTitle({
  title,
  description,
  action,
}: {
  title: string
  description: string
  action?: ReactNode
}) {
  return (
    <header className="page-title">
      <div>
        <h1>{title}</h1>
        <p className="page-description">{description}</p>
      </div>
      {action}
    </header>
  )
}

export function PanelHeader({
  title,
  description,
  action,
}: {
  title: string
  description?: string
  action?: ReactNode
}) {
  return (
    <div className="panel-header">
      <div>
        <h2>{title}</h2>
        {description && <p>{description}</p>}
      </div>
      {action}
    </div>
  )
}

export function Status({ value }: { value: ScanStatus }) {
  return (
    <span className={`badge status-${value}`}>
      <span className="indicator" />
      {value}
    </span>
  )
}

export function SeverityBadge({ value }: { value: Severity }) {
  return (
    <span className={`badge severity-${value}`}>
      <span className="indicator" />
      {value}
    </span>
  )
}

export function SourceBadge({ value }: { value: Provenance }) {
  return (
    <span className={`badge source-${value}`}>
      {value === 'offline_fixture' ? 'Offline fixture' : 'Live OSV'}
    </span>
  )
}

export function SourceControl({
  value,
  onChange,
}: {
  value: Provenance
  onChange: (value: Provenance) => void
}) {
  return (
    <div className="segmented" role="group" aria-label="Scan source">
      <button
        type="button"
        aria-pressed={value === 'offline_fixture'}
        onClick={() => onChange('offline_fixture')}
      >
        Offline demos
      </button>
      <button
        type="button"
        aria-pressed={value === 'live_osv'}
        onClick={() => onChange('live_osv')}
      >
        Live OSV
      </button>
    </div>
  )
}

export function Busy({ label = 'Loading scan data' }: { label?: string }) {
  return (
    <div className="state state-loading" role="status">
      <LoaderCircle className="spin" aria-hidden="true" />
      {label}
    </div>
  )
}

export function Empty({
  title,
  children,
}: {
  title: string
  children?: ReactNode
}) {
  return (
    <div className="state">
      <span className="state-icon">
        <ArrowDownRight size={21} aria-hidden="true" />
      </span>
      <h3>{title}</h3>
      {children}
    </div>
  )
}

export function ErrorState({
  error,
  retry,
}: {
  error: Error
  retry?: () => void
}) {
  return (
    <div className="notice notice-error" role="alert">
      <AlertCircle size={19} aria-hidden="true" />
      <div>
        <strong>{error.message}</strong>
        {error instanceof ApiError && error.retryAfter && (
          <p>
            Retry after {error.retryAfter}{' '}
            {Number(error.retryAfter) === 1 ? 'second' : 'seconds'}.
          </p>
        )}
      </div>
      {retry && (
        <button
          className="button secondary small"
          type="button"
          onClick={retry}
        >
          Retry
        </button>
      )}
    </div>
  )
}

export function Pager({
  page,
  label,
  onChange,
}: {
  page: Page<unknown>
  label: string
  onChange: (page: number) => void
}) {
  const pages = Math.ceil(page.total / page.page_size)
  if (pages <= 1) return null
  return (
    <nav className="pager" aria-label={`${label} pagination`}>
      <span>
        Page {page.page} of {pages}
      </span>
      <button
        className="icon-button"
        type="button"
        aria-label={`Previous ${label.toLowerCase()} page`}
        disabled={page.page <= 1}
        onClick={() => onChange(page.page - 1)}
      >
        <ChevronLeft size={16} aria-hidden="true" />
      </button>
      <button
        className="icon-button"
        type="button"
        aria-label={`Next ${label.toLowerCase()} page`}
        disabled={page.page >= pages}
        onClick={() => onChange(page.page + 1)}
      >
        <ChevronRight size={16} aria-hidden="true" />
      </button>
    </nav>
  )
}

export function ScanTable({ scans }: { scans: Scan[] }) {
  return (
    <div
      className="table-scroll scan-table"
      tabIndex={0}
      role="region"
      aria-label="Scan records"
    >
      <table>
        <thead>
          <tr>
            <th scope="col">Scan</th>
            <th scope="col" className="scan-table-wide">
              Source
            </th>
            <th scope="col">Status</th>
            <th scope="col" className="scan-table-wide">
              Assessed
            </th>
            <th scope="col">Risk index</th>
            <th scope="col" className="scan-table-wide">
              Submitted
            </th>
          </tr>
        </thead>
        <tbody>
          {scans.map((scan) => (
            <tr key={scan.id}>
              <th scope="row">
                <Link className="row-link" to={scanRoute(scan.id)}>
                  {scanName(scan)}
                  <ArrowRight size={14} aria-hidden="true" />
                </Link>
                <span className="table-note">
                  {formatNames[scan.format]} · {scan.id.slice(0, 8)}
                </span>
                <span className="table-note scan-table-compact">
                  {dateLabel(scan.requested_at)}
                </span>
              </th>
              <td className="scan-table-wide">
                <SourceBadge value={scan.provenance} />
              </td>
              <td>
                <Status value={scan.status} />
                <span className="table-note scan-table-compact">
                  {scan.provenance === 'offline_fixture'
                    ? 'Offline fixture'
                    : 'Live OSV'}
                  {scan.coverage &&
                    ` · ${scan.coverage.assessed_coordinates}/${scan.coverage.exact_coordinates} assessed`}
                </span>
              </td>
              <td className="numeric scan-table-wide">
                {scan.coverage
                  ? `${scan.coverage.assessed_coordinates} / ${scan.coverage.exact_coordinates}`
                  : '—'}
              </td>
              <td className="numeric">{displayNumber(scan.risk_index)}</td>
              <td className="scan-table-wide">
                {dateLabel(scan.requested_at)}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}
