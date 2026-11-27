import { useQuery } from '@tanstack/react-query'
import { Plus } from 'lucide-react'
import { useState } from 'react'
import { Link } from 'react-router-dom'
import { api, pending } from './api'
import type { SourceProps } from './overview'
import {
  Busy,
  Empty,
  ErrorState,
  PageTitle,
  Pager,
  PanelHeader,
  ScanTable,
  SourceControl,
} from './ui'

export function HistoryPage({ source, changeSource }: SourceProps) {
  const [status, setStatus] = useState('')
  const [format, setFormat] = useState('')
  const [sort, setSort] = useState('newest')
  const [page, setPage] = useState(1)
  const parameters = { page, provenance: source, status, format, sort }
  const scans = useQuery({
    queryKey: ['scans', parameters],
    queryFn: ({ signal }) => api.scans(parameters, signal),
    refetchInterval: ({ state }) =>
      state.data?.items.some((scan) => pending(scan.status)) ? 1500 : false,
  })

  return (
    <>
      <PageTitle
        title="Scan history"
        description="Open a saved scan to review its original coverage, findings, and advisory evidence."
        action={
          <Link className="button primary" to="/scans/new">
            <Plus size={17} aria-hidden="true" />
            New scan
          </Link>
        }
      />
      <div className="workspace-toolbar">
        <SourceControl
          value={source}
          onChange={(value) => {
            setPage(1)
            changeSource(value)
          }}
        />
      </div>
      <section className="panel">
        <PanelHeader
          title="Scan records"
          description={
            scans.data ? `${scans.data.total} matching scans` : undefined
          }
        />
        <div className="filters history-filters">
          <label>
            Status
            <select
              value={status}
              onChange={(e) => {
                setStatus(e.target.value)
                setPage(1)
              }}
            >
              <option value="">Any status</option>
              {['queued', 'running', 'complete', 'partial', 'failed'].map(
                (value) => (
                  <option key={value}>{value}</option>
                ),
              )}
            </select>
          </label>
          <label>
            Format
            <select
              value={format}
              onChange={(e) => {
                setFormat(e.target.value)
                setPage(1)
              }}
            >
              <option value="">Any format</option>
              <option value="requirements">Python</option>
              <option value="npm-lock">npm</option>
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
              <option value="newest">Newest first</option>
              <option value="oldest">Oldest first</option>
              <option value="risk">Highest risk first</option>
            </select>
          </label>
        </div>
        {scans.isPending ? (
          <Busy label="Loading scan history" />
        ) : scans.isError ? (
          <div className="panel-body">
            <ErrorState
              error={scans.error}
              retry={() => void scans.refetch()}
            />
          </div>
        ) : (
          <>
            {scans.data.items.length ? (
              <ScanTable scans={scans.data.items} />
            ) : (
              <Empty title="No matching scans">
                <p>Change your filters or submit a new scan.</p>
              </Empty>
            )}
            <Pager page={scans.data} label="Scan history" onChange={setPage} />
          </>
        )}
      </section>
    </>
  )
}
