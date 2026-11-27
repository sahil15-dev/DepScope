import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Download, Printer } from 'lucide-react'
import { Link, useParams } from 'react-router-dom'
import { api, type Report } from './api'
import {
  displayNumber,
  safeReference,
  scanName,
  scanRoute,
  severities,
  wordLabel,
} from './presentation'
import {
  Busy,
  ErrorState,
  PageTitle,
  SeverityBadge,
  SourceBadge,
  Status,
} from './ui'

const reportTimestamp = new Intl.DateTimeFormat(undefined, {
  dateStyle: 'long',
  timeStyle: 'long',
  timeZone: 'UTC',
})

function ReportFindings({ report }: { report: Report }) {
  return (
    <section className="report-section">
      <h2>Findings by dependency</h2>
      {!report.packages.length && (
        <p>
          No findings were recorded. Interpretation depends on the scan coverage
          above.
        </p>
      )}
      {report.packages.map((group) => (
        <section
          className="report-package"
          key={JSON.stringify(group.coordinate)}
        >
          <h3>
            {group.coordinate.name}{' '}
            <small>
              {group.coordinate.ecosystem} · {group.coordinate.version}
            </small>
          </h3>
          <p>
            {group.finding_count}{' '}
            {group.finding_count === 1 ? 'finding' : 'findings'} ·{' '}
            {group.fixable_count} with applicable fix evidence
          </p>
          {group.findings.map(({ finding, observations }) => {
            const references = new Set<string>()
            const advisoryRecords = finding.observed_ids.flatMap((id) =>
              report.advisories[id] ? [report.advisories[id]] : [],
            )
            for (const advisory of advisoryRecords) {
              for (const ref of advisory.references) {
                const url = safeReference(ref.url)
                if (url) references.add(url)
              }
            }
            return (
              <article className="report-finding" key={finding.advisory_id}>
                <h4>
                  {finding.advisory_id}{' '}
                  <SeverityBadge value={finding.priority.severity} />
                </h4>
                {finding.aliases.length > 0 && (
                  <p>Aliases · {finding.aliases.join(', ')}</p>
                )}
                {finding.evidence_level === 'discovery_only' && (
                  <p>
                    Discovery evidence only. Full matching details are
                    unavailable.
                  </p>
                )}
                {advisoryRecords.map(
                  (advisory) =>
                    advisory.summary && (
                      <p key={advisory.id}>{advisory.summary}</p>
                    ),
                )}
                <p>
                  CVSS base score ·{' '}
                  {finding.priority.severity_evidence?.score?.toFixed(1) ??
                    'Unavailable'}
                </p>
                {finding.fixes.length ? (
                  <ul>
                    {finding.fixes.map((fix, index) => (
                      <li key={index}>
                        Fixed {fix.version} · {fix.advisory_id} · range
                        introduced at {fix.introduced}
                      </li>
                    ))}
                  </ul>
                ) : (
                  <p>
                    No applicable fixed version verified for{' '}
                    {group.coordinate.version}.
                  </p>
                )}
                {observations
                  .filter((item) => item.error_code)
                  .map((item) => (
                    <p key={item.discovery.id}>
                      {item.discovery.id} · {wordLabel(item.error_code ?? '')}
                    </p>
                  ))}
                {references.size > 0 && (
                  <ul className="report-references">
                    {[...references].map((url) => (
                      <li key={url}>
                        <a href={url} target="_blank" rel="noopener noreferrer">
                          {url}
                        </a>
                      </li>
                    ))}
                  </ul>
                )}
              </article>
            )
          })}
        </section>
      ))}
    </section>
  )
}

export function ReportPage() {
  const { id = '' } = useParams()
  const result = useQuery({
    queryKey: ['report', id],
    queryFn: ({ signal }) => api.report(id, signal),
    enabled: Boolean(id),
  })
  const report = result.data
  const scan = report?.scan
  const counts = scan?.severity_counts
  const coverage = scan?.coverage
  return (
    <article className="report-page">
      <div className="report-actions">
        <Link className="button secondary" to={scanRoute(id)}>
          <ArrowLeft size={15} />
          Scan results
        </Link>
        {report && (
          <>
            <a className="button secondary" download href={api.download(id)}>
              <Download size={16} />
              Download JSON
            </a>
            <button
              className="button primary"
              type="button"
              onClick={() => window.print()}
            >
              <Printer size={16} />
              Print / save PDF
            </button>
          </>
        )}
      </div>
      <PageTitle
        title="Security scan report"
        description={
          scan
            ? `${scanName(scan)} · ${scan.id}`
            : 'DepScope saved scan evidence'
        }
      />
      {result.isPending ? (
        <Busy label="Loading saved report" />
      ) : result.isError ? (
        <ErrorState error={result.error} retry={() => void result.refetch()} />
      ) : (
        report &&
        scan && (
          <>
            <div className="result-labels">
              <Status value={scan.status} />
              <SourceBadge value={scan.provenance} />
            </div>
            <section className="report-section">
              <h2>Scan summary</h2>
              <dl className="definition-grid">
                <div>
                  <dt>Source</dt>
                  <dd>
                    {scan.source} · {scan.format}
                  </dd>
                </div>
                <div>
                  <dt>Submitted</dt>
                  <dd>
                    <time dateTime={scan.requested_at}>
                      {reportTimestamp.format(new Date(scan.requested_at))}
                    </time>
                  </dd>
                </div>
                <div>
                  <dt>Evidence observed</dt>
                  <dd>
                    {scan.observed_at ? (
                      <time dateTime={scan.observed_at}>
                        {reportTimestamp.format(new Date(scan.observed_at))}
                      </time>
                    ) : (
                      'Unavailable'
                    )}
                  </dd>
                </div>
                <div>
                  <dt>Risk index</dt>
                  <dd>
                    {displayNumber(scan.risk_index)}
                    {scan.risk_index != null && ' / 100'}
                  </dd>
                </div>
              </dl>
              {scan.error_code && (
                <p>Scan diagnostic · {wordLabel(scan.error_code)}</p>
              )}
              <h3>Severity breakdown</h3>
              {counts ? (
                <div className="report-severity">
                  {severities.map((severity) => (
                    <span key={severity}>
                      <SeverityBadge value={severity} />{' '}
                      <strong>{counts[severity] ?? 0}</strong>
                    </span>
                  ))}
                </div>
              ) : (
                <p>Severity counts are unavailable.</p>
              )}
              <h3>Score interpretation</h3>
              {scan.scoring_revision === '1' ? (
                <p>
                  DepScope revision 1 adds 20 points per critical finding, 10
                  per high finding, 4 per medium finding, and 1 per low finding,
                  capped at 100. Unknown and none contribute zero. A capped
                  score can represent several different levels of exposure. This
                  index is separate from CVSS.
                </p>
              ) : (
                <p>
                  Recorded scoring revision ·{' '}
                  {scan.scoring_revision ?? 'Unavailable'}.
                </p>
              )}
            </section>
            <section className="report-section">
              <h2>Coverage and limitations</h2>
              {coverage ? (
                <p>
                  Manifest entries {coverage.occurrences} · Exact versions{' '}
                  {coverage.exact_coordinates} · Fully assessed{' '}
                  {coverage.assessed_coordinates} · Partial{' '}
                  {coverage.partial_coordinates} · Failed{' '}
                  {coverage.failed_coordinates} · Unresolved{' '}
                  {coverage.unresolved_occurrences}
                </p>
              ) : (
                <p>Coverage is unavailable.</p>
              )}
              <ul>
                {scan.limitations?.map((item) => (
                  <li key={item}>{wordLabel(item)}</li>
                ))}
              </ul>
              <p>
                Advisory-specific fixes do not establish compatibility or
                absence of other findings. Review each candidate with the
                package constraints and application tests.
              </p>
              {report.assessments.filter((item) => item.diagnostics.length)
                .length > 0 && (
                <ul>
                  {report.assessments
                    .filter((item) => item.diagnostics.length)
                    .map((item) => (
                      <li key={JSON.stringify(item.coordinate)}>
                        {item.coordinate.name} {item.coordinate.version} ·{' '}
                        {item.diagnostics.map(wordLabel).join(', ')}
                      </li>
                    ))}
                </ul>
              )}
            </section>
            <ReportFindings report={report} />
            <section className="report-section">
              <h2>Dependency inventory</h2>
              {report.dependencies.length ? (
                <div className="table-scroll">
                  <table>
                    <thead>
                      <tr>
                        <th scope="col">Package</th>
                        <th scope="col">Version / constraint</th>
                        <th scope="col">Resolution</th>
                      </tr>
                    </thead>
                    <tbody>
                      {report.dependencies.map((item, index) => (
                        <tr key={index}>
                          <th scope="row">
                            {item.name ?? 'Unidentified entry'} ·{' '}
                            {item.ecosystem}
                            <span className="table-note">
                              {item.dependency_path ??
                                (item.line != null
                                  ? `Line ${item.line}`
                                  : `Entry ${item.entry_number ?? '—'}`)}
                            </span>
                          </th>
                          <td>
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
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <p>No dependency entries were saved.</p>
              )}
            </section>
          </>
        )
      )}
    </article>
  )
}
