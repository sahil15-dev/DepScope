export type Provenance = 'offline_fixture' | 'live_osv'
export type ManifestFormat = 'requirements' | 'npm-lock'
export type ScanStatus =
  | 'queued'
  | 'running'
  | 'complete'
  | 'partial'
  | 'failed'
export type Severity =
  | 'critical'
  | 'high'
  | 'medium'
  | 'low'
  | 'none'
  | 'unknown'
export type Ecosystem = 'PyPI' | 'npm'
export type SampleId =
  | 'python-vulnerable'
  | 'npm-vulnerable'
  | 'python-clean'
  | 'python-mixed'
  | 'python-partial'

export interface Coverage {
  occurrences: number
  unresolved_occurrences: number
  exact_coordinates: number
  assessed_coordinates: number
  partial_coordinates: number
  failed_coordinates: number
  coordinates_with_findings: number
}

export interface Scan {
  id: string
  format: ManifestFormat
  source: 'upload' | 'paste' | 'sample'
  provenance: Provenance
  sample_id: SampleId | null
  status: ScanStatus
  requested_at: string
  started_at: string | null
  finished_at: string | null
  observed_at: string | null
  error_code: string | null
  coverage: Coverage | null
  risk_index: number | null
  scoring_revision: string | null
  severity_counts: Partial<Record<Severity, number>> | null
  limitations: string[] | null
}

export interface Page<T> {
  items: T[]
  page: number
  page_size: number
  total: number
}
export interface Overview {
  provenance: Provenance
  status_counts: Record<ScanStatus, number>
  recent_scans: Scan[]
  latest_result: Scan | null
  risk_trend: Scan[]
}

export interface Coordinate {
  ecosystem: Ecosystem
  name: string
  version: string
}
export interface Occurrence {
  ecosystem: Ecosystem
  resolution:
    | 'declared_pin'
    | 'locked'
    | 'range'
    | 'unpinned'
    | 'unresolved'
    | 'invalid'
  directness: 'declared' | 'direct' | 'transitive' | 'unknown'
  name: string | null
  coordinate: Coordinate | null
  constraint: string | null
  line: number | null
  dependency_path: string | null
  entry_number: number | null
  reason: string | null
}

interface Observation {
  discovery: { id: string; modified: string | null }
  evidence_level: string
  error_code: string | null
}

export interface Assessment {
  coordinate: Coordinate
  status: 'complete' | 'partial' | 'failed'
  diagnostics: string[]
  observations: Observation[]
}

export interface ScanDetail {
  scan: Scan
  dependencies: Page<Occurrence>
  assessments: Page<Assessment>
}

interface SeverityEvidence {
  scheme: string
  source: string
  severity: Severity
  vector: string | null
  score: number | null
  label: string | null
  score_basis: string | null
  upstream_source: string | null
}

export interface Advisory {
  id: string
  summary: string | null
  modified: string
  published: string | null
  aliases: string[]
  affected: {
    ecosystem: string | null
    name: string | null
    versions: string[]
    ranges: {
      kind: string
      events: { kind: string; version: string }[]
    }[]
  }[]
  references: { kind: string; url: string }[]
}

export interface Finding {
  coordinate: Coordinate
  advisory_id: string
  aliases: string[]
  observed_ids: string[]
  evidence_level: 'hydrated' | 'discovery_only'
  fixes: {
    advisory_id: string
    version: string
    introduced: string
    range_type: string
  }[]
  priority: {
    severity: Severity
    severity_advisory_id: string | null
    severity_evidence: SeverityEvidence | null
    fix_available: boolean
    reason: string
  }
}

export interface FindingView {
  finding: Finding
  observations: Observation[]
}
export interface Findings extends Page<FindingView> {
  advisories: Record<string, Advisory>
}

export interface PackageGroup {
  coordinate: Coordinate
  status: Assessment['status']
  finding_count: number
  fixable_count: number
  severity_counts: Record<Severity, number>
  highest_severity: Severity
}

export interface PackagePage extends Page<PackageGroup> {
  finding_count: number
  fixable_count: number
}

export interface Candidate {
  version: string
  advisory_ids: string[]
  evidence: 'insufficient_evidence' | 'known_findings' | 'no_known_findings'
  scan_id: string | null
  observed_at: string | null
  lookup_status: Assessment['status'] | null
  finding_count: number | null
}

export interface Report {
  schema_version: number
  scan: Scan
  packages: (PackageGroup & { findings: FindingView[] })[]
  dependencies: Occurrence[]
  assessments: Assessment[]
  advisories: Record<string, Advisory>
}

export interface Comparison {
  baseline: Scan
  target: Scan
  risk_delta: number | null
  dependencies: {
    package: Pick<Coordinate, 'ecosystem' | 'name'>
    kind: 'added' | 'removed' | 'changed'
    before_versions: string[]
    after_versions: string[]
    before_unresolved: number
    after_unresolved: number
  }[]
  findings: {
    package: Pick<Coordinate, 'ecosystem' | 'name'>
    advisory_ids: string[]
    kind: 'newly_detected' | 'no_longer_detected' | 'unchanged'
    before_versions: string[]
    after_versions: string[]
    before_severity: Severity | null
    after_severity: Severity | null
    context:
      | 'observed'
      | 'incomplete_coverage'
      | 'package_absent'
      | 'versions_changed'
  }[]
}
export interface Accepted {
  id: string
  status: 'queued'
  status_url: string
}
export type Submission =
  | { sample: SampleId }
  | { format: ManifestFormat; source: 'upload' | 'paste'; body: File | string }

export class ApiError extends Error {
  readonly status: number
  readonly retryAfter: string | null

  constructor(status: number, message: string, retryAfter: string | null) {
    super(message)
    this.status = status
    this.retryAfter =
      retryAfter && /^\d{1,6}$/.test(retryAfter) ? retryAfter : null
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  let response: Response
  try {
    response = await fetch(path, {
      ...init,
      cache: 'no-store',
      redirect: 'error',
    })
  } catch (error) {
    if (init?.signal?.aborted) throw error
    throw new Error(
      'The local API could not be reached. Check that DepScope is running.',
    )
  }
  if (!response.ok) {
    const json: { error?: { message?: unknown } } | null = await response
      .json()
      .catch(() => null)
    const message =
      typeof json?.error?.message === 'string'
        ? json.error.message
        : 'The local API could not complete the request.'
    throw new ApiError(
      response.status,
      message,
      response.headers.get('retry-after'),
    )
  }
  return response.json() as Promise<T>
}

type Parameters = Record<string, string | number | boolean | undefined>
function query(path: string, values: Parameters) {
  const params = new URLSearchParams()
  for (const [name, value] of Object.entries(values))
    if (value !== undefined && value !== '') params.set(name, String(value))
  return `${path}?${params}`
}

function validatedScanId(id: string) {
  if (!/^[0-9a-f]{8}-(?:[0-9a-f]{4}-){3}[0-9a-f]{12}$/i.test(id)) {
    throw new ApiError(400, 'The scan ID is invalid.', null)
  }
  return id
}

const scanPath = (id: string) => `/api/scans/${validatedScanId(id)}`

export const api = {
  health: (signal: AbortSignal) =>
    request<{ status: 'ready'; database: 'ready' }>('/api/health', { signal }),
  overview: (provenance: Provenance, signal: AbortSignal) =>
    request<Overview>(query('/api/overview', { provenance }), { signal }),
  scans: (parameters: Parameters, signal: AbortSignal) =>
    request<Page<Scan>>(query('/api/scans', parameters), { signal }),
  detail: (id: string, page: number, signal: AbortSignal) =>
    request<ScanDetail>(query(scanPath(id), { page }), { signal }),
  findings: (id: string, parameters: Parameters, signal: AbortSignal) =>
    request<Findings>(query(`${scanPath(id)}/findings`, parameters), {
      signal,
    }),
  packages: (id: string, parameters: Parameters, signal: AbortSignal) =>
    request<PackagePage>(query(`${scanPath(id)}/packages`, parameters), {
      signal,
    }),
  candidates: (id: string, coordinate: Coordinate, signal: AbortSignal) =>
    request<Candidate[]>(
      query(`${scanPath(id)}/candidates`, { ...coordinate }),
      { signal },
    ),
  review: (id: string, page: number, signal: AbortSignal) =>
    request<Page<Occurrence>>(query(`${scanPath(id)}/review`, { page }), {
      signal,
    }),
  report: (id: string, signal: AbortSignal) =>
    request<Report>(`${scanPath(id)}/report`, { signal }),
  download: (id: string) => `${scanPath(id)}/report?download=true`,
  compare: (baseline: string, target: string, signal: AbortSignal) =>
    request<Comparison>(
      `${scanPath(baseline)}/comparison/${validatedScanId(target)}`,
      { signal },
    ),
  submit: (submission: Submission) => {
    if ('sample' in submission)
      return request<Accepted>(
        query('/api/scans', { sample_id: submission.sample }),
        { method: 'POST' },
      )
    const type =
      submission.format === 'requirements' ? 'text/plain' : 'application/json'
    return request<Accepted>(
      query('/api/scans', {
        format: submission.format,
        source: submission.source,
        live: true,
      }),
      {
        method: 'POST',
        headers: { 'Content-Type': type },
        body: submission.body,
      },
    )
  },
}

export const pending = (status?: ScanStatus) =>
  status === 'queued' || status === 'running'
