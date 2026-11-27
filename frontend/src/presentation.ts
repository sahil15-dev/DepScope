import type { ManifestFormat, SampleId, Scan, Severity } from './api'

export const severities: Severity[] = [
  'critical',
  'high',
  'medium',
  'low',
  'unknown',
  'none',
]
export const formatNames: Record<ManifestFormat, string> = {
  requirements: 'Python',
  'npm-lock': 'npm',
}
export const samples: { id: SampleId; title: string; description: string }[] = [
  {
    id: 'python-vulnerable',
    title: 'Python advisory',
    description: 'Historical Jinja finding and an advisory-supported fix.',
  },
  {
    id: 'npm-vulnerable',
    title: 'npm advisory',
    description: 'Historical lodash finding in a lockfile.',
  },
  {
    id: 'python-clean',
    title: 'No fixture matches',
    description: 'A completed lookup with no findings in the fixture set.',
  },
  {
    id: 'python-mixed',
    title: 'Mixed requirements',
    description: 'A pinned package alongside unresolved requirements.',
  },
  {
    id: 'python-partial',
    title: 'Partial advisory data',
    description: 'A verified finding and a simulated detail-fetch failure.',
  },
]

export function scanName(scan: Scan) {
  return (
    samples.find(({ id }) => id === scan.sample_id)?.title ??
    `${formatNames[scan.format]} ${scan.source}`
  )
}

export const scanRoute = (id: string) => `/scans/${encodeURIComponent(id)}`
export const wordLabel = (label: string) => label.replaceAll('_', ' ')
export const displayNumber = (value?: number | null) =>
  value == null ? '—' : value.toLocaleString()
const date = new Intl.DateTimeFormat(undefined, {
  month: 'short',
  day: 'numeric',
  hour: 'numeric',
  minute: '2-digit',
})
export function dateLabel(value: string | null) {
  if (!value) return '—'
  const parsed = new Date(value)
  return Number.isNaN(parsed.getTime()) ? '—' : date.format(parsed)
}

const failureMessages: Record<string, string> = {
  advisory_lookup_failed:
    'The advisory provider returned no usable results. Check the lookup diagnostics before retrying.',
  interrupted:
    'This scan was interrupted. Submit the input again to start a new scan.',
  invalid_encoding: 'The manifest must be UTF-8 text.',
  invalid_lockfile:
    'DepScope could not parse this npm lockfile. Check that it contains valid JSON and the expected lockfile fields.',
  job_timeout: 'The scan reached its time limit before it could finish.',
  storage_failure: 'DepScope could not save this scan result.',
  unsupported_lockfile_version:
    'DepScope supports npm lockfile versions 1 through 3.',
}

export function failureMessage(code: string | null) {
  return (
    (code && failureMessages[code]) ||
    'This scan did not finish successfully. Review its error code or try again.'
  )
}

export function safeReference(value: string) {
  try {
    const url = new URL(value)
    return (url.protocol === 'https:' || url.protocol === 'http:') &&
      !url.username &&
      !url.password
      ? url.href
      : null
  } catch {
    return null
  }
}
