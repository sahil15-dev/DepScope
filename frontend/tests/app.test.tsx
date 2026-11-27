import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, vi } from 'vitest'
import type {
  Comparison,
  Findings,
  Overview,
  PackagePage,
  Page,
  Report,
  Scan,
  ScanDetail,
} from '../src/api'
import { App } from '../src/app'

const id = 'acb62854-1c41-4e8a-9ad0-51be9c76f37a'
const otherId = 'fd140094-38af-417e-8aa5-74a119cc98ac'
const instant = '2026-11-27T00:00:00Z'
const baseline: Scan = {
  id,
  format: 'requirements',
  source: 'sample',
  sample_id: 'python-vulnerable',
  provenance: 'offline_fixture',
  status: 'complete',
  requested_at: instant,
  started_at: instant,
  finished_at: instant,
  observed_at: instant,
  error_code: null,
  risk_index: 17,
  scoring_revision: '1',
  coverage: {
    occurrences: 19,
    unresolved_occurrences: 2,
    exact_coordinates: 11,
    assessed_coordinates: 9,
    partial_coordinates: 1,
    failed_coordinates: 1,
    coordinates_with_findings: 1,
  },
  severity_counts: { high: 2, medium: 1 },
  limitations: ['bundled_fixture_subset', 'runtime_reachability_not_assessed'],
}

const coordinate = {
  name: 'jinja2',
  ecosystem: 'PyPI',
  version: '3.1.2',
} as const
const severity = {
  scheme: 'CVSS_V3',
  source: 'advisory.severity',
  severity: 'medium',
  score: 5.4,
  label: null,
  score_basis: 'base_vector',
  upstream_source: null,
  vector: 'CVSS:3.1/AV:N',
} as const
const advisoryId = 'GHSA-h5c8-rqwp-cp95'
const finding: Findings['items'][number] = {
  finding: {
    coordinate,
    advisory_id: advisoryId,
    aliases: ['CVE-2024-22195'],
    observed_ids: [advisoryId],
    evidence_level: 'hydrated',
    fixes: [
      {
        advisory_id: advisoryId,
        version: '3.1.3',
        introduced: '0',
        range_type: 'ECOSYSTEM',
      },
    ],
    priority: {
      severity: 'medium',
      severity_advisory_id: advisoryId,
      severity_evidence: severity,
      fix_available: true,
      reason: 'severity_with_advisory_fix',
    },
  },
  observations: [],
}

function page<T>(items: T[], number = 1, total = items.length): Page<T> {
  return { items, page: number, page_size: 20, total }
}

function overview(scan: Scan | null, recent = scan ? [scan] : []): Overview {
  return {
    provenance: 'offline_fixture',
    latest_result: scan,
    recent_scans: recent,
    risk_trend: scan ? [scan] : [],
    status_counts: {
      queued: 0,
      running: 0,
      complete: scan ? 1 : 0,
      partial: 0,
      failed: 0,
    },
  }
}

function detail(scan: Scan = baseline): ScanDetail {
  return {
    scan,
    dependencies: page([
      {
        ecosystem: 'PyPI',
        resolution: 'declared_pin',
        directness: 'declared',
        name: 'jinja2',
        coordinate,
        constraint: '==3.1.2',
        line: 2,
        dependency_path: null,
        entry_number: null,
        reason: null,
      },
    ]),
    assessments: page([
      {
        coordinate,
        status: 'partial',
        diagnostics: ['advisory_not_found'],
        observations: [],
      },
    ]),
  }
}

const findings: Findings = {
  ...page([finding]),
  advisories: {
    [advisoryId]: {
      id: advisoryId,
      summary: 'Fixture advisory summary',
      modified: instant,
      published: instant,
      aliases: ['CVE-2024-22195'],
      affected: [
        {
          ecosystem: 'PyPI',
          name: 'Jinja2',
          versions: ['3.1.2'],
          ranges: [
            {
              kind: 'ECOSYSTEM',
              events: [
                { kind: 'introduced', version: '0' },
                { kind: 'fixed', version: '3.1.3' },
              ],
            },
          ],
        },
      ],
      references: [
        {
          kind: 'ADVISORY',
          url: 'https://osv.dev/vulnerability/GHSA-h5c8-rqwp-cp95',
        },
        { kind: 'UNSAFE', url: 'javascript:alert(1)' },
        { kind: 'CREDENTIALS', url: 'https://user:example@invalid.invalid/' },
      ],
    },
  },
}

const scanUrl = `/api/scans/${id}`
const accepted = { id, status: 'queued', status_url: scanUrl }
const packageGroup = {
  coordinate,
  status: 'complete' as const,
  finding_count: 1,
  fixable_count: 1,
  severity_counts: {
    critical: 0,
    high: 0,
    medium: 1,
    low: 0,
    none: 0,
    unknown: 0,
  },
  highest_severity: 'medium' as const,
}
const packages: PackagePage = {
  ...page([packageGroup]),
  finding_count: 1,
  fixable_count: 1,
}

function json(data: unknown, status = 200, headers?: HeadersInit) {
  return new Response(JSON.stringify(data), { status, headers })
}

function fixture(
  handler: (url: URL, init?: RequestInit) => Response | Promise<Response>,
) {
  const fetch = vi.fn((path: string, init?: RequestInit) => {
    const url = new URL(path, 'http://127.0.0.1:5173')
    if (url.pathname === '/api/health')
      return Promise.resolve(json({ status: 'ready', database: 'ready' }))
    return Promise.resolve(handler(url, init))
  })
  vi.stubGlobal('fetch', fetch)
  return fetch
}

function app(route = '/') {
  const client = new QueryClient({
    defaultOptions: {
      queries: { retry: false, gcTime: 0 },
      mutations: { retry: false },
    },
  })
  render(
    <QueryClientProvider client={client}>
      <MemoryRouter initialEntries={[route]}>
        <App />
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return userEvent.setup()
}

const notFound = () => json({ error: { message: 'Scan not found.' } }, 404)

describe('Phase 4 analysis and reports', () => {
  it('filters dependency groups and fetches exact-version advisories on expansion', async () => {
    const fetch = fixture((url) => {
      if (url.pathname.endsWith('/packages'))
        return json(
          url.searchParams.get('severity') === 'high'
            ? { ...page([]), finding_count: 0, fixable_count: 0 }
            : packages,
        )
      if (url.pathname.endsWith('/findings')) return json(findings)
      if (url.pathname === '/api/scans') return json(page([baseline]))
      return json(detail())
    })
    const user = app(`/explorer?scan=${id}`)
    await user.click(await screen.findByRole('button', { name: 'Dependency' }))
    await user.click(await screen.findByText('jinja2', { exact: true }))
    await waitFor(() =>
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining('name=jinja2&version=3.1.2'),
        expect.any(Object),
      ),
    )
    expect(screen.getByLabelText('Severity distribution')).toHaveTextContent(
      '1 medium',
    )
    await user.selectOptions(
      screen.getByRole('combobox', { name: 'Severity' }),
      'high',
    )
    expect(await screen.findByText('No matching packages')).toBeVisible()
  })

  it('distinguishes a candidate without saved evidence from an advisory-specific fix', async () => {
    fixture((url) => {
      if (url.pathname.endsWith('/packages')) return json(packages)
      if (url.pathname.endsWith('/review')) return json(page([]))
      if (url.pathname.endsWith('/candidates'))
        return json([
          {
            version: '3.1.3',
            advisory_ids: [advisoryId],
            evidence: 'insufficient_evidence',
            scan_id: null,
            observed_at: null,
            lookup_status: null,
            finding_count: null,
          },
        ])
      if (url.pathname.endsWith('/findings')) return json(findings)
      if (url.pathname === '/api/scans') return json(page([baseline]))
      return json(detail())
    })
    const user = app(`/remediation?scan=${id}`)
    expect(await screen.findByText('Fix evidence available')).toBeVisible()
    await user.click(await screen.findByText('jinja2'))
    expect(
      await screen.findByText('Insufficient lookup evidence'),
    ).toBeVisible()
    expect(
      screen.getByText(`Advisory-specific fix · ${advisoryId}`),
    ).toBeVisible()
    expect(
      screen.queryByText('No known findings in saved lookup'),
    ).not.toBeInTheDocument()
  })

  it('shows comparison coverage and keeps disappeared findings distinct from remediation', async () => {
    const comparison: Comparison = {
      baseline,
      target: { ...baseline, id: otherId, status: 'partial' },
      risk_delta: -3,
      dependencies: [
        {
          package: coordinate,
          kind: 'changed',
          before_versions: ['3.1.2'],
          after_versions: ['3.1.3'],
          before_unresolved: 0,
          after_unresolved: 1,
        },
      ],
      findings: [
        {
          package: coordinate,
          kind: 'no_longer_detected',
          advisory_ids: [advisoryId],
          before_versions: ['3.1.2'],
          after_versions: [],
          before_severity: 'medium',
          after_severity: null,
          context: 'incomplete_coverage',
        },
      ],
    }
    fixture((url) =>
      json(
        url.pathname.includes('/comparison/')
          ? comparison
          : page([baseline, comparison.target]),
      ),
    )
    const user = app(`/compare?baseline=${id}&target=${otherId}`)
    expect(await screen.findByText('-3')).toBeVisible()
    await user.click(
      screen.getByRole('button', { name: /no longer detected/i }),
    )
    expect(screen.getByText('Incomplete coverage')).toBeVisible()
    expect(
      screen.getByText(/does not establish that an advisory was remediated/i),
    ).toBeVisible()
    expect(screen.getByText('1 unresolved')).toBeVisible()
  })

  it('renders a report from saved evidence with working JSON and print actions', async () => {
    const scanDetail = detail()
    const report: Report = {
      schema_version: 1,
      scan: baseline,
      packages: [{ ...packageGroup, findings: [finding] }],
      dependencies: scanDetail.dependencies.items,
      assessments: scanDetail.assessments.items,
      advisories: findings.advisories,
    }
    fixture(() => json(report))
    const print = vi.spyOn(window, 'print').mockImplementation(() => {})
    const user = app(`/scans/${id}/report`)
    expect(
      await screen.findByRole('heading', { name: 'Findings by dependency' }),
    ).toBeVisible()
    expect(
      screen.getByText(
        'Fixed 3.1.3 · GHSA-h5c8-rqwp-cp95 · range introduced at 0',
      ),
    ).toBeVisible()
    expect(screen.getByRole('link', { name: 'Download JSON' })).toHaveAttribute(
      'href',
      `${scanUrl}/report?download=true`,
    )
    expect(screen.queryByText(/javascript:alert/)).not.toBeInTheDocument()
    await user.click(screen.getByRole('button', { name: 'Print / save PDF' }))
    expect(print).toHaveBeenCalledOnce()
  })
})

describe('Overview and workspace', () => {
  it('shows loading, then renders API-supplied metrics and coverage', async () => {
    let resolveResponse!: (response: Response) => void
    const response = new Promise<Response>((resolve) => {
      resolveResponse = resolve
    })
    const fetch = fixture((url) => {
      if (url.pathname.endsWith('/packages')) return json(packages)
      expect(url.searchParams.get('provenance')).toBe('offline_fixture')
      return response
    })
    app()
    expect(screen.getByText('Loading overview')).toBeVisible()
    resolveResponse(json(overview(baseline)))
    const metrics = await screen.findByLabelText('Latest scan metrics')
    expect(within(metrics).getByText('17')).toBeVisible()
    expect(within(metrics).getByText('2 unresolved entries')).toBeVisible()
    expect(within(metrics).getByText('1 partial · 1 failed')).toBeVisible()
    expect(within(screen.getByRole('table')).getByText('9 / 11')).toBeVisible()
    expect(await screen.findByText('One recorded score')).toBeVisible()
    expect(
      screen.queryByRole('img', { name: /risk index over time/i }),
    ).not.toBeInTheDocument()
    expect(await screen.findByText('jinja2', { exact: true })).toBeVisible()
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('provenance=offline_fixture'),
      expect.any(Object),
    )
  })

  it('plots repeat runs of the same sample and excludes unrelated samples', async () => {
    const other = {
      ...baseline,
      id: otherId,
      sample_id: 'npm-vulnerable' as const,
    }
    const previous = {
      ...baseline,
      id: 'a5a01247-35cf-4fec-a83b-e03c42d85331',
      risk_index: 10,
    }
    fixture((url) =>
      json(
        url.pathname.endsWith('/packages')
          ? packages
          : {
              ...overview(baseline),
              risk_trend: [other, previous, baseline],
            },
      ),
    )
    app()
    expect(
      await screen.findByRole(
        'img',
        { name: /risk index over time/i },
        { timeout: 5000 },
      ),
    ).toBeInTheDocument()
    const list = screen.getByText('View trend values').parentElement
    expect(list).toHaveTextContent('Python advisory')
    expect(list).not.toHaveTextContent('npm advisory')
  })

  it('separates the empty demo state and a retryable live API error', async () => {
    let attempts = 0
    fixture((url) => {
      if (url.searchParams.get('provenance') === 'offline_fixture')
        return json(overview(null))
      return ++attempts === 1
        ? json({ error: { message: 'The scan database is unavailable.' } }, 503)
        : json(overview(null))
    })
    const user = app()
    expect(await screen.findByText('No sample scans yet')).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Live OSV' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The scan database is unavailable.',
    )
    await user.click(screen.getByRole('button', { name: 'Retry' }))
    expect(await screen.findByText('No live scans yet')).toBeVisible()
  })

  it('switches and persists the theme', async () => {
    fixture(notFound)
    const user = app('/settings')
    await user.click(screen.getByRole('button', { name: 'Light' }))
    expect(document.documentElement).toHaveAttribute('data-theme', 'light')
    expect(window.localStorage.getItem('depscope-theme')).toBe('light')
    await user.click(
      screen.getByRole('button', { name: 'Switch to dark theme' }),
    )
    expect(screen.getByRole('button', { name: 'Dark' })).toHaveAttribute(
      'aria-pressed',
      'true',
    )
    expect(
      screen.getByRole('link', { name: /openapi schema/i }),
    ).toHaveAttribute('href', '/openapi.json')
  })
})

describe('Scan workflows', () => {
  it('submits a bundled sample, polls the real status, and shows a partial report', async () => {
    let reads = 0
    fixture((url, init) => {
      if (init?.method === 'POST') {
        expect(url.searchParams.toString()).toBe('sample_id=python-partial')
        expect(init.body).toBeUndefined()
        return json(accepted, 202)
      }
      if (url.pathname === scanUrl)
        return json(
          detail(
            reads++ === 0
              ? {
                  ...baseline,
                  status: 'queued',
                  coverage: null,
                  risk_index: null,
                }
              : { ...baseline, status: 'partial', sample_id: 'python-partial' },
          ),
        )
      return json(findings)
    })
    const user = app('/scans/new')
    await user.click(
      screen.getByRole('radio', { name: /partial advisory data/i }),
    )
    await user.click(screen.getByRole('button', { name: 'Run offline sample' }))
    expect(await screen.findByText('Waiting for the scan worker')).toBeVisible()
    expect(
      await screen.findByText(
        'Some advisory checks could not finish.',
        {},
        { timeout: 4000 },
      ),
    ).toBeVisible()
    expect(await screen.findByText('Offline fixture')).toBeVisible()
    expect(await screen.findByText('jinja2')).toBeVisible()
    expect(reads).toBeGreaterThanOrEqual(2)
  })

  it('requires live consent before passing pasted text as a raw manifest', async () => {
    const lookups = vi.fn()
    fixture((url, init) => {
      if (init?.method === 'POST') {
        lookups(init.body)
        expect(url.searchParams.get('format')).toBe('requirements')
        expect(url.searchParams.get('source')).toBe('paste')
        expect(url.searchParams.get('live')).toBe('true')
        expect(init.headers).toEqual({ 'Content-Type': 'text/plain' })
        return json(accepted, 202)
      }
      return json(
        url.pathname.endsWith('/findings')
          ? findings
          : detail({
              ...baseline,
              provenance: 'live_osv',
              source: 'paste',
              sample_id: null,
            }),
      )
    })
    const user = app('/scans/new')
    await user.click(screen.getByRole('button', { name: 'Paste manifest' }))
    await user.type(
      screen.getByRole('textbox', { name: 'Manifest contents' }),
      'jinja2==3.1.2',
    )
    await user.click(screen.getByRole('button', { name: 'Start scan' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /confirm the live osv lookup/i,
    )
    expect(lookups).not.toHaveBeenCalled()
    await user.click(
      screen.getByRole('checkbox', { name: /allow live osv lookups/i }),
    )
    await user.click(screen.getByRole('button', { name: 'Start scan' }))
    expect(
      await screen.findByRole('heading', { name: 'Python paste' }),
    ).toBeVisible()
    expect(screen.getByRole('main')).toHaveFocus()
    expect(lookups).toHaveBeenCalledExactlyOnceWith('jinja2==3.1.2')
  })

  it('submits a selected lockfile and keeps backend queue errors visible', async () => {
    const file = new File(
      ['{"lockfileVersion":3,"packages":{}}'],
      'package-lock.json',
      { type: 'application/json' },
    )
    fixture((url, init) => {
      expect(url.searchParams.get('source')).toBe('upload')
      expect(url.searchParams.get('format')).toBe('npm-lock')
      expect(init?.body).toBe(file)
      return json(
        { error: { message: 'All scan slots are currently in use.' } },
        503,
        { 'Retry-After': '1' },
      )
    })
    const user = app('/scans/new')
    await user.click(screen.getByRole('button', { name: 'Upload file' }))
    await user.upload(screen.getByLabelText('Dependency file'), file)
    expect(
      screen.getByRole('combobox', { name: 'Manifest format' }),
    ).toHaveValue('npm-lock')
    await user.click(screen.getByRole('checkbox'))
    await user.click(screen.getByRole('button', { name: 'Start scan' }))
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'All scan slots are currently in use.',
    )
    expect(screen.getByText('Retry after 1 second.')).toBeVisible()
  })

  it('shows interrupted failures without implying there are zero vulnerabilities', async () => {
    fixture(() =>
      json(
        detail({
          ...baseline,
          status: 'failed',
          error_code: 'interrupted',
          coverage: null,
          risk_index: null,
        }),
      ),
    )
    app(`/scans/${id}`)
    expect(await screen.findByRole('alert')).toHaveTextContent(
      /scan was interrupted/i,
    )
    expect(screen.queryByText('No findings recorded')).not.toBeInTheDocument()
  })

  it('renders saved entries and coordinate diagnostics', async () => {
    fixture((url) =>
      json(url.pathname.endsWith('/findings') ? findings : detail()),
    )
    const user = app(`/scans/${id}`)
    await user.click(
      await screen.findByRole('button', { name: 'Dependencies' }),
    )
    expect(await screen.findByText('Line 2')).toBeVisible()
    await user.click(screen.getByRole('button', { name: 'Lookups' }))
    expect(await screen.findByText('advisory not found')).toBeVisible()
  })
})

describe('History and vulnerability explorer', () => {
  it('rejects malformed scan identifiers before constructing an API path', async () => {
    const fetch = fixture(() => json(page([])))
    app('/explorer?scan=..%2F..%2Fhealth')
    expect(await screen.findByRole('alert')).toHaveTextContent(
      'The scan ID is invalid.',
    )
    expect(fetch.mock.calls.map(([url]) => url.split('?')[0]).sort()).toEqual([
      '/api/health',
      '/api/scans',
    ])
  })

  it('pages history and filters using the API', async () => {
    fixture((url) => {
      if (url.searchParams.get('status') === 'failed') return json(page([]))
      const next = url.searchParams.get('page') === '2'
      return json(
        page(
          next
            ? [{ ...baseline, id: otherId, sample_id: 'npm-vulnerable' }]
            : [baseline],
          next ? 2 : 1,
          21,
        ),
      )
    })
    const user = app('/history')
    expect(
      await screen.findByRole('link', { name: 'Python advisory' }),
    ).toBeVisible()
    await user.click(
      screen.getByRole('button', { name: 'Next scan history page' }),
    )
    expect(
      await screen.findByRole('link', { name: 'npm advisory' }),
    ).toBeVisible()
    expect(screen.getByText('Page 2 of 2')).toBeVisible()
    await user.selectOptions(
      screen.getByRole('combobox', { name: 'Status' }),
      'failed',
    )
    expect(await screen.findByText('No matching scans')).toBeVisible()
  })

  it('renders advisory evidence, blocks unsafe references, and searches and sorts the saved results', async () => {
    const fetch = fixture((url) => {
      if (url.pathname.endsWith('/findings'))
        return json(
          url.searchParams.has('package')
            ? { ...page([]), advisories: {} }
            : findings,
        )
      if (url.pathname === '/api/scans') return json(page([baseline]))
      return json(detail())
    })
    const user = app(`/explorer?scan=${id}`)
    await user.click(await screen.findByText('jinja2'))
    expect(await screen.findByText('Fixture advisory summary')).toBeVisible()
    expect(screen.getByText('CVE-2024-22195')).toBeVisible()
    expect(screen.getByText('5.4 · CVSS_V3')).toBeVisible()
    expect(
      screen.getByText('ECOSYSTEM · introduced 0 → fixed 3.1.3'),
    ).toBeVisible()
    expect(
      screen.getByRole('link', { name: /ADVISORY · osv.dev/i }),
    ).toHaveAttribute('rel', 'noopener noreferrer')
    expect(screen.queryByText(/UNSAFE|CREDENTIALS/)).not.toBeInTheDocument()
    await user.selectOptions(
      screen.getByRole('combobox', { name: 'Sort by' }),
      'package',
    )
    await user.type(
      screen.getByRole('searchbox', { name: 'Package search' }),
      'missing & private',
    )
    await user.click(screen.getByRole('button', { name: 'Search packages' }))
    expect(await screen.findByText('No matching findings')).toBeVisible()
    await waitFor(() =>
      expect(fetch).toHaveBeenCalledWith(
        expect.stringContaining('package=missing+%26+private'),
        expect.any(Object),
      ),
    )
    expect(fetch).toHaveBeenCalledWith(
      expect.stringContaining('sort=package'),
      expect.any(Object),
    )
    await user.click(screen.getByRole('button', { name: 'Clear filters' }))
    expect(await screen.findByText('jinja2')).toBeVisible()
  })
})
