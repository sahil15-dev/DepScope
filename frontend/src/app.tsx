import { useQuery } from '@tanstack/react-query'
import {
  Activity,
  FilePlus2,
  GitCompareArrows,
  History,
  LayoutDashboard,
  Moon,
  Radar,
  ScanSearch,
  Settings,
  ShieldCheck,
  Sun,
} from 'lucide-react'
import { useEffect, useRef, useState } from 'react'
import { Link, NavLink, Route, Routes, useLocation } from 'react-router-dom'
import { api, type Provenance } from './api'
import { ComparePage, RemediationPage } from './analysis-pages'
import { ReportPage } from './report'
import { HistoryPage } from './history'
import { NewScan } from './new-scan'
import { OverviewPage } from './overview'
import { ExplorerPage, ResultsPage } from './results'
import { Empty, PageTitle, PanelHeader } from './ui'

type Theme = 'dark' | 'light'
const themeKey = 'depscope-theme'
const nav = [
  { href: '/', icon: LayoutDashboard, label: 'Overview' },
  { href: '/scans/new', icon: FilePlus2, label: 'New scan' },
  { href: '/history', icon: History, label: 'Scan history' },
  { href: '/explorer', icon: ScanSearch, label: 'Explorer' },
  { href: '/remediation', icon: ShieldCheck, label: 'Remediation' },
  { href: '/compare', icon: GitCompareArrows, label: 'Compare scans' },
  { href: '/settings', icon: Settings, label: 'Settings' },
]

function initialTheme(): Theme {
  try {
    return window.localStorage.getItem(themeKey) === 'light' ? 'light' : 'dark'
  } catch {
    return 'dark'
  }
}

function SettingsPage({
  theme,
  setTheme,
}: {
  theme: Theme
  setTheme: (theme: Theme) => void
}) {
  return (
    <>
      <PageTitle
        title="Settings & about"
        description="Manage the workspace appearance and inspect the local service."
      />
      <div className="settings-grid">
        <section className="panel">
          <PanelHeader
            title="Appearance"
            description="Choose how DepScope looks in this browser."
          />
          <div className="panel-body">
            <div className="segmented" role="group" aria-label="Color theme">
              <button
                type="button"
                aria-pressed={theme === 'dark'}
                onClick={() => setTheme('dark')}
              >
                <Moon size={16} aria-hidden="true" />
                Dark
              </button>
              <button
                type="button"
                aria-pressed={theme === 'light'}
                onClick={() => setTheme('light')}
              >
                <Sun size={16} aria-hidden="true" />
                Light
              </button>
            </div>
          </div>
        </section>
        <section className="panel">
          <PanelHeader
            title="Local service"
            description="DepScope · Dependency Security"
          />
          <div className="panel-body settings-copy">
            <p>
              Scan history and advisory snapshots are stored in local SQLite.
              Fixture results stay labeled separately from live OSV data.
            </p>
            <p>
              The DepScope risk index is a triage measure based on recorded
              evidence. Review coverage and individual findings when
              interpreting a score.
            </p>
            <div className="settings-links">
              <a href="/openapi.json" target="_blank" rel="noopener noreferrer">
                OpenAPI schema{' '}
                <span className="sr-only">(opens in new tab)</span>
              </a>
              <a href="/api/health" target="_blank" rel="noopener noreferrer">
                Service health{' '}
                <span className="sr-only">(opens in new tab)</span>
              </a>
            </div>
          </div>
        </section>
      </div>
    </>
  )
}

export function App() {
  const [theme, setTheme] = useState<Theme>(initialTheme)
  const [source, changeSource] = useState<Provenance>('offline_fixture')
  const health = useQuery({
    queryKey: ['health'],
    queryFn: ({ signal }) => api.health(signal),
    refetchInterval: 15_000,
  })
  const { pathname } = useLocation()
  const previousPath = useRef(pathname)
  const main = useRef<HTMLElement>(null)

  useEffect(() => {
    if (pathname !== previousPath.current) {
      main.current?.focus()
      previousPath.current = pathname
    }
  }, [pathname])

  useEffect(() => {
    document.documentElement.dataset.theme = theme
    try {
      window.localStorage.setItem(themeKey, theme)
    } catch {
      /* The current theme still works without storage. */
    }
  }, [theme])

  const healthLabel = health.isPaused
    ? 'Connection unavailable'
    : health.isPending
      ? 'Checking API'
      : health.isError
        ? 'Local API unavailable'
        : 'Local API ready'
  const sourceProps = { source, changeSource }

  return (
    <div className="app-shell">
      <a className="skip-link" href="#main-content">
        Skip to content
      </a>
      <aside className="sidebar">
        <Link className="brand" to="/" aria-label="DepScope home">
          <span className="brand-mark">
            <Radar size={22} aria-hidden="true" />
          </span>
          <span>
            <strong>DepScope</strong>
            <small>Dependency Security</small>
          </span>
        </Link>
        <nav aria-label="Main navigation" className="nav-list">
          {nav.map(({ href, icon: Icon, label }) => (
            <NavLink to={href} key={href} end>
              <Icon size={18} aria-hidden="true" />
              <span>{label}</span>
            </NavLink>
          ))}
        </nav>
        <div className="sidebar-note">
          <span className="indicator" />
          Local workspace
        </div>
      </aside>
      <div className="workspace">
        <header className="topbar">
          <div className="topbar-label">
            <Activity size={17} aria-hidden="true" />
            Scan workspace
          </div>
          <div className="topbar-actions">
            <span
              className={`health-badge ${health.isSuccess ? 'health-ready' : health.isError ? 'health-error' : ''}`}
              role="status"
            >
              <span className="indicator" />
              {healthLabel}
            </span>
            <button
              type="button"
              className="icon-button theme-button"
              aria-label={`Switch to ${theme === 'dark' ? 'light' : 'dark'} theme`}
              onClick={() => setTheme(theme === 'dark' ? 'light' : 'dark')}
            >
              {theme === 'dark' ? (
                <Sun size={18} aria-hidden="true" />
              ) : (
                <Moon size={18} aria-hidden="true" />
              )}
            </button>
          </div>
        </header>
        <main
          className="main-content"
          id="main-content"
          tabIndex={-1}
          ref={main}
        >
          <Routes>
            <Route path="/" element={<OverviewPage {...sourceProps} />} />
            <Route
              path="/scans/new"
              element={<NewScan onSubmitted={changeSource} />}
            />
            <Route path="/scans/:id" element={<ResultsPage />} />
            <Route path="/scans/:id/report" element={<ReportPage />} />
            <Route path="/history" element={<HistoryPage {...sourceProps} />} />
            <Route
              path="/explorer"
              element={<ExplorerPage {...sourceProps} />}
            />
            <Route
              path="/remediation"
              element={<RemediationPage {...sourceProps} />}
            />
            <Route path="/compare" element={<ComparePage {...sourceProps} />} />
            <Route
              path="/settings"
              element={<SettingsPage theme={theme} setTheme={setTheme} />}
            />
            <Route
              path="*"
              element={
                <div className="panel">
                  <Empty title="Page not found">
                    <Link className="button secondary" to="/">
                      Back to overview
                    </Link>
                  </Empty>
                </div>
              }
            />
          </Routes>
        </main>
      </div>
    </div>
  )
}
