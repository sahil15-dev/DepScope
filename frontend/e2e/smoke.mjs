import assert from 'node:assert/strict'
import { spawn, spawnSync } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { mkdir, readFile } from 'node:fs/promises'
import { resolve } from 'node:path'
import process from 'node:process'
import { setTimeout as delay } from 'node:timers/promises'
import { chromium, firefox, webkit } from 'playwright'

const root = resolve(import.meta.dirname, '../..')
const output = resolve(root, 'artifacts', 'phase5-browser')
const database = resolve(output, `${randomUUID()}.sqlite3`)
const python =
  process.env.DEPSCOPE_E2E_PYTHON ||
  resolve(
    root,
    process.platform === 'win32'
      ? '.venv/Scripts/python.exe'
      : '.venv/bin/python',
  )
const origin = 'http://127.0.0.1:41736'
const env = {
  ...process.env,
  DEPSCOPE_DB_PATH: database,
  DEPSCOPE_ALLOWED_ORIGINS: origin,
}
const engines = { chromium, firefox, webkit }
const selected = [
  ...new Set((process.env.DEPSCOPE_E2E_BROWSERS || 'chromium').split(',')),
]
assert.ok(
  selected.every((name) => Object.hasOwn(engines, name)),
  'Choose chromium, firefox, or webkit',
)
await mkdir(output, { recursive: true })
assert.equal(
  spawnSync(python, ['-m', 'alembic', 'upgrade', 'head'], {
    cwd: root,
    stdio: 'inherit',
    windowsHide: true,
    env,
  }).status,
  0,
)

async function api(path, options) {
  const response = await fetch(`${origin}${path}`, {
    ...options,
    signal: AbortSignal.timeout(4000),
  })
  assert.ok(response.ok, `API returned ${response.status} for ${path}`)
  return response.json()
}

async function wait(check, name) {
  for (let attempt = 0; attempt < 180; attempt++) {
    const result = await check()
    if (result) return result
    await delay(80)
  }
  throw new Error(`Timed out waiting for ${name}`)
}

async function checkContrast(badge) {
  const ratio = await badge.evaluate((element) => {
    const style = getComputedStyle(element)
    const canvas = document.createElement('canvas')
    canvas.width = canvas.height = 1
    const context = canvas.getContext('2d')
    const luminance = (color) => {
      context.fillStyle = color
      context.fillRect(0, 0, 1, 1)
      const channels = context.getImageData(0, 0, 1, 1).data
      const linear = (channel) => {
        const value = channel / 255
        return value <= 0.04045
          ? value / 12.92
          : ((value + 0.055) / 1.055) ** 2.4
      }
      return (
        0.2126 * linear(channels[0]) +
        0.7152 * linear(channels[1]) +
        0.0722 * linear(channels[2])
      )
    }
    const text = luminance(style.color)
    const background = luminance(style.backgroundColor)
    return (
      (Math.max(text, background) + 0.05) / (Math.min(text, background) + 0.05)
    )
  })
  assert.ok(ratio >= 4.5, `Badge contrast was ${ratio.toFixed(2)}`)
}

async function verify(engine) {
  const captures = resolve(output, engine)
  await mkdir(captures, { recursive: true })
  const options =
    engine === 'chromium'
      ? {
          ...(process.env.DEPSCOPE_BROWSER
            ? { executablePath: process.env.DEPSCOPE_BROWSER }
            : process.env.DEPSCOPE_E2E_BUNDLED === '1'
              ? {}
              : { channel: 'chrome' }),
          args: ['--disable-background-networking', '--no-proxy-server'],
        }
      : {}
  const browser = await engines[engine].launch(options)
  let passed = 0
  try {
    const context = await browser.newContext({
      viewport: { width: 1440, height: 1000 },
      acceptDownloads: true,
    })
    const external = []
    await context.route('**/*', (route) => {
      if (new URL(route.request().url()).origin === origin)
        return route.continue()
      external.push(new URL(route.request().url()).origin)
      return route.abort()
    })
    const page = await context.newPage()
    page.setDefaultTimeout(10000)
    page.setDefaultNavigationTimeout(30000)
    const errors = []
    page.on('pageerror', (error) => errors.push(error.message))
    page.on('console', (entry) => {
      if (entry.type() === 'error') errors.push(entry.text())
    })
    const go = (path) =>
      page.goto(origin + path, { waitUntil: 'domcontentloaded' })
    const visible = (value) =>
      page.getByText(value, { exact: true }).first().waitFor()
    const click = (value) =>
      page.getByRole('button', { name: value, exact: true }).click()
    const screenshot = (name) =>
      page.screenshot({
        path: resolve(captures, `${name}.png`),
        fullPage: true,
        animations: 'disabled',
      })
    const frameFits = async () =>
      assert.equal(
        await page.evaluate(
          () => document.documentElement.scrollWidth <= innerWidth,
        ),
        true,
      )
    const resultId = () => new URL(page.url()).pathname.split('/')[2]
    const test = async (name, run) => {
      await run()
      assert.deepEqual(errors, [], `Browser errors in ${name}`)
      assert.deepEqual(
        external,
        [],
        `Unexpected outbound browser request in ${name}`,
      )
      passed++
      console.log(`[${engine}] PASS ${name}`)
    }

    const ids = []
    for (const sample of [
      'python-clean',
      'npm-vulnerable',
      'python-vulnerable',
      'python-vulnerable',
    ]) {
      const accepted = await api(`/api/scans?sample_id=${sample}`, {
        method: 'POST',
      })
      ids.push(accepted.id)
      await wait(
        async () => (await api(accepted.status_url)).scan.status === 'complete',
        sample,
      )
    }
    for (const [name, width, height] of [
      ['desktop', 1440, 1000],
      ['tablet', 900, 900],
      ['mobile', 390, 844],
    ]) {
      await test(`overview at ${width} × ${height}`, async () => {
        await page.setViewportSize({ width, height })
        await go('/')
        await visible('Recent scans')
        await page.locator('.chart .recharts-area-dot').first().waitFor()
        await page.evaluate(() => document.fonts.ready)
        await frameFits()
        const table = page.getByRole('region', { name: 'Scan records' })
        assert.equal(
          await table.evaluate(
            (element) => element.scrollWidth <= element.clientWidth,
          ),
          true,
        )
        await checkContrast(page.locator('.risk-summary .badge'))
        await screenshot(name)
      })
    }
    await page.setViewportSize({ width: 1440, height: 1000 })
    await test('offline submission retains fixture provenance', async () => {
      await go('/scans/new')
      await click('Run offline sample')
      await page.locator('.result-labels .status-complete').waitFor()
      const saved = await api(`/api/scans/${resultId()}`)
      assert.equal(saved.scan.provenance, 'offline_fixture')
      assert.equal(saved.scan.sample_id, 'python-vulnerable')
    })
    await test('upload validates the input and consent before submission', async () => {
      await go('/scans/new')
      await click('Upload file')
      await click('Start scan')
      await visible('Choose a nonempty dependency file.')
      await page
        .getByLabel('Dependency file')
        .setInputFiles(resolve(root, 'samples/package-lock-vulnerable.json'))
      await click('Start scan')
      await visible('Confirm the live OSV lookup before submitting.')
      await page.getByRole('checkbox', { name: /Allow live OSV/ }).check()
      await click('Start scan')
      await page.locator('.result-labels .status-complete').waitFor()
      const saved = await api(`/api/scans/${resultId()}`)
      assert.equal(saved.scan.source, 'upload')
      assert.equal(saved.scan.format, 'npm-lock')
      assert.deepEqual(saved.assessments.items[0].coordinate, {
        ecosystem: 'npm',
        name: 'lodash',
        version: '4.17.20',
      })
    })
    await test('paste sends the requirements and preserves unresolved entries', async () => {
      await go('/scans/new')
      await click('Paste manifest')
      await page
        .getByLabel('Manifest contents')
        .fill('Jinja2==3.1.2\r\nother>=1')
      await page.getByRole('checkbox', { name: /Allow live OSV/ }).check()
      await click('Start scan')
      await page.locator('.result-labels .status-complete').waitFor()
      const saved = await api(`/api/scans/${resultId()}`)
      assert.equal(saved.scan.source, 'paste')
      assert.equal(saved.scan.coverage.unresolved_occurrences, 1)
      assert.equal(saved.assessments.items[0].coordinate.name, 'jinja2')
    })
    await test('invalid lockfile reaches a safe failed status', async () => {
      await go('/scans/new')
      await click('Paste manifest')
      await page.getByLabel('Manifest format').selectOption('npm-lock')
      await page.getByLabel('Manifest contents').fill('{')
      await page.getByRole('checkbox', { name: /Allow live OSV/ }).check()
      await click('Start scan')
      await page.locator('.result-labels .status-failed').waitFor()
      await page
        .getByRole('alert')
        .getByText(/lockfile/i)
        .first()
        .waitFor()
      assert.equal(
        (await api(`/api/scans/${resultId()}`)).scan.error_code,
        'invalid_lockfile',
      )
    })
    await test('partial sample retains its diagnosis and hydrated findings', async () => {
      await go('/scans/new')
      await page.getByRole('radio', { name: /Partial advisory data/i }).check()
      await click('Run offline sample')
      await visible('Some advisory checks could not finish.')
      await click('Lookups')
      await visible('Advisory lookups')
      const saved = await api(`/api/scans/${resultId()}`)
      assert.equal(saved.scan.status, 'partial')
      assert.equal(saved.scan.coverage.partial_coordinates, 1)
    })
    await test('search, severity filtering, grouping, and advisory evidence', async () => {
      await go(`/scans/${ids[3]}`)
      await visible('jinja2')
      await page
        .getByLabel('Severity')
        .selectOption('critical')
      await visible('No matching findings')
      await page.getByLabel('Severity').selectOption('')
      await click('Dependency')
      await page.getByLabel('Package search').fill('jinja')
      await click('Search packages')
      await page.getByText('jinja2', { exact: true }).first().click()
      await page.locator('.group-content .finding-row summary').first().click()
      await page
        .getByRole('link', { name: /github advisory|github.com/i })
        .first()
        .waitFor()
      await screenshot('results')
    })
    await test('remediation shows applicable fixes and missing candidate evidence', async () => {
      await go(`/remediation?scan=${ids[3]}`)
      await page.getByText('jinja2', { exact: true }).first().click()
      await visible('Insufficient lookup evidence')
      await visible('Why this is prioritized')
      await screenshot('remediation')
    })
    await test('comparison separates findings and dependency changes', async () => {
      await go(`/compare?baseline=${ids[2]}&target=${ids[3]}`)
      await page.getByText('Unchanged findings', { exact: true }).click()
      await page
        .getByRole('rowheader', { name: /jinja2/i })
        .first()
        .waitFor()
      await screenshot('comparison')
      const [response] = await Promise.all([
        page.waitForResponse(
          (entry) =>
            entry.url() === `${origin}/api/scans/${ids[0]}/comparison/${ids[3]}` &&
            entry.ok(),
        ),
        page.getByLabel('Baseline scan').selectOption(ids[0]),
      ])
      await page
        .getByRole('rowheader', { name: /jinja2/i })
        .first()
        .waitFor()
      const comparison = await response.json()
      assert.equal(comparison.findings[0].kind, 'newly_detected')
    })
    await test('history reopens a saved result and filters by status', async () => {
      await go('/history')
      await page.getByLabel('Status').selectOption('partial')
      await page
        .getByRole('link', { name: 'Partial advisory data' })
        .first()
        .click()
      await visible('Some advisory checks could not finish.')
    })
    await test('report download matches the API and print mode keeps the evidence', async () => {
      await go(`/scans/${ids[3]}/report`)
      await page
        .getByRole('heading', { name: /jinja2/i })
        .first()
        .waitFor()
      const [download] = await Promise.all([
        page.waitForEvent('download'),
        page.getByRole('link', { name: 'Download JSON' }).click(),
      ])
      const jsonPath = resolve(captures, 'report.json')
      await download.saveAs(jsonPath)
      const report = JSON.parse(await readFile(jsonPath, 'utf8'))
      const findings = await api(`/api/scans/${ids[3]}/findings`)
      assert.equal(report.scan.id, ids[3])
      assert.equal(
        report.packages.flatMap((group) => group.findings).length,
        findings.total,
      )
      await screenshot('report')
      await page.emulateMedia({ media: 'print' })
      assert.equal(await page.locator('.report-actions').isVisible(), false)
      await checkContrast(page.locator('.report-page .status-complete'))
      await checkContrast(page.locator('.report-page .source-offline_fixture'))
      await screenshot('report-print')
      if (engine === 'chromium') {
        const pdf = await page.pdf({
          path: resolve(captures, 'report.pdf'),
          printBackground: true,
          format: 'A4',
        })
        assert.equal(pdf.subarray(0, 4).toString(), '%PDF')
      }
      await page.emulateMedia({ media: 'screen' })
    })
    await test('narrow analysis pages and persistent light and dark themes', async () => {
      await page.setViewportSize({ width: 390, height: 844 })
      for (const [path, ready] of [
        [`/remediation?scan=${ids[3]}`, 'Why this is prioritized'],
        [`/compare?baseline=${ids[2]}&target=${ids[3]}`, 'Unchanged findings'],
        [`/scans/${ids[3]}/report`, 'Findings by dependency'],
      ]) {
        await go(path)
        if (path.startsWith('/remediation'))
          await page.getByText('jinja2', { exact: true }).first().click()
        await visible(ready)
        await frameFits()
      }
      const refresh = await api('/api/scans?sample_id=python-vulnerable', {
        method: 'POST',
      })
      await wait(
        async () => (await api(refresh.status_url)).scan.status === 'complete',
        'latest demo scan',
      )
      await go('/')
      await page.locator('.chart .recharts-area-dot').first().waitFor()
      await click('Switch to light theme')
      await page.reload()
      assert.equal(
        await page.locator('html').getAttribute('data-theme'),
        'light',
      )
      await page.locator('.chart .recharts-area-dot').first().waitFor()
      await checkContrast(page.locator('.risk-summary .badge'))
      await frameFits()
      await screenshot('light-mobile')
      await click('Switch to dark theme')
      assert.equal(
        await page.locator('html').getAttribute('data-theme'),
        'dark',
      )
    })
    console.log(
      `[${engine}] ${passed} browser checks passed (${browser.version()})`,
    )
  } catch (error) {
    const page = browser.contexts().at(-1)?.pages().at(-1)
    await page
      ?.screenshot({ path: resolve(captures, 'failure.png'), fullPage: true })
      .catch(() => {})
    throw error
  } finally {
    await browser.close()
  }
  return passed
}

const server = spawn(
  python,
  [
    '-m',
    'uvicorn',
    'e2e.fixture_app:create_test_app',
    '--factory',
    '--host',
    '127.0.0.1',
    '--port',
    '41736',
    '--workers',
    '1',
    '--no-access-log',
    '--no-proxy-headers',
  ],
  { cwd: root, env, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] },
)
let log = ''
server.stderr.on('data', (chunk) => {
  log += chunk
})
try {
  await wait(() => {
    if (server.exitCode != null) throw new Error(log)
    return log.includes(`Uvicorn running on ${origin}`)
  }, 'local test service')
  let total = 0
  for (const engine of selected) total += await verify(engine)
  console.log(
    `${total} browser checks passed. Screenshots and exports saved to ${output}`,
  )
} finally {
  if (server.exitCode == null) server.kill()
}
