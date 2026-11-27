import { useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ArrowRight,
  Check,
  Clipboard,
  FileCode,
  FileUp,
  FlaskConical,
  ShieldCheck,
} from 'lucide-react'
import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import {
  api,
  type ManifestFormat,
  type Provenance,
  type SampleId,
  type Submission,
} from './api'
import { samples, scanRoute } from './presentation'
import { ErrorState, PageTitle, PanelHeader } from './ui'

type Mode = 'sample' | 'upload' | 'paste'
const modes = [
  { id: 'sample', name: 'Offline sample', icon: FlaskConical },
  { id: 'upload', name: 'Upload file', icon: FileUp },
  { id: 'paste', name: 'Paste manifest', icon: Clipboard },
] as const

export function NewScan({
  onSubmitted,
}: {
  onSubmitted: (source: Provenance) => void
}) {
  const navigate = useNavigate()
  const query = useQueryClient()
  const [mode, setMode] = useState<Mode>('sample')
  const [sample, setSample] = useState<SampleId>('python-vulnerable')
  const [format, setFormat] = useState<ManifestFormat>('requirements')
  const [file, setFile] = useState<File | null>(null)
  const [text, setText] = useState('')
  const [consent, setConsent] = useState(false)
  const [validation, setValidation] = useState<string | null>(null)
  const submit = useMutation({
    mutationFn: api.submit,
    onSuccess: (result, input) => {
      onSubmitted('sample' in input ? 'offline_fixture' : 'live_osv')
      void query.invalidateQueries({ queryKey: ['scans'] })
      void query.invalidateQueries({ queryKey: ['overview'] })
      navigate(scanRoute(result.id))
    },
  })

  function selectFile(value: File | null) {
    setFile(value)
    setValidation(null)
    if (value?.name.toLowerCase().endsWith('.json')) setFormat('npm-lock')
    else if (value?.name.toLowerCase().endsWith('.txt'))
      setFormat('requirements')
  }

  function send(event: FormEvent) {
    event.preventDefault()
    if (submit.isPending) return
    let input: Submission
    if (mode === 'sample') input = { sample }
    else {
      const body = mode === 'upload' ? file : text
      if (
        body === null ||
        (typeof body === 'string' && !body.trim()) ||
        (body instanceof File && body.size === 0)
      ) {
        setValidation(
          mode === 'upload'
            ? 'Choose a nonempty dependency file.'
            : 'Enter a dependency manifest.',
        )
        return
      }
      if (!consent) {
        setValidation('Confirm the live OSV lookup before submitting.')
        return
      }
      input = { format, source: mode, body }
    }
    setValidation(null)
    submit.mutate(input)
  }

  return (
    <>
      <PageTitle
        title="New dependency scan"
        description="Review a Python requirements file or npm lockfile for known advisories."
      />
      <div className="scan-grid">
        <section className="panel">
          <PanelHeader title="Choose a manifest source" />
          <form className="scan-form panel-body" onSubmit={send}>
            <div
              className="mode-control"
              role="group"
              aria-label="Input method"
            >
              {modes.map(({ id, name, icon: Icon }) => (
                <button
                  type="button"
                  key={id}
                  aria-pressed={mode === id}
                  disabled={submit.isPending}
                  onClick={() => {
                    setMode(id)
                    setConsent(false)
                    setValidation(null)
                    submit.reset()
                  }}
                >
                  <Icon size={17} aria-hidden="true" />
                  {name}
                </button>
              ))}
            </div>
            {mode === 'sample' ? (
              <fieldset className="sample-field">
                <legend>Bundled samples</legend>
                <div className="sample-options">
                  {samples.map((item) => (
                    <label key={item.id} className="sample-option">
                      <input
                        type="radio"
                        name="sample"
                        value={item.id}
                        checked={sample === item.id}
                        onChange={() => setSample(item.id)}
                        disabled={submit.isPending}
                      />
                      <span>
                        <strong>{item.title}</strong>
                        <small>{item.description}</small>
                      </span>
                      {sample === item.id && (
                        <Check
                          size={17}
                          className="selection-icon"
                          aria-hidden="true"
                        />
                      )}
                    </label>
                  ))}
                </div>
              </fieldset>
            ) : (
              <>
                {mode === 'upload' ? (
                  <label
                    className="dropzone"
                    onDragOver={(e) => e.preventDefault()}
                    onDrop={(event) => {
                      event.preventDefault()
                      if (!submit.isPending)
                        selectFile(event.dataTransfer.files[0] ?? null)
                    }}
                  >
                    <input
                      type="file"
                      aria-label="Dependency file"
                      accept=".txt,.json,text/plain,application/json"
                      disabled={submit.isPending}
                      onChange={(e) => selectFile(e.target.files?.[0] ?? null)}
                    />
                    <FileUp size={24} aria-hidden="true" />
                    <strong>
                      {file ? file.name : 'Choose a file or drop it here'}
                    </strong>
                    <small>
                      {file
                        ? `${file.size.toLocaleString()} bytes`
                        : 'requirements.txt or package-lock.json'}
                    </small>
                  </label>
                ) : (
                  <label>
                    Manifest contents
                    <textarea
                      rows={8}
                      value={text}
                      disabled={submit.isPending}
                      spellCheck={false}
                      onChange={(e) => {
                        setText(e.target.value)
                        setValidation(null)
                      }}
                      placeholder={
                        format === 'requirements'
                          ? 'package==1.2.3'
                          : '{ "lockfileVersion": 3, "packages": {} }'
                      }
                    />
                  </label>
                )}
                <label>
                  Manifest format
                  <select
                    value={format}
                    disabled={submit.isPending}
                    onChange={(event) =>
                      setFormat(event.target.value as ManifestFormat)
                    }
                  >
                    <option value="requirements">Python requirements</option>
                    <option value="npm-lock">npm lockfile</option>
                  </select>
                </label>
                <label className="consent">
                  <input
                    type="checkbox"
                    checked={consent}
                    disabled={submit.isPending}
                    onChange={(e) => setConsent(e.target.checked)}
                  />
                  <span>
                    Allow live OSV lookups for exact package names, versions,
                    and ecosystems.
                  </span>
                </label>
              </>
            )}
            {validation && (
              <p className="notice notice-error" role="alert">
                {validation}
              </p>
            )}
            {submit.isError && <ErrorState error={submit.error} />}
            <div className="form-actions">
              <span>
                {mode === 'sample'
                  ? 'No network lookups'
                  : 'Live advisory lookup'}
              </span>
              <button
                className="button primary"
                type="submit"
                disabled={submit.isPending}
              >
                {submit.isPending
                  ? 'Submitting…'
                  : mode === 'sample'
                    ? 'Run offline sample'
                    : 'Start scan'}
                <ArrowRight size={17} aria-hidden="true" />
              </button>
            </div>
          </form>
        </section>
        <aside className="panel policy-panel">
          <PanelHeader title="Input handling" />
          <div className="panel-body policy-list">
            <div>
              <FileCode size={19} aria-hidden="true" />
              <div>
                <h3>Exact versions only</h3>
                <p>
                  Pinned requirements and locked npm versions are assessed.
                  Ranges and unsupported sources appear as unresolved.
                </p>
              </div>
            </div>
            <div>
              <ShieldCheck size={19} aria-hidden="true" />
              <div>
                <h3>Local scan history</h3>
                <p>
                  DepScope stores normalized records and evidence. The original
                  manifest stays out of the database.
                </p>
              </div>
            </div>
            <div>
              <FlaskConical size={19} aria-hidden="true" />
              <div>
                <h3>Offline fixtures</h3>
                <p>
                  Samples use a curated advisory subset and are labeled
                  throughout the dashboard.
                </p>
              </div>
            </div>
          </div>
        </aside>
      </div>
    </>
  )
}
