# CI and dependency policy

The workflow runs on pushes to main, pull requests, and manual dispatch. It verifies linting, formatting, types, tests, builds, Python packaging, and the dashboard in Chromium, Firefox, and WebKit. It installs locked dependencies and browser tooling from public registries. Scanning tests use fixtures and mocks.

The workflow uses contents read permission, disables checkout credential persistence, pins actions to full commits, and omits privileged pull request triggers. [CI workflow](../.github/workflows/ci.yml)

## Apply a policy to one manifest

Run the installed scanner in a job that never installs the scanned dependencies. Use a trusted DepScope wheel and hash-locked runtime dependencies. Pass the command’s exit code through to the job. An incomplete result must fail the check.

~~~bash
depscope scan requirements.txt --live --format json --fail-on high
~~~

Use live mode only on manifests approved for sending their exact coordinates to OSV. The bundled offline fixture subset can test the integration with demo inputs. Use OSV for real repository checks.

## Compare a pull request with its baseline

Run this example from a trusted DepScope checkout with its virtual environment active. Give the job read-only access to the consumer repository’s Git objects. Pass its checkout path and both commit SHAs through environment variables. Use the pull request context to populate `BASE_SHA` and `HEAD_SHA` in the workflow’s environment. The scanner and its migration files must come from a separately trusted revision.

~~~bash
set -euo pipefail
mkdir -p artifacts
policy_dir=$(mktemp -d "$PWD/artifacts/consumer-policy.XXXXXXXX")
export DEPSCOPE_DB_PATH="$policy_dir/scan-history.sqlite3"
python -m alembic upgrade head

scan_ref() {
  local sha=$1 label=$2 size mode selector manifest
  [[ "$sha" =~ ^[a-fA-F0-9]{40}$ ]] || return 2
  selector="$sha:requirements.txt"
  mode=$(git -C "$CONSUMER_CHECKOUT" ls-tree "$sha" -- requirements.txt | cut -d ' ' -f 1) || return 2
  [[ "$mode" == 100644 || "$mode" == 100755 ]] || return 2
  size=$(git -C "$CONSUMER_CHECKOUT" cat-file -s "$selector") || return 2
  [[ "$size" =~ ^[0-9]+$ && "$size" -le 1000000 ]] || return 2
  manifest="$policy_dir/$label-requirements.txt"
  git -C "$CONSUMER_CHECKOUT" cat-file blob "$selector" > "$manifest" || return 2
  depscope scan "$manifest" --manifest-format requirements --live --save --format json |
    python -c 'import json, sys, uuid; print(uuid.UUID(json.load(sys.stdin)["scan_id"]))'
}

baseline=$(scan_ref "$BASE_SHA" baseline)
target=$(scan_ref "$HEAD_SHA" target)
depscope compare "$baseline" "$target" --fail-on "${DEPSCOPE_FAIL_ON:-high}"
~~~

This example reads a fixed manifest path from each set of Git objects. It runs no scripts from either revision. Use one comparison for each approved manifest and keep normalized history and JSON reports private. Run both scans close together because OSV data can change. Comparison reports newly detected findings and severity increases across the configured threshold. Findings already at or above the threshold in the baseline are treated as existing. Any nonzero exit fails the job, including incomplete coverage. [CLI exit codes](cli.md#exit-codes)
