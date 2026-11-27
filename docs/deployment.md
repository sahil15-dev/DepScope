# Local deployment

DepScope is a single-user application. The API, frontend, and SQLite history run under one service. Local users and processes can access the loopback listener. Keep the port bound to loopback and use one worker per database.

## Docker Compose

Use Docker Desktop or Docker Engine with a Compose release that supports `up --wait`. From the workspace root in PowerShell, run the following commands.

~~~powershell
docker compose --env-file .env.example config --quiet
docker compose --env-file .env.example up --build -d --wait
docker compose --env-file .env.example ps
Invoke-RestMethod http://127.0.0.1:8000/api/health
~~~

Open `http://127.0.0.1:8000`. The build uses digest-pinned Node and slim Python images, hash-locked Python wheels, and the npm lockfile. The final image serves the dashboard and the API from one origin. It runs as UID and GID 10001, drops Linux capabilities, uses a read-only root filesystem, and mounts a writable named SQLite volume. Compose publishes the container port to IPv4 loopback on the host.

Startup applies Alembic migrations before opening the listener. The health check verifies local SQLite readiness. Use the same named volume for upgrades. For a consistent backup, stop the service and copy the SQLite data with your Docker backup tooling. Keep backups and reports within the privacy boundary of the live database.

~~~powershell
docker compose --env-file .env.example logs --tail 60 depscope
docker compose --env-file .env.example restart depscope
docker compose --env-file .env.example down
~~~

Stopping or bringing down the service retains the named volume. If the port is occupied, set `$env:DEPSCOPE_PORT = '8001'` before starting and open the corresponding URL. For startup failures, check that Docker Desktop is running in Linux container mode and inspect the service logs. If the database came from a bind mount, ensure UID 10001 can write the target directory. The health check remains local when OSV is unavailable.

Phase 5 verified configuration and image build with Compose 5.1.3 and Docker Engine 29.5.2 on Linux amd64 under Docker Desktop. The runtime check verified loopback publication, UID 10001, a read-only root, health, a real offline fixture scan, and identical saved report content after restart.

## macOS and Linux source setup

Use CPython 3.12–3.14 and Node.js 22.22 or a compatible newer release. From the repository root, install the locked dependencies, initialize SQLite, and start the API.

~~~bash
python3 -m venv .venv
.venv/bin/python -m pip install --require-hashes --only-binary=:all: -r requirements/build.txt -r requirements/dev.txt
.venv/bin/python -m pip install --no-deps --no-build-isolation -e .
.venv/bin/python -m alembic upgrade head
DEPSCOPE_ALLOWED_ORIGINS=http://127.0.0.1:5173 \
  .venv/bin/python -m uvicorn depscope.service.api:create_app --factory \
  --host 127.0.0.1 --port 8000 --workers 1 --no-proxy-headers --no-access-log
~~~

In a second terminal, run the dashboard and open `http://127.0.0.1:5173`.

~~~bash
cd frontend
npm ci --ignore-scripts --cache ../artifacts/npm-cache --no-audit --no-fund
npm run dev
~~~

## Same-origin server without Docker

Install the Python dependencies, build the frontend, migrate SQLite, and launch the production factory from the workspace root.

~~~powershell
& .\.venv\Scripts\python.exe -m alembic upgrade head
Push-Location .\frontend
npm.cmd run build
Pop-Location
& .\.venv\Scripts\python.exe -m uvicorn depscope.service.web:create_web_app --factory --host 127.0.0.1 --port 8000 --workers 1 --no-proxy-headers --no-access-log
~~~

The production factory serves known dashboard routes and assets. It applies a content security policy and preserves the API’s host and origin validation. [API configuration and migrations](api.md)
