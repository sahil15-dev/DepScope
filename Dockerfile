FROM node:22.22.0-bookworm-slim@sha256:dd9d21971ec4395903fa6143c2b9267d048ae01ca6d3ea96f16cb30df6187d94 AS frontend
WORKDIR /build
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --ignore-scripts --no-audit --no-fund
COPY frontend/ ./
RUN npm run build

FROM python:3.12-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64 AS python-build
WORKDIR /build
ENV PIP_DISABLE_PIP_VERSION_CHECK=1
COPY requirements/runtime.txt requirements/build.txt ./
RUN python -m venv /opt/depscope && /opt/depscope/bin/python -m pip install \
    --no-cache-dir --require-hashes --only-binary=:all: -r build.txt
COPY pyproject.toml README.md MANIFEST.in ./
COPY backend/depscope ./backend/depscope
RUN /opt/depscope/bin/python -m build --wheel --no-isolation \
    && /opt/depscope/bin/python -m pip install --no-cache-dir --no-deps dist/*.whl \
    && /opt/depscope/bin/python -m pip uninstall -y build pyproject-hooks setuptools wheel

FROM python:3.12-slim-bookworm@sha256:44cf1793efa7c7a476bb0f2cff81443f4a072c90c1cb127e2924933daa3e8c64
ENV PATH="/opt/depscope/bin:${PATH}" PYTHONUNBUFFERED=1 PYTHONDONTWRITEBYTECODE=1
WORKDIR /app
RUN install -d -o 10001 -g 10001 -m 0750 /app/data
COPY --from=python-build /opt/depscope /opt/depscope
COPY alembic.ini ./
COPY migrations/ ./migrations/
COPY samples/ ./samples/
COPY --from=frontend /build/dist ./frontend/dist
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=20s --timeout=4s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/api/health', timeout=2).close()"]
CMD ["sh", "-c", "alembic upgrade head && exec uvicorn depscope.service.web:create_web_app --factory --host 0.0.0.0 --port 8000 --workers 1 --no-proxy-headers --no-access-log"]
