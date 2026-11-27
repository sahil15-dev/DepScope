import re
from pathlib import Path

from fastapi import FastAPI
from starlette.exceptions import HTTPException
from starlette.responses import Response
from starlette.staticfiles import StaticFiles
from starlette.types import Scope

from ..scanner import AdvisoryProvider
from ..settings import Settings
from .api import create_app

_SCAN = re.compile(r"scans/[0-9a-fA-F-]{36}(?:/report)?")
_PAGES = frozenset(
    {"", ".", "scans/new", "history", "explorer", "remediation", "compare", "settings"}
)
_CONTENT_POLICY = (
    "default-src 'self'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'; "
    "img-src 'self' data:; style-src 'self' 'unsafe-inline'"
)


class DashboardFiles(StaticFiles):
    async def get_response(self, path: str, scope: Scope) -> Response:
        path = Path(path).as_posix()
        if path in _PAGES or _SCAN.fullmatch(path):
            response = await super().get_response("index.html", scope)
            response.headers["Cache-Control"] = "no-cache"
        elif path.startswith("assets/"):
            response = await super().get_response(path, scope)
        else:
            raise HTTPException(status_code=404)
        response.headers["Content-Security-Policy"] = _CONTENT_POLICY
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        return response


def create_web_app(
    settings: Settings | None = None, *, live_provider: AdvisoryProvider | None = None
) -> FastAPI:
    """Serve the production build and API from one loopback origin."""
    app = create_app(settings, live_provider=live_provider)
    application = Path.cwd().resolve()
    static = (application / "frontend" / "dist").resolve()
    if not static.is_relative_to(application) or not (static / "index.html").is_file():
        raise RuntimeError("Build the dashboard before starting the production service")
    app.mount("/", DashboardFiles(directory=static), name="dashboard")
    return app
