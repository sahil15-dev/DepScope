from pathlib import Path

import pytest
from depscope.service.web import create_web_app
from depscope.settings import Settings
from depscope.storage.database import sqlite_engine
from fastapi.testclient import TestClient

from .test_storage import migrate


def test_production_dashboard_and_api_share_loopback_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    db = tmp_path / "web.sqlite3"
    engine = sqlite_engine(db)
    migrate(engine)
    engine.dispose()
    build = tmp_path / "frontend" / "dist"
    (build / "assets").mkdir(parents=True)
    (build / "index.html").write_text("<!doctype html><title>DepScope</title>", encoding="utf-8")
    (build / "assets" / "app.js").write_text("void 0;", encoding="utf-8")
    (tmp_path / "private.txt").write_text("unpublished fixture", encoding="utf-8")
    monkeypatch.chdir(tmp_path)
    with TestClient(
        create_web_app(Settings(database_path=db)), base_url="http://localhost"
    ) as client:
        root = client.get("/")
        assert root.status_code == 200 and root.text.startswith("<!doctype html>")
        assert root.headers["cache-control"] == "no-cache"
        assert "frame-ancestors 'none'" in root.headers["content-security-policy"]
        assert root.headers["x-content-type-options"] == "nosniff"
        assert client.get("/compare").text == root.text
        assert client.get("/scans/new").text == root.text
        assert client.get("/scans/09d6732b-332d-41a5-a3d5-289796b9bb2d/report").text == root.text
        assert client.get("/assets/app.js").text == "void 0;"
        assert client.get("/api/health").json() == {"database": "ready", "status": "ready"}
        for path in (
            "/private.txt",
            "/assets/missing.js",
            "/api/unknown",
            "/assets/%2e%2e/private.txt",
        ):
            assert client.get(path).status_code == 404
        assert client.get("/", headers={"Host": "outside.invalid"}).status_code == 400
        rejected = client.post(
            "/api/scans?sample_id=python-clean", headers={"Origin": "https://outside.invalid"}
        )
        assert rejected.status_code == 403


def test_production_server_requires_a_frontend_build(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.chdir(tmp_path)
    with pytest.raises(RuntimeError, match="Build the dashboard"):
        create_web_app()
