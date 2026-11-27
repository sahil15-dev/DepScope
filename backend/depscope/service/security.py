import re

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from .errors import ServiceError

_HOST = re.compile(r"(?:localhost|127\.0\.0\.1|\[::1\])(?::[0-9]{1,5})?", re.IGNORECASE | re.ASCII)


class LocalRequests:
    def __init__(self, app: ASGIApp, *, origins: tuple[str, ...]) -> None:
        self._app = app
        self._origins = frozenset(origins)

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] == "http":
            headers = Headers(scope=scope)
            hosts = headers.getlist("host")
            if len(hosts) != 1 or not _HOST.fullmatch(hosts[0]):
                error = ServiceError(400, "invalid_host", "Use a loopback DepScope address.")
                await error.response()(scope, receive, send)
                return
            origins = headers.getlist("origin")
            if (
                scope["method"] in ("POST", "OPTIONS")
                and origins
                and (len(origins) != 1 or origins[0] not in self._origins)
            ):
                error = ServiceError(403, "origin_denied", "The browser origin is not allowed.")
                await error.response()(scope, receive, send)
                return
        await self._app(scope, receive, send)
