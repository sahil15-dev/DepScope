from pydantic import BaseModel
from starlette.responses import JSONResponse


class ErrorDetail(BaseModel):
    code: str
    message: str


class ErrorResponse(BaseModel):
    error: ErrorDetail


class ServiceError(Exception):
    def __init__(self, status: int, code: str, message: str, **headers: str) -> None:
        super().__init__(code)
        self.status = status
        self.code = code
        self.message = message
        self.headers = {name.replace("_", "-"): value for name, value in headers.items()}

    def response(self) -> JSONResponse:
        return JSONResponse(
            ErrorResponse(error=ErrorDetail(code=self.code, message=self.message)).model_dump(),
            status_code=self.status,
            headers=self.headers,
        )


def database_unavailable() -> ServiceError:
    return ServiceError(503, "database_unavailable", "The local scan database is unavailable.")


def scan_not_found() -> ServiceError:
    return ServiceError(404, "scan_not_found", "The requested scan was not found.")
