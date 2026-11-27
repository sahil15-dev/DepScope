class ScanError(Exception):
    """A safe, structured scanner error for local clients."""

    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)
