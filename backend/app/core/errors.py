class DomainError(Exception):
    def __init__(self, message: str, status_code: int = 422, code: str = "invalid_input") -> None:
        super().__init__(message)
        self.message = message
        self.status_code = status_code
        self.code = code
