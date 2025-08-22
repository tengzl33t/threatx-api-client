class TXAPIError(Exception):
    """Common TX API Client exception class."""
    pass


class TXAPIIncorrectTokenError(TXAPIError):
    """TX API Client exception class for incorrect API token provided."""
    pass


class TXAPIIncorrectCommandError(TXAPIError):
    """TX API Client exception class for incorrect command provided."""
    pass


class TXAPIResponseError(TXAPIError):
    """TX API Client response error exception class."""
    pass

class TXAPIJSONError(TXAPIError):
    """TX API Client JSON response error exception class."""
    def __init__(self, status_code, message, request_id):
        """Additional fields to provide data in exception."""
        self.status_code = status_code
        self.message = message
        self.request_id = request_id
