# This Source Code Form is subject to the terms of the Mozilla Public
# License, v. 2.0. If a copy of the MPL was not distributed with this
# file, You can obtain one at https://mozilla.org/MPL/2.0/.
#
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: Copyright tengzl33t
#
# Author: tengzl33t

class TXAPIError(Exception):
    """Common TX API Client exception class."""


class TXAPIIncorrectTokenError(TXAPIError):
    """TX API Client exception class for incorrect API token provided."""


class TXAPIIncorrectCommandError(TXAPIError):
    """TX API Client exception class for incorrect command provided."""


class TXAPIResponseError(TXAPIError):
    """TX API Client response error exception class."""

class TXAPIJSONError(TXAPIError):
    """TX API Client JSON response error exception class."""
    def __init__(
            self, status_code: int, message: str,
            request_id: str, marker_var: str | None = None,
    ) -> None:
        """Additional fields to provide data in exception."""
        self.status_code = status_code
        self.message = message
        self.request_id = request_id
        self.marker_var = marker_var
