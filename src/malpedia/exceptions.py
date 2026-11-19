"""Exceptions raised by the Malpedia client."""

from __future__ import annotations


class MalpediaError(Exception):
    """Base class for all errors raised by this package."""


class InvalidArgumentError(MalpediaError, ValueError):
    """An argument was rejected before any request was made."""


class APIError(MalpediaError):
    """The API answered with an unsuccessful status code.

    Attributes:
        status_code: HTTP status code of the response.
        detail: Error message from the API, or the HTTP reason phrase.
        url: URL of the failed request.
    """

    def __init__(self, status_code: int, detail: str, url: str) -> None:
        super().__init__(f"HTTP {status_code}: {detail}")
        self.status_code = status_code
        self.detail = detail
        self.url = url


class AuthenticationError(APIError):
    """The request lacked valid credentials or the account may not access the resource."""


class NotFoundError(APIError):
    """The requested resource does not exist."""


class ResponseError(MalpediaError):
    """The API answered successfully, but with content this client cannot interpret."""


class TransportError(MalpediaError):
    """The API could not be reached, or the connection failed or timed out."""
