"""
OAuth Error Handling and Validation

Provides comprehensive error handling and input validation for OAuth endpoints.
"""

import logging
import re
from typing import Optional, Dict, Any, List
from starlette.responses import JSONResponse
from starlette.requests import Request
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


class OAuthError(Exception):
    """Base exception for OAuth-related errors."""

    def __init__(self, error_code: str, description: str, status_code: int = 400):
        self.error_code = error_code
        self.description = description
        self.status_code = status_code
        super().__init__(f"{error_code}: {description}")


class OAuthValidationError(OAuthError):
    """Exception for OAuth validation errors."""

    def __init__(self, description: str, field: Optional[str] = None):
        error_code = "invalid_request"
        if field:
            description = f"Invalid {field}: {description}"
        super().__init__(error_code, description, 400)


class OAuthConfigurationError(OAuthError):
    """Exception for OAuth configuration errors."""

    def __init__(self, description: str):
        super().__init__("server_error", description, 500)


def create_oauth_error_response(error: OAuthError, origin: Optional[str] = None) -> JSONResponse:
    """Create a standardized OAuth error response."""
    headers = {
        "Content-Type": "application/json",
        "Cache-Control": "no-store"
    }
    cors_headers = get_development_cors_headers(origin)
    headers.update(cors_headers)

    content = {
        "error": error.error_code,
        "error_description": error.description
    }

    logger.warning(f"OAuth error response: {error.error_code} - {error.description}")

    return JSONResponse(
        status_code=error.status_code,
        content=content,
        headers=headers
    )


def validate_redirect_uri(uri: str) -> None:
    """Validate an OAuth redirect URI."""
    if not uri:
        raise OAuthValidationError("Redirect URI is required", "redirect_uri")
    try:
        parsed = urlparse(uri)
    except Exception:
        raise OAuthValidationError("Malformed redirect URI", "redirect_uri")
    if not parsed.scheme or not parsed.netloc:
        raise OAuthValidationError("Redirect URI must be absolute", "redirect_uri")
    if parsed.scheme not in ["http", "https"]:
        raise OAuthValidationError("Redirect URI must use HTTP or HTTPS", "redirect_uri")
    if parsed.scheme == "http" and parsed.hostname not in ["localhost", "127.0.0.1"]:
        logger.warning(f"Insecure redirect URI: {uri}")


def validate_client_id(client_id: str) -> None:
    """Validate an OAuth client ID."""
    if not client_id:
        raise OAuthValidationError("Client ID is required", "client_id")
    if len(client_id) < 10:
        raise OAuthValidationError("Client ID is too short", "client_id")
    if not re.match(r'^[a-zA-Z0-9\-_.]+$', client_id):
        raise OAuthValidationError("Client ID contains invalid characters", "client_id")


def validate_authorization_code(code: str) -> None:
    """Validate an OAuth authorization code."""
    if not code:
        raise OAuthValidationError("Authorization code is required", "code")
    if len(code) < 10:
        raise OAuthValidationError("Authorization code is too short", "code")
    if any(char in code for char in [' ', '\n', '\t', '<', '>']):
        raise OAuthValidationError("Authorization code contains invalid characters", "code")


def validate_token_request(request_data: Dict[str, Any]) -> None:
    """Validate an OAuth token exchange request."""
    grant_type = request_data.get("grant_type")
    if not grant_type:
        raise OAuthValidationError("Grant type is required", "grant_type")
    if grant_type not in ["authorization_code", "refresh_token"]:
        raise OAuthValidationError(f"Unsupported grant type: {grant_type}", "grant_type")
    if grant_type == "authorization_code":
        code = request_data.get("code")
        validate_authorization_code(code)
        redirect_uri = request_data.get("redirect_uri")
        if redirect_uri:
            validate_redirect_uri(redirect_uri)
    client_id = request_data.get("client_id")
    if client_id:
        validate_client_id(client_id)


def validate_registration_request(request_data: Dict[str, Any]) -> None:
    """Validate an OAuth client registration request."""
    redirect_uris = request_data.get("redirect_uris", [])
    if redirect_uris:
        if not isinstance(redirect_uris, list):
            raise OAuthValidationError("redirect_uris must be an array", "redirect_uris")
        for uri in redirect_uris:
            validate_redirect_uri(uri)
    grant_types = request_data.get("grant_types", [])
    if grant_types:
        if not isinstance(grant_types, list):
            raise OAuthValidationError("grant_types must be an array", "grant_types")
        allowed_grant_types = ["authorization_code", "refresh_token"]
        for grant_type in grant_types:
            if grant_type not in allowed_grant_types:
                raise OAuthValidationError(f"Unsupported grant type: {grant_type}", "grant_types")
    response_types = request_data.get("response_types", [])
    if response_types:
        if not isinstance(response_types, list):
            raise OAuthValidationError("response_types must be an array", "response_types")
        allowed_response_types = ["code"]
        for response_type in response_types:
            if response_type not in allowed_response_types:
                raise OAuthValidationError(f"Unsupported response type: {response_type}", "response_types")


def log_security_event(event_type: str, details: Dict[str, Any], request: Optional[Request] = None) -> None:
    """Log security-related events for monitoring."""
    log_data = {
        "event_type": event_type,
        "details": details
    }
    if request:
        log_data["request"] = {
            "method": request.method,
            "path": request.url.path,
            "user_agent": request.headers.get("user-agent", "unknown"),
            "origin": request.headers.get("origin", "unknown")
        }
    logger.warning(f"Security event: {log_data}")


def get_development_cors_headers(origin: Optional[str] = None) -> Dict[str, str]:
    """
    Get minimal CORS headers for development scenarios only.
    Only allows localhost origins for development tools and inspectors.
    """
    if origin and (origin.startswith("http://localhost:") or origin.startswith("http://127.0.0.1:")):
        return {
            "Access-Control-Allow-Origin": origin,
            "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
            "Access-Control-Allow-Headers": "Content-Type, Authorization",
            "Access-Control-Max-Age": "3600"
        }
    return {}
