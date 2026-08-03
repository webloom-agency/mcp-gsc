"""
Compat fixes for MCP SDK client authentication vs DCR defaults.

The MCP TypeScript SDK prefers ``client_secret_basic`` whenever the AS
metadata advertises it. Our DCR path (and Wegen) registers clients as
``client_secret_post``. The stock MCP ``ClientAuthenticator`` then only
reads the secret from the form body → 401 "Client secret is required"
on /token even though Google consent succeeded.

Fix:
1. Advertise only ``client_secret_post`` in AS metadata (steers the SDK).
2. Accept Basic *or* form secrets at /token (defensive for older clients).
"""

from __future__ import annotations

import base64
import binascii
import hmac
import logging
import time
from urllib.parse import unquote

from starlette.requests import Request

from mcp.server.auth.middleware.client_auth import (
    AuthenticationError,
    ClientAuthenticator,
)
from mcp.shared.auth import OAuthClientInformationFull

logger = logging.getLogger(__name__)

_APPLIED = False


async def _flexible_authenticate_request(
    self: ClientAuthenticator, request: Request
) -> OAuthClientInformationFull:
    form_data = await request.form()
    client_id = form_data.get("client_id")
    auth_header = request.headers.get("Authorization", "")

    # client_id may only be in Basic auth when SDK uses client_secret_basic
    basic_client_id: str | None = None
    basic_secret: str | None = None
    if auth_header.startswith("Basic "):
        try:
            decoded = base64.b64decode(auth_header[6:]).decode("utf-8")
            if ":" in decoded:
                basic_client_id, basic_secret = decoded.split(":", 1)
                basic_client_id = unquote(basic_client_id)
                basic_secret = unquote(basic_secret)
        except (ValueError, UnicodeDecodeError, binascii.Error):
            raise AuthenticationError("Invalid Basic authentication header")

    if not client_id:
        client_id = basic_client_id
    if not client_id:
        raise AuthenticationError("Missing client_id")

    client = await self.provider.get_client(str(client_id))
    if not client:
        logger.error(
            "/token: invalid_client_id=%s (DCR client missing from memory/disk)",
            client_id,
        )
        raise AuthenticationError("Invalid client_id")

    if basic_client_id and basic_client_id != str(client_id):
        raise AuthenticationError("Client ID mismatch in Basic auth")

    request_client_secret: str | None = None
    raw_form_secret = form_data.get("client_secret")
    if isinstance(raw_form_secret, str) and raw_form_secret:
        request_client_secret = raw_form_secret
    elif basic_secret:
        request_client_secret = basic_secret

    if client.client_secret:
        if not request_client_secret:
            logger.error(
                "/token: client_secret missing for client_id=%s "
                "(registered_method=%s; send Basic or form secret)",
                client_id,
                client.token_endpoint_auth_method,
            )
            raise AuthenticationError("Client secret is required")
        if not hmac.compare_digest(
            client.client_secret.encode(), request_client_secret.encode()
        ):
            logger.error(
                "/token: invalid client_secret for client_id=%s",
                client_id,
            )
            raise AuthenticationError("Invalid client_secret")
        if client.client_secret_expires_at and client.client_secret_expires_at < int(
            time.time()
        ):
            raise AuthenticationError("Client secret has expired")

    return client


def apply_mcp_client_auth_compat() -> None:
    """Idempotent process-wide patch; call once when loading GoogleOAuthProvider."""
    global _APPLIED
    if _APPLIED:
        return

    from mcp.server.auth import routes as routes_mod

    ClientAuthenticator.authenticate_request = _flexible_authenticate_request  # type: ignore[method-assign]

    _original_build_metadata = routes_mod.build_metadata

    def _build_metadata_post_preferred(*args, **kwargs):
        metadata = _original_build_metadata(*args, **kwargs)
        # Steer MCP TS SDK away from Basic (it prefers Basic when advertised).
        metadata.token_endpoint_auth_methods_supported = ["client_secret_post"]
        if metadata.revocation_endpoint_auth_methods_supported is not None:
            metadata.revocation_endpoint_auth_methods_supported = [
                "client_secret_post"
            ]
        return metadata

    routes_mod.build_metadata = _build_metadata_post_preferred  # type: ignore[assignment]
    _APPLIED = True
    logger.info(
        "MCP client-auth compat enabled: metadata advertises client_secret_post only; "
        "/token accepts Basic or form client secrets"
    )
