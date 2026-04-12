"""
Google Search Console OAuthProvider for FastMCP.

Full OAuth Authorization Server that:
1. Issues its own MCP tokens (auth codes, access tokens, refresh tokens)
2. Proxies authorization to Google for user consent
3. Stores Google credentials server-side, mapped to MCP tokens
4. Verifies MCP tokens on each /mcp request
"""

import os
import secrets
import time
import logging
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urlencode, parse_qs

import aiohttp
from pydantic import AnyHttpUrl
from starlette.requests import Request
from starlette.responses import RedirectResponse
from starlette.routing import Route
from google.oauth2.credentials import Credentials as GoogleCredentials

from mcp.server.auth.provider import (
    AccessToken as _SDKAccessToken,
    AuthorizationCode,
    AuthorizationParams,
    AuthorizeError,
    RefreshToken,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken

from fastmcp.server.auth.auth import OAuthProvider, AccessToken, ClientRegistrationOptions

from auth.scopes import SCOPES as GSC_SCOPES
from auth.credential_store import get_credential_store

logger = logging.getLogger(__name__)

DEFAULT_AUTH_CODE_EXPIRY = 5 * 60
DEFAULT_ACCESS_TOKEN_EXPIRY = 60 * 60
DEFAULT_REFRESH_TOKEN_EXPIRY = 30 * 24 * 60 * 60


class GoogleOAuthProvider(OAuthProvider):
    """
    OAuth Authorization Server that proxies to Google for user consent,
    then issues its own MCP tokens for the transport layer.
    """

    def __init__(self, *, base_url: str):
        self.google_client_id = (
            os.getenv("GOOGLE_OAUTH_CLIENT_ID")
            or os.getenv("GSC_OAUTH_CLIENT_ID")
        )
        self.google_client_secret = (
            os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
            or os.getenv("GSC_OAUTH_CLIENT_SECRET")
        )
        if not self.google_client_id or not self.google_client_secret:
            raise ValueError(
                "GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET are required"
            )

        self.google_callback_uri = f"{base_url.rstrip('/')}/oauth2callback"

        super().__init__(
            base_url=base_url,
            required_scopes=GSC_SCOPES,
            client_registration_options=ClientRegistrationOptions(
                enabled=True,
                valid_scopes=GSC_SCOPES,
                default_scopes=GSC_SCOPES,
            ),
        )

        # In-memory stores (survive for the lifetime of the process)
        self.clients: dict[str, OAuthClientInformationFull] = {}
        self.auth_codes: dict[str, AuthorizationCode] = {}
        self.access_tokens: dict[str, AccessToken] = {}
        self.refresh_tokens: dict[str, RefreshToken] = {}

        # Mappings: MCP token → user email (to retrieve Google creds)
        self.pending_authorizations: dict[str, dict] = {}
        self.auth_code_to_email: dict[str, str] = {}
        self.token_to_email: dict[str, str] = {}

        logger.info(
            "GoogleOAuthProvider initialized: base_url=%s, google_callback=%s",
            base_url,
            self.google_callback_uri,
        )

    # ------------------------------------------------------------------
    # Client registration
    # ------------------------------------------------------------------

    async def get_client(self, client_id: str) -> Optional[OAuthClientInformationFull]:
        return self.clients.get(client_id)

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        self.clients[client_info.client_id] = client_info
        logger.info("Registered MCP client: %s", client_info.client_id)

    # ------------------------------------------------------------------
    # Authorization  (MCP client → Google consent → callback → MCP client)
    # ------------------------------------------------------------------

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        google_state = secrets.token_urlsafe(32)

        scopes = params.scopes if params.scopes else list(GSC_SCOPES)

        self.pending_authorizations[google_state] = {
            "client_id": client.client_id,
            "redirect_uri": str(params.redirect_uri),
            "redirect_uri_provided_explicitly": params.redirect_uri_provided_explicitly,
            "state": params.state,
            "code_challenge": params.code_challenge,
            "scopes": scopes,
        }

        google_params: dict[str, str] = {
            "response_type": "code",
            "client_id": self.google_client_id,
            "redirect_uri": self.google_callback_uri,
            "scope": " ".join(GSC_SCOPES + ["openid", "email"]),
            "state": google_state,
            "access_type": "offline",
            "prompt": "consent",
        }

        logger.info(
            "authorize(): redirecting to Google (state=%s, client=%s)",
            google_state,
            client.client_id,
        )
        return (
            "https://accounts.google.com/o/oauth2/v2/auth?"
            + urlencode(google_params)
        )

    # ------------------------------------------------------------------
    # Google callback  (/oauth2callback)
    # ------------------------------------------------------------------

    async def _handle_google_callback(self, request: Request):
        """
        Receives Google's auth code, exchanges it for Google tokens,
        stores Google credentials, generates an MCP auth code, and
        redirects to the MCP client's redirect_uri.
        """
        error = request.query_params.get("error")
        if error:
            logger.error("Google returned error: %s", error)
            return RedirectResponse(
                construct_redirect_uri(
                    "about:blank",
                    error="access_denied",
                    error_description=f"Google error: {error}",
                )
            )

        google_code = request.query_params.get("code")
        google_state = request.query_params.get("state")

        if not google_code or not google_state:
            logger.error("Missing code or state in Google callback")
            return RedirectResponse(
                construct_redirect_uri(
                    "about:blank",
                    error="invalid_request",
                    error_description="Missing code or state",
                )
            )

        pending = self.pending_authorizations.pop(google_state, None)
        if not pending:
            logger.error("Unknown state in Google callback: %s", google_state)
            return RedirectResponse(
                construct_redirect_uri(
                    "about:blank",
                    error="invalid_request",
                    error_description="Unknown or expired state",
                )
            )

        # Exchange Google auth code for Google tokens
        token_data = await self._exchange_google_code(google_code)
        if not token_data or "access_token" not in token_data:
            logger.error("Google token exchange failed: %s", token_data)
            return RedirectResponse(
                construct_redirect_uri(
                    pending["redirect_uri"],
                    error="server_error",
                    error_description="Failed to exchange Google authorization code",
                    state=pending["state"],
                )
            )

        # Extract user email from Google tokens
        user_email = await self._extract_user_email(token_data)
        if not user_email:
            logger.error("Could not determine user email from Google tokens")
            return RedirectResponse(
                construct_redirect_uri(
                    pending["redirect_uri"],
                    error="server_error",
                    error_description="Could not determine user identity",
                    state=pending["state"],
                )
            )

        # Store Google credentials on disk (persistent across restarts)
        self._store_google_credentials(user_email, token_data)

        # Generate MCP authorization code
        mcp_code = secrets.token_urlsafe(32)
        self.auth_codes[mcp_code] = AuthorizationCode(
            code=mcp_code,
            client_id=pending["client_id"],
            redirect_uri=AnyHttpUrl(pending["redirect_uri"]),
            redirect_uri_provided_explicitly=pending["redirect_uri_provided_explicitly"],
            scopes=pending["scopes"],
            expires_at=time.time() + DEFAULT_AUTH_CODE_EXPIRY,
            code_challenge=pending["code_challenge"],
        )
        self.auth_code_to_email[mcp_code] = user_email

        logger.info(
            "Google callback success: user=%s, redirecting to client", user_email
        )
        return RedirectResponse(
            construct_redirect_uri(
                pending["redirect_uri"],
                code=mcp_code,
                state=pending["state"],
            )
        )

    async def _exchange_google_code(self, code: str) -> Optional[dict]:
        """Exchange a Google authorization code for tokens."""
        payload = {
            "code": code,
            "client_id": self.google_client_id,
            "client_secret": self.google_client_secret,
            "redirect_uri": self.google_callback_uri,
            "grant_type": "authorization_code",
        }
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    "https://oauth2.googleapis.com/token",
                    data=payload,
                ) as resp:
                    data = await resp.json()
                    if resp.status != 200:
                        logger.error("Google token exchange HTTP %d: %s", resp.status, data)
                        return None
                    return data
        except Exception as e:
            logger.error("Google token exchange error: %s", e, exc_info=True)
            return None

    async def _extract_user_email(self, token_data: dict) -> Optional[str]:
        """
        Get user email from id_token or userinfo endpoint.

        Signature verification is skipped because the id_token was received
        directly from Google's token endpoint over TLS in _exchange_google_code(),
        not from the client. A user cannot inject a forged id_token into this flow.
        """
        # Try id_token first (fast, no extra request)
        id_token = token_data.get("id_token")
        if id_token:
            try:
                import jwt as pyjwt
                claims = pyjwt.decode(id_token, options={"verify_signature": False})
                email = claims.get("email")
                if email and claims.get("email_verified", False):
                    return email
                if email and not claims.get("email_verified", False):
                    logger.warning("Rejecting unverified email from id_token: %s", email)
            except Exception as e:
                logger.debug("id_token decode failed: %s", e)

        # Fallback: call Google userinfo endpoint (also server-to-server over TLS)
        access_token = token_data.get("access_token")
        if access_token:
            try:
                async with aiohttp.ClientSession() as session:
                    async with session.get(
                        "https://www.googleapis.com/oauth2/v3/userinfo",
                        headers={"Authorization": f"Bearer {access_token}"},
                    ) as resp:
                        if resp.status == 200:
                            info = await resp.json()
                            email = info.get("email")
                            if email and info.get("email_verified", False):
                                return email
                            if email:
                                logger.warning("Rejecting unverified email from userinfo: %s", email)
            except Exception as e:
                logger.debug("userinfo fetch failed: %s", e)

        return None

    def _store_google_credentials(self, user_email: str, token_data: dict) -> None:
        """Persist Google credentials to the credential store."""
        expiry = None
        if "expires_in" in token_data:
            expiry = datetime.utcnow() + timedelta(seconds=token_data["expires_in"])

        creds = GoogleCredentials(
            token=token_data["access_token"],
            refresh_token=token_data.get("refresh_token"),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=self.google_client_id,
            client_secret=self.google_client_secret,
            scopes=token_data.get("scope", "").split() or None,
            expiry=expiry,
        )

        store = get_credential_store()
        if store.store_credential(user_email, creds):
            logger.info("Stored Google credentials for %s", user_email)
        else:
            logger.error("Failed to store Google credentials for %s", user_email)

    # ------------------------------------------------------------------
    # Token exchange  (MCP auth code → MCP access/refresh tokens)
    # ------------------------------------------------------------------

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> Optional[AuthorizationCode]:
        ac = self.auth_codes.get(authorization_code)
        if not ac:
            return None
        if ac.client_id != client.client_id:
            return None
        if ac.expires_at < time.time():
            self.auth_codes.pop(authorization_code, None)
            self.auth_code_to_email.pop(authorization_code, None)
            return None
        return ac

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        self.auth_codes.pop(authorization_code.code, None)
        user_email = self.auth_code_to_email.pop(authorization_code.code, None)

        access_token_value = secrets.token_urlsafe(32)
        refresh_token_value = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + DEFAULT_ACCESS_TOKEN_EXPIRY

        self.access_tokens[access_token_value] = AccessToken(
            token=access_token_value,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=expires_at,
            claims={"email": user_email},
        )

        self.refresh_tokens[refresh_token_value] = RefreshToken(
            token=refresh_token_value,
            client_id=client.client_id,
            scopes=authorization_code.scopes,
            expires_at=int(time.time()) + DEFAULT_REFRESH_TOKEN_EXPIRY,
        )

        self.token_to_email[access_token_value] = user_email
        self.token_to_email[refresh_token_value] = user_email

        logger.info(
            "Issued MCP tokens for user=%s (client=%s)", user_email, client.client_id
        )

        return OAuthToken(
            access_token=access_token_value,
            token_type="Bearer",
            expires_in=DEFAULT_ACCESS_TOKEN_EXPIRY,
            refresh_token=refresh_token_value,
            scope=" ".join(authorization_code.scopes),
        )

    # ------------------------------------------------------------------
    # Refresh token exchange
    # ------------------------------------------------------------------

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> Optional[RefreshToken]:
        rt = self.refresh_tokens.get(refresh_token)
        if not rt:
            return None
        if rt.client_id != client.client_id:
            return None
        if rt.expires_at is not None and rt.expires_at < time.time():
            self.refresh_tokens.pop(refresh_token, None)
            self.token_to_email.pop(refresh_token, None)
            return None
        return rt

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        user_email = self.token_to_email.get(refresh_token.token)

        # Also refresh the underlying Google token if we have a refresh_token
        if user_email:
            self._try_refresh_google_token(user_email)

        # Rotate MCP tokens
        self.refresh_tokens.pop(refresh_token.token, None)
        self.token_to_email.pop(refresh_token.token, None)

        new_access = secrets.token_urlsafe(32)
        new_refresh = secrets.token_urlsafe(32)
        expires_at = int(time.time()) + DEFAULT_ACCESS_TOKEN_EXPIRY

        self.access_tokens[new_access] = AccessToken(
            token=new_access,
            client_id=client.client_id,
            scopes=scopes,
            expires_at=expires_at,
            claims={"email": user_email},
        )
        self.refresh_tokens[new_refresh] = RefreshToken(
            token=new_refresh,
            client_id=client.client_id,
            scopes=scopes,
            expires_at=int(time.time()) + DEFAULT_REFRESH_TOKEN_EXPIRY,
        )

        self.token_to_email[new_access] = user_email
        self.token_to_email[new_refresh] = user_email

        logger.info("Rotated MCP tokens for user=%s", user_email)

        return OAuthToken(
            access_token=new_access,
            token_type="Bearer",
            expires_in=DEFAULT_ACCESS_TOKEN_EXPIRY,
            refresh_token=new_refresh,
            scope=" ".join(scopes),
        )

    def _try_refresh_google_token(self, user_email: str) -> None:
        """Attempt to refresh the stored Google token for a user."""
        try:
            from google.auth.transport.requests import Request as GoogleAuthRequest
            store = get_credential_store()
            creds = store.get_credential(user_email)
            if creds and creds.expired and creds.refresh_token:
                creds.refresh(GoogleAuthRequest())
                store.store_credential(user_email, creds)
                logger.info("Refreshed Google token for %s", user_email)
        except Exception as e:
            logger.warning("Could not refresh Google token for %s: %s", user_email, e)

    # ------------------------------------------------------------------
    # Token verification  (called on every /mcp request)
    # ------------------------------------------------------------------

    async def load_access_token(self, token: str) -> Optional[AccessToken]:
        at = self.access_tokens.get(token)
        if not at:
            return None
        if at.expires_at is not None and at.expires_at < time.time():
            self.access_tokens.pop(token, None)
            self.token_to_email.pop(token, None)
            return None
        return at

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        return await self.load_access_token(token)

    # ------------------------------------------------------------------
    # Token revocation
    # ------------------------------------------------------------------

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        if isinstance(token, AccessToken):
            self.access_tokens.pop(token.token, None)
            self.token_to_email.pop(token.token, None)
        elif isinstance(token, RefreshToken):
            self.refresh_tokens.pop(token.token, None)
            self.token_to_email.pop(token.token, None)

    # ------------------------------------------------------------------
    # Routes: add /oauth2callback alongside standard OAuth routes
    # ------------------------------------------------------------------

    def get_routes(self) -> list[Route]:
        routes = super().get_routes()
        routes.append(
            Route(
                "/oauth2callback",
                endpoint=self._handle_google_callback,
                methods=["GET"],
            )
        )
        return routes

    # ------------------------------------------------------------------
    # Helper: look up user email from an MCP access token string
    # ------------------------------------------------------------------

    def get_user_email(self, token: str) -> Optional[str]:
        return self.token_to_email.get(token)
