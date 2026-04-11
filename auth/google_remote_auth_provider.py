"""
Google Search Console RemoteAuthProvider for FastMCP v2.11.1+

Implements OAuth 2.1 authentication using FastMCP's RemoteAuthProvider pattern.
Provides JWT token verification using Google's public keys, OAuth proxy endpoints,
dynamic client registration, and session bridging to Google credentials.
"""

import logging
import time
import aiohttp
from typing import Optional, List

from starlette.routing import Route
from pydantic import AnyHttpUrl

try:
    from fastmcp.server.auth import RemoteAuthProvider, AccessToken
    from fastmcp.server.auth.providers.jwt import JWTVerifier

    REMOTEAUTHPROVIDER_AVAILABLE = True
except ImportError:
    REMOTEAUTHPROVIDER_AVAILABLE = False
    RemoteAuthProvider = object
    JWTVerifier = object
    AccessToken = None

from auth.oauth_common_handlers import (
    handle_oauth_authorize,
    handle_proxy_token_exchange,
    handle_oauth_protected_resource,
    handle_oauth_authorization_server,
    handle_oauth_client_config,
    handle_oauth_register,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


class GoogleRemoteAuthProvider(RemoteAuthProvider):
    """
    RemoteAuthProvider implementation for Google Search Console.

    Extends RemoteAuthProvider to add OAuth proxy endpoints for CORS workaround,
    dynamic client registration support, and session management with issuer tracking.
    """

    def __init__(self):
        if not REMOTEAUTHPROVIDER_AVAILABLE:
            raise ImportError("FastMCP v2.11.1+ required for RemoteAuthProvider")

        from auth.oauth_config import get_oauth_config
        config = get_oauth_config()

        self.client_id = config.client_id
        self.client_secret = config.client_secret
        self.base_url = config.get_oauth_base_url()
        self.port = config.port

        if not self.client_id:
            logger.error("GOOGLE_OAUTH_CLIENT_ID not set - OAuth 2.1 authentication will not work")
            raise ValueError("GOOGLE_OAUTH_CLIENT_ID environment variable is required for OAuth 2.1 authentication")

        token_verifier = JWTVerifier(
            jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
            issuer="https://accounts.google.com",
            audience=self.client_id,
            algorithm="RS256",
        )

        super().__init__(
            token_verifier=token_verifier,
            authorization_servers=[AnyHttpUrl(self.base_url)],
            resource_server_url=self.base_url,
        )

        logger.debug(f"Initialized GoogleRemoteAuthProvider with base_url={self.base_url}")

    def get_routes(self) -> List[Route]:
        parent_routes = super().get_routes()

        routes = [
            r for r in parent_routes
            if r.path != "/.well-known/oauth-protected-resource"
        ]

        routes.append(
            Route("/.well-known/oauth-protected-resource", handle_oauth_protected_resource, methods=["GET", "OPTIONS"])
        )
        routes.append(
            Route("/.well-known/oauth-authorization-server", handle_oauth_authorization_server, methods=["GET", "OPTIONS"])
        )
        routes.append(
            Route("/.well-known/oauth-client", handle_oauth_client_config, methods=["GET", "OPTIONS"])
        )
        routes.append(
            Route("/oauth2/authorize", handle_oauth_authorize, methods=["GET", "OPTIONS"])
        )
        routes.append(
            Route("/oauth2/token", handle_proxy_token_exchange, methods=["POST", "OPTIONS"])
        )
        routes.append(
            Route("/oauth2/register", handle_oauth_register, methods=["POST", "OPTIONS"])
        )

        logger.info(f"Registered {len(routes)} OAuth routes")
        return routes

    async def verify_token(self, token: str) -> Optional[AccessToken]:
        """
        Override verify_token to handle Google OAuth access tokens.

        Google OAuth access tokens (ya29.*) are opaque tokens that need to be
        verified using the tokeninfo endpoint, not JWT verification.
        """
        token_prefix = token[:10] if len(token) > 10 else token
        logger.info(f"verify_token called, token starts with: {token_prefix}...")

        if token.startswith("ya29."):
            logger.info("Detected Google OAuth access token, using tokeninfo verification")

            try:
                async with aiohttp.ClientSession() as session:
                    url = f"https://oauth2.googleapis.com/tokeninfo?access_token={token}"
                    async with session.get(url) as response:
                        if response.status != 200:
                            logger.info(f"Token verification failed: {response.status}")
                            return None

                        token_info = await response.json()
                        logger.info(f"tokeninfo response: aud={token_info.get('aud')}, email={token_info.get('email')}, expires_in={token_info.get('expires_in')}")

                        if token_info.get("aud") != self.client_id:
                            logger.info(
                                f"Token audience mismatch: expected {self.client_id}, got {token_info.get('aud')}"
                            )
                            return None

                        expires_in = int(token_info.get("expires_in", 0))
                        if expires_in <= 0:
                            logger.info("Token is expired")
                            return None

                        expires_at = int(time.time()) + expires_in

                        claims = {
                            "email": token_info.get("email"),
                            "sub": token_info.get("sub"),
                            "aud": token_info.get("aud"),
                            "scope": token_info.get("scope", ""),
                        }
                        scopes = token_info.get("scope", "").split()

                        access_token_obj = AccessToken(
                            token=token,
                            client_id=self.client_id,
                            scopes=scopes,
                            expires_at=expires_at,
                            claims=claims,
                        )

                        user_email = token_info.get("email")
                        if user_email:
                            from auth.oauth21_session_store import get_oauth21_session_store

                            store = get_oauth21_session_store()
                            session_id = f"google_{token_info.get('sub', 'unknown')}"

                            mcp_session_id = None
                            try:
                                from fastmcp.server.dependencies import get_context
                                ctx = get_context()
                                if ctx and hasattr(ctx, "session_id"):
                                    mcp_session_id = ctx.session_id
                            except Exception:
                                pass

                            store.store_session(
                                user_email=user_email,
                                access_token=token,
                                scopes=scopes,
                                session_id=session_id,
                                mcp_session_id=mcp_session_id,
                                issuer="https://accounts.google.com",
                            )

                            logger.info(f"Verified OAuth token for user: {user_email}")

                        return access_token_obj

            except Exception as e:
                logger.error(f"Error verifying Google OAuth token: {e}", exc_info=True)
                return None

        else:
            logger.info(f"Using JWT verification for non-OAuth token (prefix: {token_prefix})")
            access_token = await super().verify_token(token)

            if access_token:
                logger.info(f"JWT verification succeeded: client_id={access_token.client_id}")
            else:
                logger.info("JWT verification failed - token rejected")

            if access_token and self.client_id:
                user_email = access_token.claims.get("email")
                if user_email:
                    from auth.oauth21_session_store import get_oauth21_session_store

                    store = get_oauth21_session_store()
                    session_id = f"google_{access_token.claims.get('sub', 'unknown')}"

                    store.store_session(
                        user_email=user_email,
                        access_token=token,
                        scopes=access_token.scopes or [],
                        session_id=session_id,
                        issuer="https://accounts.google.com",
                    )

                    logger.info(f"Verified JWT token for user: {user_email}")

            return access_token
