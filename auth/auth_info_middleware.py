"""
Authentication middleware to populate context state with user information
for Google Search Console MCP.
"""
import jwt
import logging
import os
import time
from types import SimpleNamespace
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_http_headers

logger = logging.getLogger(__name__)


class AuthInfoMiddleware(Middleware):
    """
    Middleware to extract authentication information from Bearer tokens
    and populate the FastMCP context state for use in tool handlers.
    """

    async def _process_request_for_auth(self, context: MiddlewareContext):
        """Extract, verify, and store auth info from a request."""
        if not context.fastmcp_context:
            logger.warning("No fastmcp_context available")
            return

        if context.fastmcp_context.get_state("authenticated_user_email"):
            return

        try:
            headers = get_http_headers()
            if headers:
                auth_header = headers.get("authorization", "")
                if auth_header.startswith("Bearer "):
                    token_str = auth_header[7:]

                    if token_str.startswith("ya29."):
                        logger.debug("Detected Google OAuth access token format")

                        from auth.oauth21_session_store import get_auth_provider
                        auth_provider = get_auth_provider()

                        if auth_provider:
                            try:
                                verified_auth = await auth_provider.verify_token(token_str)
                                if verified_auth:
                                    user_email = None
                                    if hasattr(verified_auth, 'claims'):
                                        user_email = verified_auth.claims.get("email")

                                    expires_at = getattr(verified_auth, 'expires_at', int(time.time()) + 3600)
                                    client_id = getattr(verified_auth, 'client_id', None) or "google"

                                    access_token = SimpleNamespace(
                                        token=token_str,
                                        client_id=client_id,
                                        scopes=verified_auth.scopes if hasattr(verified_auth, 'scopes') else [],
                                        session_id=f"google_oauth_{token_str[:8]}",
                                        expires_at=expires_at,
                                        sub=verified_auth.sub if hasattr(verified_auth, 'sub') else user_email,
                                        email=user_email
                                    )

                                    context.fastmcp_context.set_state("access_token", access_token)
                                    context.fastmcp_context.set_state("token_type", "google_oauth")
                                    context.fastmcp_context.set_state("user_email", user_email)
                                    context.fastmcp_context.set_state("authenticated_user_email", user_email)
                                    context.fastmcp_context.set_state("authenticated_via", "bearer_token")

                                    logger.info(f"Authenticated via Google OAuth: {user_email}")
                                else:
                                    logger.error("Failed to verify Google OAuth token")
                            except Exception as e:
                                logger.error(f"Error verifying Google OAuth token: {e}")
                        else:
                            logger.warning("No auth provider available to verify Google token")

                    else:
                        try:
                            token_payload = jwt.decode(
                                token_str,
                                options={"verify_signature": False}
                            )

                            access_token = SimpleNamespace(
                                token=token_str,
                                client_id=token_payload.get("client_id", "unknown"),
                                scopes=token_payload.get("scope", "").split() if token_payload.get("scope") else [],
                                session_id=token_payload.get("sid", token_payload.get("jti", "unknown")),
                                expires_at=token_payload.get("exp", 0)
                            )

                            context.fastmcp_context.set_state("access_token", access_token)
                            context.fastmcp_context.set_state("user_id", token_payload.get("sub"))
                            context.fastmcp_context.set_state("username", token_payload.get("username", token_payload.get("email")))

                            user_email = token_payload.get("email", token_payload.get("username"))
                            if user_email:
                                context.fastmcp_context.set_state("authenticated_user_email", user_email)
                                context.fastmcp_context.set_state("authenticated_via", "jwt_token")

                        except jwt.DecodeError as e:
                            logger.error(f"Failed to decode JWT: {e}")
                        except Exception as e:
                            logger.error(f"Error processing JWT: {e}")
                else:
                    logger.debug("No Bearer token in Authorization header")
            else:
                logger.debug("No HTTP headers available (stdio transport)")
        except Exception as e:
            logger.debug(f"Could not get HTTP request: {e}")

        # Check MCP session binding as fallback
        if not context.fastmcp_context.get_state("authenticated_user_email"):
            if hasattr(context.fastmcp_context, 'session_id'):
                mcp_session_id = context.fastmcp_context.session_id
                if mcp_session_id:
                    try:
                        from auth.oauth21_session_store import get_oauth21_session_store
                        store = get_oauth21_session_store()
                        bound_user = store.get_user_by_mcp_session(mcp_session_id)
                        if bound_user:
                            context.fastmcp_context.set_state("authenticated_user_email", bound_user)
                            context.fastmcp_context.set_state("authenticated_via", "mcp_session_binding")
                    except Exception as e:
                        logger.debug(f"Error checking MCP session binding: {e}")

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        """Extract auth info from token and set in context state before tool execution."""
        try:
            await self._process_request_for_auth(context)
            return await call_next(context)
        except Exception as e:
            logger.error(f"Error in on_call_tool middleware: {e}", exc_info=True)
            raise

    async def on_get_prompt(self, context: MiddlewareContext, call_next):
        """Extract auth info for prompt requests too."""
        try:
            await self._process_request_for_auth(context)
            return await call_next(context)
        except Exception as e:
            logger.error(f"Error in on_get_prompt middleware: {e}", exc_info=True)
            raise
