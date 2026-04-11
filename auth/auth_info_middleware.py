"""
Authentication middleware to populate context state with user information
for Google Search Console MCP.

With OAuthProvider, the Bearer token on /mcp is an MCP-issued token.
We look up the user email from the provider's token-to-email mapping
and set it in the FastMCP context for tool handlers.
"""
import logging
from fastmcp.server.middleware import Middleware, MiddlewareContext
from fastmcp.server.dependencies import get_http_headers

logger = logging.getLogger(__name__)


def _get_provider():
    """Lazily import the auth provider to avoid circular imports."""
    try:
        from auth.google_oauth_provider import GoogleOAuthProvider
        import server_http
        provider = getattr(server_http, "_auth_provider", None)
        if isinstance(provider, GoogleOAuthProvider):
            return provider
    except Exception:
        pass
    return None


class AuthInfoMiddleware(Middleware):
    """
    Middleware to extract user identity from MCP-issued Bearer tokens
    and populate the FastMCP context state for use in tool handlers.
    """

    async def _process_request_for_auth(self, context: MiddlewareContext):
        if not context.fastmcp_context:
            return

        if context.fastmcp_context.get_state("authenticated_user_email"):
            return

        try:
            headers = get_http_headers()
            if not headers:
                logger.debug("No HTTP headers available (stdio transport)")
                return

            auth_header = headers.get("authorization", "")
            if not auth_header.startswith("Bearer "):
                return

            token_str = auth_header[7:]
            provider = _get_provider()
            if not provider:
                logger.debug("No GoogleOAuthProvider available")
                return

            user_email = provider.get_user_email(token_str)
            if user_email:
                context.fastmcp_context.set_state("authenticated_user_email", user_email)
                context.fastmcp_context.set_state("authenticated_via", "mcp_oauth_token")
                logger.debug("Authenticated user from MCP token: %s", user_email)
            else:
                logger.debug("MCP token not found in provider mapping")

        except Exception as e:
            logger.debug("Error in auth middleware: %s", e)

    async def on_call_tool(self, context: MiddlewareContext, call_next):
        await self._process_request_for_auth(context)
        return await call_next(context)

    async def on_get_prompt(self, context: MiddlewareContext, call_next):
        await self._process_request_for_auth(context)
        return await call_next(context)
