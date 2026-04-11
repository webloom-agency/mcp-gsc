"""
MCP Session Middleware for Google Search Console MCP

Intercepts MCP requests and sets the session context
for use by tool functions.
"""

import logging
from typing import Callable, Any

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request

from auth.oauth21_session_store import (
    SessionContext,
    SessionContextManager,
    extract_session_from_headers,
)

logger = logging.getLogger(__name__)


class MCPSessionMiddleware(BaseHTTPMiddleware):
    """
    Middleware that extracts session information from requests and makes it
    available to MCP tool functions via context variables.
    """

    async def dispatch(self, request: Request, call_next: Callable) -> Any:
        logger.debug(f"MCPSessionMiddleware processing request: {request.method} {request.url.path}")

        if not request.url.path.startswith("/mcp"):
            return await call_next(request)

        session_context = None

        try:
            headers = dict(request.headers)
            session_id = extract_session_from_headers(headers)

            auth_context = None
            user_email = None
            mcp_session_id = None

            if hasattr(request.state, "auth"):
                auth_context = request.state.auth
                if hasattr(auth_context, 'claims') and auth_context.claims:
                    user_email = auth_context.claims.get('email')

            if hasattr(request.state, "session_id"):
                mcp_session_id = request.state.session_id

            auth_header = headers.get("authorization")
            if auth_header and auth_header.lower().startswith("bearer ") and not user_email:
                try:
                    import jwt
                    token = auth_header[7:]
                    claims = jwt.decode(token, options={"verify_signature": False})
                    user_email = claims.get('email')
                except Exception:
                    pass

            if session_id or auth_context or user_email or mcp_session_id:
                effective_session_id = session_id
                if not effective_session_id and user_email:
                    effective_session_id = f"google_{user_email}"
                elif not effective_session_id and mcp_session_id:
                    effective_session_id = mcp_session_id

                session_context = SessionContext(
                    session_id=effective_session_id,
                    user_id=user_email or (auth_context.user_id if auth_context else None),
                    auth_context=auth_context,
                    request=request,
                    metadata={
                        "path": request.url.path,
                        "method": request.method,
                        "user_email": user_email,
                        "mcp_session_id": mcp_session_id,
                    }
                )

                logger.debug(
                    f"MCP request with session: session_id={session_context.session_id}, "
                    f"user_id={session_context.user_id}, path={request.url.path}"
                )

            with SessionContextManager(session_context):
                response = await call_next(request)
                return response

        except Exception as e:
            logger.error(f"Error in MCP session middleware: {e}")
            return await call_next(request)
