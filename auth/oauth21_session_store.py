"""
OAuth 2.1 Session Store for Google Search Console MCP

Provides a global store for OAuth 2.1 authenticated sessions
that can be accessed by tool handlers. Also includes session context
management and credential conversion functionality.
"""

import contextvars
import hashlib
import logging
from typing import Dict, Optional, Any
from threading import RLock
from datetime import datetime, timedelta
from dataclasses import dataclass

from google.oauth2.credentials import Credentials

logger = logging.getLogger(__name__)


# =============================================================================
# Session Context Management
# =============================================================================

_current_session_context: contextvars.ContextVar[Optional['SessionContext']] = contextvars.ContextVar(
    'current_session_context',
    default=None
)


@dataclass
class SessionContext:
    """Container for session-related information."""
    session_id: Optional[str] = None
    user_id: Optional[str] = None
    auth_context: Optional[Any] = None
    request: Optional[Any] = None
    metadata: Dict[str, Any] = None
    issuer: Optional[str] = None

    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


def set_session_context(context: Optional[SessionContext]):
    _current_session_context.set(context)
    if context:
        logger.debug(f"Set session context: session_id={context.session_id}, user_id={context.user_id}")
    else:
        logger.debug("Cleared session context")


def get_session_context() -> Optional[SessionContext]:
    return _current_session_context.get()


def clear_session_context():
    set_session_context(None)


class SessionContextManager:
    """Context manager for temporarily setting session context."""

    def __init__(self, context: Optional[SessionContext]):
        self.context = context
        self.token = None

    def __enter__(self):
        self.token = _current_session_context.set(self.context)
        return self.context

    def __exit__(self, exc_type, exc_val, exc_tb):
        if self.token:
            _current_session_context.reset(self.token)


def extract_session_from_headers(headers: Dict[str, str]) -> Optional[str]:
    """Extract session ID from request headers."""
    session_id = headers.get("mcp-session-id") or headers.get("Mcp-Session-Id")
    if session_id:
        return session_id

    session_id = headers.get("x-session-id") or headers.get("X-Session-ID")
    if session_id:
        return session_id

    auth_header = headers.get("authorization") or headers.get("Authorization")
    if auth_header and auth_header.lower().startswith("bearer "):
        token = auth_header[7:]
        if token:
            store = get_oauth21_session_store()
            for user_email, session_info in store._sessions.items():
                if session_info.get("access_token") == token:
                    return session_info.get("session_id") or f"bearer_{user_email}"
            token_hash = hashlib.sha256(token.encode()).hexdigest()[:8]
            return f"bearer_token_{token_hash}"

    return None


# =============================================================================
# OAuth21SessionStore - Main Session Management
# =============================================================================

class OAuth21SessionStore:
    """
    Global store for OAuth 2.1 authenticated sessions.

    Maintains a mapping of user emails to their OAuth 2.1
    credentials, allowing tool handlers to access per-user credentials.
    """

    def __init__(self):
        self._sessions: Dict[str, Dict[str, Any]] = {}
        self._mcp_session_mapping: Dict[str, str] = {}
        self._session_auth_binding: Dict[str, str] = {}
        self._lock = RLock()

    def store_session(
        self,
        user_email: str,
        access_token: str,
        refresh_token: Optional[str] = None,
        token_uri: str = "https://oauth2.googleapis.com/token",
        client_id: Optional[str] = None,
        client_secret: Optional[str] = None,
        scopes: Optional[list] = None,
        expiry: Optional[Any] = None,
        session_id: Optional[str] = None,
        mcp_session_id: Optional[str] = None,
        issuer: Optional[str] = None,
    ):
        with self._lock:
            session_info = {
                "access_token": access_token,
                "refresh_token": refresh_token,
                "token_uri": token_uri,
                "client_id": client_id,
                "client_secret": client_secret,
                "scopes": scopes or [],
                "expiry": expiry,
                "session_id": session_id,
                "mcp_session_id": mcp_session_id,
                "issuer": issuer,
            }

            self._sessions[user_email] = session_info

            if mcp_session_id:
                if mcp_session_id not in self._session_auth_binding:
                    self._session_auth_binding[mcp_session_id] = user_email
                    logger.info(f"Created immutable session binding: {mcp_session_id} -> {user_email}")
                elif self._session_auth_binding[mcp_session_id] != user_email:
                    logger.error(f"SECURITY: Attempt to rebind session {mcp_session_id} from {self._session_auth_binding[mcp_session_id]} to {user_email}")
                    raise ValueError(f"Session {mcp_session_id} is already bound to a different user")

                self._mcp_session_mapping[mcp_session_id] = user_email
                logger.info(f"Stored OAuth 2.1 session for {user_email} (session_id: {session_id}, mcp_session_id: {mcp_session_id})")
            else:
                logger.info(f"Stored OAuth 2.1 session for {user_email} (session_id: {session_id})")

            if session_id and session_id not in self._session_auth_binding:
                self._session_auth_binding[session_id] = user_email

    def get_credentials(self, user_email: str) -> Optional[Credentials]:
        with self._lock:
            session_info = self._sessions.get(user_email)
            if not session_info:
                logger.debug(f"No OAuth 2.1 session found for {user_email}")
                return None

            try:
                credentials = Credentials(
                    token=session_info["access_token"],
                    refresh_token=session_info.get("refresh_token"),
                    token_uri=session_info["token_uri"],
                    client_id=session_info.get("client_id"),
                    client_secret=session_info.get("client_secret"),
                    scopes=session_info.get("scopes", []),
                    expiry=session_info.get("expiry"),
                )
                logger.debug(f"Retrieved OAuth 2.1 credentials for {user_email}")
                return credentials
            except Exception as e:
                logger.error(f"Failed to create credentials for {user_email}: {e}")
                return None

    def get_credentials_by_mcp_session(self, mcp_session_id: str) -> Optional[Credentials]:
        with self._lock:
            user_email = self._mcp_session_mapping.get(mcp_session_id)
            if not user_email:
                logger.debug(f"No user mapping found for MCP session {mcp_session_id}")
                return None
            logger.debug(f"Found user {user_email} for MCP session {mcp_session_id}")
            return self.get_credentials(user_email)

    def get_user_by_mcp_session(self, mcp_session_id: str) -> Optional[str]:
        with self._lock:
            return self._mcp_session_mapping.get(mcp_session_id)

    def get_session_info(self, user_email: str) -> Optional[Dict[str, Any]]:
        with self._lock:
            return self._sessions.get(user_email)

    def remove_session(self, user_email: str):
        with self._lock:
            if user_email in self._sessions:
                session_info = self._sessions.get(user_email, {})
                mcp_session_id = session_info.get("mcp_session_id")
                session_id = session_info.get("session_id")

                del self._sessions[user_email]

                if mcp_session_id and mcp_session_id in self._mcp_session_mapping:
                    del self._mcp_session_mapping[mcp_session_id]
                    if mcp_session_id in self._session_auth_binding:
                        del self._session_auth_binding[mcp_session_id]

                if session_id and session_id in self._session_auth_binding:
                    del self._session_auth_binding[session_id]

                logger.info(f"Removed OAuth 2.1 session for {user_email}")

    def has_session(self, user_email: str) -> bool:
        with self._lock:
            return user_email in self._sessions

    def has_mcp_session(self, mcp_session_id: str) -> bool:
        with self._lock:
            return mcp_session_id in self._mcp_session_mapping

    def get_stats(self) -> Dict[str, Any]:
        with self._lock:
            return {
                "total_sessions": len(self._sessions),
                "users": list(self._sessions.keys()),
                "mcp_session_mappings": len(self._mcp_session_mapping),
            }


# Global instance
_global_store = OAuth21SessionStore()


def get_oauth21_session_store() -> OAuth21SessionStore:
    return _global_store


# =============================================================================
# Google Credentials Bridge
# =============================================================================

_auth_provider = None


def set_auth_provider(provider):
    global _auth_provider
    _auth_provider = provider
    logger.debug("OAuth 2.1 session store configured with auth provider")


def get_auth_provider():
    return _auth_provider


def get_credentials_from_token(access_token: str, user_email: Optional[str] = None) -> Optional[Credentials]:
    """Convert a bearer token to Google credentials."""
    if not _auth_provider:
        logger.error("Auth provider not configured")
        return None

    try:
        store = get_oauth21_session_store()

        if user_email:
            credentials = store.get_credentials(user_email)
            if credentials and credentials.token == access_token:
                logger.debug(f"Found matching credentials from store for {user_email}")
                return credentials

        expiry = datetime.utcnow() + timedelta(hours=1)
        credentials = Credentials(
            token=access_token,
            refresh_token=None,
            token_uri="https://oauth2.googleapis.com/token",
            client_id=_auth_provider.client_id,
            client_secret=_auth_provider.client_secret,
            scopes=None,
            expiry=expiry
        )
        logger.debug("Created Google credentials from bearer token")
        return credentials

    except Exception as e:
        logger.error(f"Failed to create Google credentials from token: {e}")
        return None


def store_token_session(token_response: dict, user_email: str, mcp_session_id: Optional[str] = None) -> str:
    """Store a token response in the session store."""
    if not _auth_provider:
        logger.error("Auth provider not configured")
        return ""

    try:
        if not mcp_session_id:
            try:
                from fastmcp.server.dependencies import get_context
                ctx = get_context()
                if ctx and hasattr(ctx, 'session_id'):
                    mcp_session_id = ctx.session_id
                    logger.debug(f"Got FastMCP session ID from context: {mcp_session_id}")
            except Exception as e:
                logger.debug(f"Could not get FastMCP session from context: {e}")

        store = get_oauth21_session_store()

        session_id = f"google_{user_email}"
        store.store_session(
            user_email=user_email,
            access_token=token_response.get("access_token"),
            refresh_token=token_response.get("refresh_token"),
            token_uri="https://oauth2.googleapis.com/token",
            client_id=_auth_provider.client_id,
            client_secret=_auth_provider.client_secret,
            scopes=token_response.get("scope", "").split() if token_response.get("scope") else None,
            expiry=datetime.utcnow() + timedelta(seconds=token_response.get("expires_in", 3600)),
            session_id=session_id,
            mcp_session_id=mcp_session_id,
            issuer="https://accounts.google.com",
        )

        logger.info(f"Stored token session for {user_email}")
        return session_id

    except Exception as e:
        logger.error(f"Failed to store token session: {e}")
        return ""
