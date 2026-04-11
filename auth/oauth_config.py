"""
OAuth Configuration Management for Google Search Console MCP

Centralizes OAuth-related configuration to eliminate hardcoded values.
Supports both OAuth 2.0 and OAuth 2.1 with automatic client capability detection.
"""

import os
from typing import List, Optional, Dict, Any


class OAuthConfig:
    """Centralized OAuth configuration management."""

    def __init__(self):
        self.base_uri = os.getenv("GSC_MCP_BASE_URI", "http://localhost")
        self.port = int(os.getenv("PORT", os.getenv("GSC_MCP_PORT", "8000")))
        self.base_url = f"{self.base_uri}:{self.port}"

        self.external_url = os.getenv("GSC_EXTERNAL_URL")

        self.client_id = os.getenv("GOOGLE_OAUTH_CLIENT_ID") or os.getenv("GSC_OAUTH_CLIENT_ID")
        self.client_secret = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET") or os.getenv("GSC_OAUTH_CLIENT_SECRET")

        self.oauth21_enabled = os.getenv("MCP_ENABLE_OAUTH21", "false").lower() in ("1", "true", "yes")
        self.pkce_required = self.oauth21_enabled
        self.supported_code_challenge_methods = ["S256"] if self.oauth21_enabled else ["S256", "plain"]

        self._transport_mode = "stdio"

        self.redirect_uri = self._get_redirect_uri()

    def _get_redirect_uri(self) -> str:
        explicit_uri = os.getenv("GOOGLE_OAUTH_REDIRECT_URI") or os.getenv("GSC_OAUTH_REDIRECT_URI")
        if explicit_uri:
            return explicit_uri
        return f"{self.base_url}/oauth2callback"

    def get_redirect_uris(self) -> List[str]:
        uris = [self.redirect_uri]
        custom_uris = os.getenv("OAUTH_CUSTOM_REDIRECT_URIS")
        if custom_uris:
            uris.extend([uri.strip() for uri in custom_uris.split(",")])
        return list(dict.fromkeys(uris))

    def get_allowed_origins(self) -> List[str]:
        origins = [
            self.base_url,
            "vscode-webview://",
            "https://vscode.dev",
            "https://github.dev",
        ]
        custom_origins = os.getenv("OAUTH_ALLOWED_ORIGINS")
        if custom_origins:
            origins.extend([origin.strip() for origin in custom_origins.split(",")])
        return list(dict.fromkeys(origins))

    def is_configured(self) -> bool:
        return bool(self.client_id and self.client_secret)

    def get_oauth_base_url(self) -> str:
        if self.external_url:
            return self.external_url
        return self.base_url

    def validate_redirect_uri(self, uri: str) -> bool:
        return uri in self.get_redirect_uris()

    def set_transport_mode(self, mode: str) -> None:
        self._transport_mode = mode

    def get_transport_mode(self) -> str:
        return self._transport_mode

    def is_oauth21_enabled(self) -> bool:
        return self.oauth21_enabled

    def get_authorization_server_metadata(self, scopes: Optional[List[str]] = None) -> Dict[str, Any]:
        """Get OAuth authorization server metadata per RFC 8414."""
        oauth_base = self.get_oauth_base_url()
        metadata = {
            "issuer": oauth_base,
            "authorization_endpoint": f"{oauth_base}/oauth2/authorize",
            "token_endpoint": f"{oauth_base}/oauth2/token",
            "registration_endpoint": f"{oauth_base}/oauth2/register",
            "jwks_uri": "https://www.googleapis.com/oauth2/v3/certs",
            "response_types_supported": ["code", "token"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
            "code_challenge_methods_supported": self.supported_code_challenge_methods,
        }
        if scopes is not None:
            metadata["scopes_supported"] = scopes
        if self.oauth21_enabled:
            metadata["pkce_required"] = True
            metadata["response_types_supported"] = ["code"]
            metadata["require_exact_redirect_uri"] = True
        return metadata


# Global configuration instance
_oauth_config = None


def get_oauth_config() -> OAuthConfig:
    global _oauth_config
    if _oauth_config is None:
        _oauth_config = OAuthConfig()
    return _oauth_config


def reload_oauth_config() -> OAuthConfig:
    global _oauth_config
    _oauth_config = OAuthConfig()
    return _oauth_config


def get_oauth_base_url() -> str:
    return get_oauth_config().get_oauth_base_url()


def get_redirect_uris() -> List[str]:
    return get_oauth_config().get_redirect_uris()


def get_allowed_origins() -> List[str]:
    return get_oauth_config().get_allowed_origins()


def is_oauth_configured() -> bool:
    return get_oauth_config().is_configured()


def set_transport_mode(mode: str) -> None:
    get_oauth_config().set_transport_mode(mode)


def get_transport_mode() -> str:
    return get_oauth_config().get_transport_mode()


def is_oauth21_enabled() -> bool:
    return get_oauth_config().is_oauth21_enabled()


def get_oauth_redirect_uri() -> str:
    return get_oauth_config().redirect_uri
