"""
Persist FastMCP / MCP OAuth authorization-server state to disk.

Survives process restarts (e.g. Render deploys) so registered clients and
MCP access/refresh tokens remain valid while Google user credentials are
stored separately by the credential store.
"""

from __future__ import annotations

import json
import logging
import os
import tempfile
import time
from typing import Any

from mcp.server.auth.provider import RefreshToken
from mcp.shared.auth import OAuthClientInformationFull

from fastmcp.server.auth.auth import AccessToken

logger = logging.getLogger(__name__)

STATE_VERSION = 1
SUBDIR_NAME = "mcp_oauth"
STATE_FILENAME = "server_state.json"


def mcp_oauth_state_path(base_dir: str) -> str:
    return os.path.join(base_dir, SUBDIR_NAME, STATE_FILENAME)


def write_mcp_oauth_state_atomic(path: str, payload: dict[str, Any]) -> None:
    """Write JSON atomically with restrictive permissions."""
    parent = os.path.dirname(path)
    os.makedirs(parent, mode=0o700, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=parent, prefix=".mcp_oauth_state_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            json.dump(payload, f, indent=2)
        os.chmod(tmp, 0o600)
        os.replace(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def read_mcp_oauth_state(path: str) -> dict[str, Any] | None:
    if not os.path.isfile(path):
        return None
    try:
        with open(path, "r") as f:
            return json.load(f)
    except (OSError, json.JSONDecodeError) as e:
        logger.warning("Could not read MCP OAuth state file %s: %s", path, e)
        return None


def deserialize_state(
    raw: dict[str, Any],
) -> tuple[
    dict[str, OAuthClientInformationFull],
    dict[str, AccessToken],
    dict[str, RefreshToken],
    dict[str, str],
]:
    clients: dict[str, OAuthClientInformationFull] = {}
    access_tokens: dict[str, AccessToken] = {}
    refresh_tokens: dict[str, RefreshToken] = {}
    token_to_email: dict[str, str] = {}

    if raw.get("version") != STATE_VERSION:
        logger.warning(
            "Ignoring MCP OAuth state file: unsupported version %r",
            raw.get("version"),
        )
        return clients, access_tokens, refresh_tokens, token_to_email

    for cid, cdata in (raw.get("clients") or {}).items():
        try:
            clients[cid] = OAuthClientInformationFull.model_validate(cdata)
        except Exception as e:
            logger.warning("Skipping invalid OAuth client %s: %s", cid, e)

    for tok, tdata in (raw.get("access_tokens") or {}).items():
        try:
            access_tokens[tok] = AccessToken.model_validate(tdata)
        except Exception as e:
            logger.warning("Skipping invalid access token entry: %s", e)

    for tok, tdata in (raw.get("refresh_tokens") or {}).items():
        try:
            refresh_tokens[tok] = RefreshToken.model_validate(tdata)
        except Exception as e:
            logger.warning("Skipping invalid refresh token entry: %s", e)

    token_to_email = dict(raw.get("token_to_email") or {})

    return clients, access_tokens, refresh_tokens, token_to_email


def serialize_state(
    clients: dict[str, OAuthClientInformationFull],
    access_tokens: dict[str, AccessToken],
    refresh_tokens: dict[str, RefreshToken],
    token_to_email: dict[str, str],
) -> dict[str, Any]:
    return {
        "version": STATE_VERSION,
        "saved_at": time.time(),
        "clients": {
            k: v.model_dump(mode="json") for k, v in clients.items()
        },
        "access_tokens": {
            k: v.model_dump(mode="json") for k, v in access_tokens.items()
        },
        "refresh_tokens": {
            k: v.model_dump(mode="json") for k, v in refresh_tokens.items()
        },
        "token_to_email": dict(token_to_email),
    }


def prune_expired(
    access_tokens: dict[str, AccessToken],
    refresh_tokens: dict[str, RefreshToken],
    token_to_email: dict[str, str],
    now: float | None = None,
) -> None:
    """Remove expired MCP access and refresh tokens and orphan email mappings."""
    t = now if now is not None else time.time()
    for key, at in list(access_tokens.items()):
        if at.expires_at is not None and at.expires_at < t:
            access_tokens.pop(key, None)
            token_to_email.pop(key, None)
    for key, rt in list(refresh_tokens.items()):
        if rt.expires_at is not None and rt.expires_at < t:
            refresh_tokens.pop(key, None)
            token_to_email.pop(key, None)
    valid_keys = set(access_tokens) | set(refresh_tokens)
    for key in list(token_to_email.keys()):
        if key not in valid_keys:
            token_to_email.pop(key, None)
