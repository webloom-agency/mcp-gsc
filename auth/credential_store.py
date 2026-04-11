"""
Credential Store for Google Search Console MCP

Provides a standardized interface for per-user credential storage and retrieval
using local JSON files (one file per user email).
"""

import os
import re
import json
import logging
import stat
from abc import ABC, abstractmethod
from typing import Optional, List
from datetime import datetime
from google.oauth2.credentials import Credentials

logger = logging.getLogger(__name__)


class CredentialStore(ABC):
    """Abstract base class for credential storage."""

    @abstractmethod
    def get_credential(self, user_email: str) -> Optional[Credentials]:
        pass

    @abstractmethod
    def store_credential(self, user_email: str, credentials: Credentials) -> bool:
        pass

    @abstractmethod
    def delete_credential(self, user_email: str) -> bool:
        pass

    @abstractmethod
    def list_users(self) -> List[str]:
        pass


class LocalDirectoryCredentialStore(CredentialStore):
    """Credential store that uses local JSON files for per-user storage."""

    def __init__(self, base_dir: Optional[str] = None):
        if base_dir is None:
            if os.getenv("GOOGLE_MCP_CREDENTIALS_DIR"):
                base_dir = os.getenv("GOOGLE_MCP_CREDENTIALS_DIR")
            elif os.getenv("GSC_MCP_CREDENTIALS_DIR"):
                base_dir = os.getenv("GSC_MCP_CREDENTIALS_DIR")
            else:
                home_dir = os.path.expanduser("~")
                if home_dir and home_dir != "~":
                    base_dir = os.path.join(home_dir, ".mcp_gsc", "credentials")
                else:
                    base_dir = os.path.join(os.getcwd(), ".credentials")

        self.base_dir = base_dir
        logger.info(f"LocalDirectoryCredentialStore initialized with base_dir: {base_dir}")

    @staticmethod
    def _sanitize_email(user_email: str) -> str:
        """Sanitize email for safe use as a filename, preventing path traversal."""
        sanitized = re.sub(r"[^a-zA-Z0-9@._-]", "_", user_email)
        sanitized = sanitized.strip(".")
        if not sanitized or sanitized in (".", ".."):
            raise ValueError(f"Invalid user email for credential storage: {user_email!r}")
        return sanitized

    def _get_credential_path(self, user_email: str) -> str:
        if not os.path.exists(self.base_dir):
            os.makedirs(self.base_dir, mode=0o700)
            logger.info(f"Created credentials directory: {self.base_dir}")
        safe_name = self._sanitize_email(user_email)
        creds_path = os.path.realpath(os.path.join(self.base_dir, f"{safe_name}.json"))
        base_real = os.path.realpath(self.base_dir)
        if not creds_path.startswith(base_real + os.sep):
            raise ValueError(f"Path traversal blocked for: {user_email!r}")
        return creds_path

    def get_credential(self, user_email: str) -> Optional[Credentials]:
        creds_path = self._get_credential_path(user_email)

        if not os.path.exists(creds_path):
            logger.debug(f"No credential file found for {user_email} at {creds_path}")
            return None

        try:
            with open(creds_path, "r") as f:
                creds_data = json.load(f)

            expiry = None
            if creds_data.get("expiry"):
                try:
                    expiry = datetime.fromisoformat(creds_data["expiry"])
                    if expiry.tzinfo is not None:
                        expiry = expiry.replace(tzinfo=None)
                except (ValueError, TypeError) as e:
                    logger.warning(f"Could not parse expiry time for {user_email}: {e}")

            credentials = Credentials(
                token=creds_data.get("token"),
                refresh_token=creds_data.get("refresh_token"),
                token_uri=creds_data.get("token_uri"),
                client_id=creds_data.get("client_id"),
                client_secret=creds_data.get("client_secret"),
                scopes=creds_data.get("scopes"),
                expiry=expiry,
            )

            logger.debug(f"Loaded credentials for {user_email} from {creds_path}")
            return credentials

        except (IOError, json.JSONDecodeError, KeyError) as e:
            logger.error(f"Error loading credentials for {user_email} from {creds_path}: {e}")
            return None

    def store_credential(self, user_email: str, credentials: Credentials) -> bool:
        creds_path = self._get_credential_path(user_email)

        creds_data = {
            "token": credentials.token,
            "refresh_token": credentials.refresh_token,
            "token_uri": credentials.token_uri,
            "client_id": credentials.client_id,
            "client_secret": credentials.client_secret,
            "scopes": credentials.scopes,
            "expiry": credentials.expiry.isoformat() if credentials.expiry else None,
        }

        try:
            fd = os.open(creds_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
            with os.fdopen(fd, "w") as f:
                json.dump(creds_data, f, indent=2)
            logger.info(f"Stored credentials for {user_email} to {creds_path}")
            return True
        except IOError as e:
            logger.error(f"Error storing credentials for {user_email} to {creds_path}: {e}")
            return False

    def delete_credential(self, user_email: str) -> bool:
        creds_path = self._get_credential_path(user_email)
        try:
            if os.path.exists(creds_path):
                os.remove(creds_path)
                logger.info(f"Deleted credentials for {user_email} from {creds_path}")
            return True
        except IOError as e:
            logger.error(f"Error deleting credentials for {user_email} from {creds_path}: {e}")
            return False

    def list_users(self) -> List[str]:
        if not os.path.exists(self.base_dir):
            return []
        users = []
        try:
            for filename in os.listdir(self.base_dir):
                if filename.endswith(".json"):
                    users.append(filename[:-5])
        except OSError as e:
            logger.error(f"Error listing credential files in {self.base_dir}: {e}")
        return sorted(users)


# Global credential store instance
_credential_store: Optional[CredentialStore] = None


def get_credential_store() -> CredentialStore:
    global _credential_store
    if _credential_store is None:
        _credential_store = LocalDirectoryCredentialStore()
        logger.info(f"Initialized credential store: {type(_credential_store).__name__}")
    return _credential_store


def set_credential_store(store: CredentialStore):
    global _credential_store
    _credential_store = store
    logger.info(f"Set credential store: {type(store).__name__}")
