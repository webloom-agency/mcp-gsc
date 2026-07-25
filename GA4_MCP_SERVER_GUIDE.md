# Building a GA4 (Google Analytics 4) MCP Server with OAuth 2.1 User-Based Login Persistence

A complete, self-contained tutorial for building a **Google Analytics 4 (Data API v1)** MCP server that
mirrors the architecture of our production `mcp-gsc` (Google Search Console) server: a FastMCP
tool server plus a full **OAuth 2.1 Authorization Server proxy** that logs each user in with
their own Google account and **persists that login across restarts**.

This is meant to be handed to another project as-is. Everything you need — code, Google Cloud
setup, deployment, and multi-client configuration — is in this one file.

---

## Table of contents

1. [TL;DR — is this model/provider-agnostic?](#1-tldr--is-this-modelprovider-agnostic)
2. [Why the official Google repo only mentions Gemini](#2-why-the-official-google-repo-only-mentions-gemini)
3. [Architecture overview](#3-architecture-overview)
4. [GA4 vs GSC: what changes](#4-ga4-vs-gsc-what-changes)
5. [Google Cloud setup](#5-google-cloud-setup)
6. [Project layout](#6-project-layout)
7. [Dependencies](#7-dependencies)
8. [The auth module (copy-paste, OAuth 2.1 + persistence)](#8-the-auth-module)
9. [The GA4 tool server (`ga4_server.py`)](#9-the-ga4-tool-server-ga4_serverpy)
10. [The HTTP entrypoint (`server_http.py`)](#10-the-http-entrypoint-server_httppy)
11. [Environment variables reference](#11-environment-variables-reference)
12. [Running locally (stdio, single user)](#12-running-locally-stdio-single-user)
13. [Running remotely (HTTP + OAuth 2.1, multi-user)](#13-running-remotely-http--oauth-21-multi-user)
14. [Connecting clients (ANY provider)](#14-connecting-clients-any-provider)
15. [Testing with MCP Inspector](#15-testing-with-mcp-inspector)
16. [Security notes](#16-security-notes)
17. [Troubleshooting](#17-troubleshooting)

---

## 1. TL;DR — is this model/provider-agnostic?

**Yes. Completely.** Neither MCP nor the Google APIs are tied to Gemini. Two independent reasons:

1. **MCP is a transport/protocol standard, not a model.** Any MCP-capable client can call this
   server: Claude (Desktop/web connectors), ChatGPT (Developer Mode / connectors),
   Cursor, VS Code (Copilot MCP), Cline, Windsurf, Gemini CLI, the MCP Inspector, or your own
   client built on the OpenAI / Anthropic / Mistral / local-LLM SDKs via any MCP bridge.
2. **The LLM never sees Google credentials.** The MCP server holds the user's Google OAuth
   tokens **server-side**. Tools return plain text/JSON. So the model provider is irrelevant to
   auth — it only ever sees tool schemas and tool results.

For the **remote** deployment, the one requirement on the client is that it supports the
**MCP Authorization spec** (OAuth 2.1: `.well-known` metadata discovery + Dynamic Client
Registration + PKCE over Streamable HTTP). Clients that do today include Claude connectors,
ChatGPT connectors, Cursor, VS Code, and the MCP Inspector. Clients that don't (or that you
run yourself over stdio) can use the **static bearer-token** or **stdio** modes described below —
still fully provider-agnostic.

There is **no Gemini-specific code anywhere** in this design.

---

## 2. Why the official Google repo only mentions Gemini

The official [`googleanalytics/google-analytics-mcp`](https://github.com/googleanalytics/google-analytics-mcp)
server is a **local stdio server** authenticated with **Application Default Credentials (ADC)**:

- It runs as `pipx run analytics-mcp` on your machine.
- Auth is whatever `gcloud auth application-default login` (or `GOOGLE_APPLICATION_CREDENTIALS`)
  set up — a single identity, on one machine.
- Their README only shows `~/.gemini/settings.json` and a `claude mcp add` command because those
  are the two clients they chose to document.

That design is perfectly model-agnostic, but it is **single-user and local-only**: there is no
per-user login, no login persistence for multiple users, and no hosted/remote deployment. It
assumes one developer, on one laptop, already logged in with `gcloud`.

**What we add** (and what your GSC stack already does) is the piece the official repo lacks:

- A hosted, multi-user server where **each end user logs in with their own Google account**
  through a browser OAuth 2.1 flow.
- **Persistence**: each user's Google refresh token is stored server-side and survives process
  restarts / redeploys, so users don't re-authenticate constantly.
- **Any MCP client / any model provider** can connect — via OAuth 2.1, a static bearer token, or
  stdio.

---

## 3. Architecture overview

Same shape as `mcp-gsc`. Two layers:

```
┌──────────────────────────────────────────────────────────────────────┐
│  MCP client (Claude / ChatGPT / Cursor / VS Code / your own client)    │
│  Speaks MCP over Streamable HTTP. Does OAuth 2.1 against OUR server.    │
└───────────────┬────────────────────────────────────────────────────────┘
                │  Authorization: Bearer <MCP-issued token>
                ▼
┌──────────────────────────────────────────────────────────────────────┐
│  server_http.py  (Starlette + FastMCP)                                 │
│                                                                        │
│  GoogleOAuthProvider  ── OAuth 2.1 Authorization Server ───────────┐   │
│   • /authorize, /token, /register  (issues OUR MCP tokens)         │   │
│   • /oauth2callback                (receives Google's consent)     │   │
│   • proxies user consent to Google, stores Google creds per email  │   │
│   • persists MCP tokens + Google creds to disk (survives restart)  │   │
│                                                                    │   │
│  AuthInfoMiddleware  ── maps MCP bearer token → user email ────────┘   │
│                                                                        │
│  FastMCP tools (ga4_server.py) ── resolve per-user Google creds ──►     │
│                                    call GA4 Data API + Admin API        │
└──────────────────────────────────────────────────────────────────────┘
```

Two token systems, exactly like GSC:

- **MCP tokens** — opaque tokens *we* issue to the MCP client. Verified on every `/mcp` request.
- **Google tokens** — the user's real Google OAuth tokens, stored server-side, mapped to the
  user's email, and used to actually call GA4.

Two persistence stores on disk (both survive restarts):

- **Per-user Google credentials** — one JSON file per user email (`credential_store.py`).
- **MCP OAuth server state** — registered clients + issued MCP access/refresh tokens
  (`mcp_oauth_state_store.py`).

The result: a user logs in once with Google; their refresh token is persisted; the server keeps
minting short-lived MCP tokens and silently refreshes the underlying Google token as needed.

---

## 4. GA4 vs GSC: what changes

The **entire `auth/` module is reused almost verbatim** — the OAuth 2.1 machinery is
API-independent. Only these things change:

| Concern | GSC (source) | GA4 (this guide) |
|---|---|---|
| OAuth scope | `https://www.googleapis.com/auth/webmasters` | `https://www.googleapis.com/auth/analytics.readonly` |
| Python client | `googleapiclient.discovery.build("searchconsole", "v1")` (httplib2, **not thread-safe** → needs thread-local hack) | `BetaAnalyticsDataClient` + `AnalyticsAdminServiceClient` (gRPC, **thread-safe** → no hack) |
| Packages | `google-api-python-client` | `google-analytics-data`, `google-analytics-admin` |
| Resource id | site URL (`sc-domain:example.com`) | numeric **property id** (`properties/123456789`) |
| APIs enabled | Search Console API | **Google Analytics Data API** + **Google Analytics Admin API** |
| Tools | queries, sitemaps, URL inspection | reports, realtime, account/property discovery |

Because the GA4 clients are gRPC-based and thread-safe, we drop the `threading.local()` client
caching that GSC needed for httplib2. We still offload the blocking unary gRPC calls with
`asyncio.to_thread`.

Tool set (mirrors the official GA4 repo):

- `get_account_summaries` — list accounts + GA4 properties the user can see (Admin API)
- `get_property_details` — details for one property (Admin API)
- `list_google_ads_links` — Google Ads links for a property (Admin API)
- `get_custom_dimensions_and_metrics` — custom dims/metrics for a property (Admin API)
- `run_report` — core report (Data API)
- `run_realtime_report` — realtime report (Data API)
- `run_funnel_report` — funnel report (Data API **v1alpha**; optional)

---

## 5. Google Cloud setup

1. Go to the [Google Cloud Console](https://console.cloud.google.com/) and create/select a project.
2. Enable both APIs:
   - [Google Analytics Data API](https://console.cloud.google.com/apis/library/analyticsdata.googleapis.com)
   - [Google Analytics Admin API](https://console.cloud.google.com/apis/library/analyticsadmin.googleapis.com)
3. Configure the **OAuth consent screen** (External unless you're Workspace-internal). Add the
   scope `https://www.googleapis.com/auth/analytics.readonly`. While the app is in "Testing",
   add each user's Google address under **Test users**.
4. Create an **OAuth client ID**:
   - **Desktop app** → for local `stdio` use (loopback redirect).
   - **Web application** → for the remote HTTP deployment. Add an authorized redirect URI:
     `https://YOUR_DOMAIN/oauth2callback` (and `http://localhost:8000/oauth2callback` for local
     testing of the HTTP flow).
5. Note your **Client ID** and **Client secret**. For local stdio, download the client secrets
   JSON (e.g. `client_secrets.json`).

> The user (or the service identity) must have at least **Viewer** access to the GA4 properties
> they want to query.

---

## 6. Project layout

Identical to `mcp-gsc`, with `ga4_server.py` replacing `gsc_server.py`:

```
mcp-ga4/
├── ga4_server.py                 # FastMCP tool server (GA4-specific)
├── server_http.py                # HTTP entrypoint (OAuth 2.1 wiring) — copied, minor edits
├── requirements.txt
├── auth/
│   ├── __init__.py
│   ├── scopes.py                 # CHANGE: GA4 scope
│   ├── oauth_config.py           # copied (rename env prefix optional)
│   ├── google_oauth_provider.py  # copied (imports auth.scopes)
│   ├── credential_store.py       # copied verbatim
│   ├── mcp_oauth_state_store.py   # copied verbatim
│   ├── oauth21_session_store.py  # copied verbatim
│   ├── auth_info_middleware.py   # copied (imports the provider)
│   ├── mcp_session_middleware.py # copied verbatim (optional)
│   ├── oauth_common_handlers.py  # copied (imports auth.scopes)
│   └── oauth_error_handling.py   # copied verbatim
└── .gitignore
```

**Copy the whole `auth/` directory from `mcp-gsc` unchanged**, then apply the two small edits
below (`scopes.py`, and optionally env-var prefixes). The rest of this doc shows the full content
of the GA4-specific files and the edits.

---

## 7. Dependencies

`requirements.txt`:

```txt
google-analytics-data>=0.18.0
google-analytics-admin>=0.23.0
google-auth>=2.0.0
google-auth-oauthlib>=1.2.1
fastmcp==2.11.3
starlette>=0.37
uvicorn>=0.30
aiohttp>=3.9.0
PyJWT[crypto]>=2.8.0
pydantic>=2.0.0
```

> Pin `fastmcp==2.11.3` (the version our OAuth provider is written against). The
> `mcp.server.auth` and `fastmcp.server.auth` APIs changed across versions; staying on the same
> FastMCP release as `mcp-gsc` guarantees the copied `auth/` module works unchanged.

Install:

```bash
uv venv .venv && source .venv/bin/activate
uv pip install -r requirements.txt
```

---

## 8. The auth module

The OAuth 2.1 machinery is **API-agnostic**, so you copy it from `mcp-gsc/auth/` and change only
the scope. Below is exactly what to do with each file.

### 8.1 `auth/scopes.py` — the only mandatory edit

Replace the GSC scope with the GA4 read-only scope:

```python
"""Google Analytics 4 OAuth scopes."""

SCOPES = ["https://www.googleapis.com/auth/analytics.readonly"]


def get_current_scopes():
    """Return the scopes required for Google Analytics 4 API access."""
    return SCOPES
```

That single change propagates everywhere, because every other auth file imports
`from auth.scopes import SCOPES` / `get_current_scopes()`.

### 8.2 Files copied verbatim (no edits needed)

- `auth/credential_store.py` — per-user Google credential persistence (one JSON per email, `0600`
  perms, path-traversal protection). It reads `GOOGLE_MCP_CREDENTIALS_DIR` for the storage dir.
- `auth/mcp_oauth_state_store.py` — persists registered MCP clients + issued MCP access/refresh
  tokens to `<creds_dir>/mcp_oauth/server_state.json` (atomic writes, prunes expired tokens).
- `auth/oauth21_session_store.py` — in-memory session store + `google.oauth2` credential bridge.
- `auth/oauth_error_handling.py` — OAuth error types, validation, CORS helpers.
- `auth/mcp_session_middleware.py` — optional Starlette middleware for session context.

These contain no GSC API calls, only OAuth plumbing — copy as-is.

### 8.3 `auth/google_oauth_provider.py` — copied (works via `auth.scopes`)

This is the heart of the system: a `fastmcp` `OAuthProvider` subclass that is a **full OAuth 2.1
Authorization Server**. Copy it verbatim. It already imports the scope from `auth.scopes`, so the
GA4 scope you set in 8.1 flows through automatically. What it does (unchanged from GSC):

- `register_client` / `get_client` — Dynamic Client Registration (persisted).
- `authorize` — redirects the user to Google consent (`analytics.readonly` + `openid email`),
  storing a pending-authorization keyed by a random `state`.
- `_handle_google_callback` (`/oauth2callback`) — exchanges Google's code for Google tokens,
  extracts the verified user email, **stores the Google credentials server-side per email**, mints
  an MCP authorization code, and redirects back to the MCP client.
- `exchange_authorization_code` / `exchange_refresh_token` — issues and rotates **our** MCP
  access/refresh tokens; refreshes the underlying Google token when needed; persists state.
- `load_access_token` / `verify_token` — validates the MCP bearer token on every `/mcp` request.
- `get_user_email(token)` — used by the middleware to resolve the caller's identity.

> The only environment-specific values it reads are `GOOGLE_OAUTH_CLIENT_ID` /
> `GOOGLE_OAUTH_CLIENT_SECRET` (with `GSC_*` fallbacks). See 8.6 if you want GA4-named env vars.

### 8.4 `auth/auth_info_middleware.py` — copied (retarget the import)

FastMCP middleware that reads the incoming `Authorization: Bearer <mcp-token>`, looks up the user
email from the provider, and stores it in the FastMCP context as `authenticated_user_email` so
tools can resolve per-user credentials. Copy it, and if you renamed the server module, update the
`import server_http` reference (it stays `server_http` here, so no change).

### 8.5 `auth/oauth_common_handlers.py` and `auth/oauth_config.py` — copied

- `oauth_config.py` centralizes base URL / port / client id / redirect URI / PKCE settings.
  Copy verbatim. (Optionally rename the `GSC_MCP_*` env fallbacks — see 8.6.)
- `oauth_common_handlers.py` implements the `.well-known` metadata endpoints, the authorize/token
  proxy, and Dynamic Client Registration used by the alternate `RemoteAuthProvider` path. Copy
  verbatim; it already pulls scopes from `auth.scopes`.

### 8.6 Optional: GA4-named environment variables

The copied code prefers generic `GOOGLE_OAUTH_*` variables and falls back to `GSC_*`. If you want
clean GA4 names, do a project-wide rename of the fallback strings `GSC_` → `GA4_` in
`oauth_config.py`, `google_oauth_provider.py`, and `oauth_common_handlers.py`. **This is cosmetic**
— using the generic `GOOGLE_OAUTH_CLIENT_ID` / `GOOGLE_OAUTH_CLIENT_SECRET` /
`GOOGLE_MCP_CREDENTIALS_DIR` everywhere avoids any edits at all. This guide assumes the generic
`GOOGLE_*` names.

---

## 9. The GA4 tool server (`ga4_server.py`)

This is the GA4 analogue of `gsc_server.py`. It creates the `FastMCP` instance, adds the auth
middleware, resolves per-user credentials, builds the GA4 clients, and defines the tools.

```python
from typing import Any, Optional, List, Dict
import os
import json
import logging
import asyncio

from google.auth.transport.requests import Request as GoogleAuthRequest
from google.oauth2.credentials import Credentials
from google.oauth2 import service_account

from google.analytics.data_v1beta import BetaAnalyticsDataClient
from google.analytics.data_v1beta.types import (
    DateRange,
    Dimension,
    Metric,
    RunReportRequest,
    RunRealtimeReportRequest,
    OrderBy,
)
from google.analytics.admin_v1beta import AnalyticsAdminServiceClient

from fastmcp import FastMCP

logger = logging.getLogger(__name__)

mcp = FastMCP("ga4-server")

# Per-user OAuth middleware (only active on the HTTP transport).
try:
    from auth.auth_info_middleware import AuthInfoMiddleware
    mcp.add_middleware(AuthInfoMiddleware())
    logger.info("AuthInfoMiddleware added to MCP server")
except (ImportError, AttributeError) as e:
    logger.debug(f"Auth middleware not available (stdio-only mode): {e}")

# GA4 read-only scope.
SCOPES = ["https://www.googleapis.com/auth/analytics.readonly"]

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# Optional service-account file (legacy / single-identity mode).
GA4_CREDENTIALS_PATH = os.environ.get("GA4_CREDENTIALS_PATH")
POSSIBLE_CREDENTIAL_PATHS = [
    GA4_CREDENTIALS_PATH,
    os.path.join(SCRIPT_DIR, "service_account_credentials.json"),
    os.path.join(os.getcwd(), "service_account_credentials.json"),
]

# Optional pre-provisioned single-user OAuth token (stdio mode).
DEFAULT_CREDENTIALS_DIR = (
    os.getenv("GOOGLE_MCP_CREDENTIALS_DIR")
    or os.getenv("GA4_MCP_CREDENTIALS_DIR")
    or "/data"
)
OAUTH_TOKEN_PATH = os.getenv(
    "GA4_OAUTH_TOKEN_PATH", os.path.join(DEFAULT_CREDENTIALS_DIR, "ga4_token.json")
)

SKIP_OAUTH = os.environ.get("GA4_SKIP_OAUTH", "").lower() in ("true", "1", "yes")


# ---------------------------------------------------------------------------
# Credential resolution (identical strategy to gsc_server.py)
# ---------------------------------------------------------------------------

def _get_authenticated_user_email() -> Optional[str]:
    """Per-user email injected by AuthInfoMiddleware (HTTP/OAuth 2.1 mode)."""
    try:
        from fastmcp.server.dependencies import get_context
        ctx = get_context()
        if ctx:
            return ctx.get_state("authenticated_user_email")
    except Exception:
        pass
    return None


def get_credentials_for_user(user_email: str) -> Credentials:
    """Resolve a user's Google credentials: in-memory session first, then disk."""
    from auth.oauth21_session_store import get_oauth21_session_store
    from auth.credential_store import get_credential_store

    store = get_oauth21_session_store()
    creds = store.get_credentials(user_email)
    if creds:
        if creds.valid:
            return creds
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleAuthRequest())
            return creds

    cred_store = get_credential_store()
    creds = cred_store.get_credential(user_email)
    if creds:
        if creds.expired and creds.refresh_token:
            creds.refresh(GoogleAuthRequest())
            cred_store.store_credential(user_email, creds)
        return creds

    raise ValueError(
        f"No credentials found for user {user_email}. Please authenticate via OAuth first."
    )


def _load_single_user_credentials() -> Optional[Credentials]:
    """Legacy/stdio: a single OAuth token on disk, or a service account."""
    if not SKIP_OAUTH and os.path.exists(OAUTH_TOKEN_PATH):
        with open(OAUTH_TOKEN_PATH) as f:
            data = json.load(f)
        return Credentials.from_authorized_user_info(data, scopes=SCOPES)

    for cred_path in POSSIBLE_CREDENTIAL_PATHS:
        if cred_path and os.path.exists(cred_path):
            return service_account.Credentials.from_service_account_file(
                cred_path, scopes=SCOPES
            )
    return None


def _resolve_credentials(user_email: Optional[str]) -> Credentials:
    """Per-user creds when available; otherwise the single-user fallback."""
    if user_email:
        try:
            return get_credentials_for_user(user_email)
        except Exception as e:
            logger.debug(f"Per-user auth failed for {user_email}: {e}")

    creds = _load_single_user_credentials()
    if creds is None:
        raise FileNotFoundError(
            "Authentication failed. Provide per-user OAuth (HTTP mode), a pre-provisioned "
            f"OAuth token at {OAUTH_TOKEN_PATH}, or a service account credentials file."
        )
    if not creds.valid and creds.expired and creds.refresh_token:
        creds.refresh(GoogleAuthRequest())
    return creds


# GA4 gRPC clients are thread-safe, so (unlike GSC/httplib2) we can cache one per user.
_data_clients: Dict[str, BetaAnalyticsDataClient] = {}
_admin_clients: Dict[str, AnalyticsAdminServiceClient] = {}


def get_data_client(user_email: Optional[str]) -> BetaAnalyticsDataClient:
    key = user_email or "__default__"
    if key not in _data_clients:
        creds = _resolve_credentials(user_email)
        _data_clients[key] = BetaAnalyticsDataClient(credentials=creds)
    return _data_clients[key]


def get_admin_client(user_email: Optional[str]) -> AnalyticsAdminServiceClient:
    key = user_email or "__default__"
    if key not in _admin_clients:
        creds = _resolve_credentials(user_email)
        _admin_clients[key] = AnalyticsAdminServiceClient(credentials=creds)
    return _admin_clients[key]


def _normalize_property(property_id: str) -> str:
    """Accept '123456', 'properties/123456', or a full resource name."""
    pid = str(property_id).strip()
    if pid.startswith("properties/"):
        return pid
    return f"properties/{pid}"


# ---------------------------------------------------------------------------
# Tools
# ---------------------------------------------------------------------------

@mcp.tool()
async def get_account_summaries() -> str:
    """List all Google Analytics accounts and their GA4 properties the user can access."""
    try:
        client = get_admin_client(_get_authenticated_user_email())
        results = await asyncio.to_thread(lambda: list(client.list_account_summaries()))
        if not results:
            return "No Google Analytics accounts found for this user."
        lines: List[str] = []
        for acct in results:
            lines.append(f"Account: {acct.display_name} ({acct.account})")
            for prop in acct.property_summaries:
                lines.append(
                    f"  - {prop.display_name} "
                    f"(id: {prop.property.split('/')[-1]}, {prop.property})"
                )
        return "\n".join(lines)
    except Exception as e:
        return f"Error retrieving account summaries: {e}"


@mcp.tool()
async def get_property_details(property_id: str) -> str:
    """Return details about a GA4 property.

    Args:
        property_id: GA4 property id, e.g. "123456789" or "properties/123456789".
    """
    try:
        client = get_admin_client(_get_authenticated_user_email())
        name = _normalize_property(property_id)
        prop = await asyncio.to_thread(lambda: client.get_property(name=name))
        return json.dumps(
            {
                "name": prop.name,
                "display_name": prop.display_name,
                "time_zone": prop.time_zone,
                "currency_code": prop.currency_code,
                "industry_category": str(prop.industry_category),
                "create_time": prop.create_time.isoformat() if prop.create_time else None,
            },
            indent=2,
        )
    except Exception as e:
        return f"Error retrieving property details: {e}"


@mcp.tool()
async def list_google_ads_links(property_id: str) -> str:
    """List Google Ads links for a GA4 property.

    Args:
        property_id: GA4 property id, e.g. "123456789".
    """
    try:
        client = get_admin_client(_get_authenticated_user_email())
        parent = _normalize_property(property_id)
        links = await asyncio.to_thread(
            lambda: list(client.list_google_ads_links(parent=parent))
        )
        if not links:
            return f"No Google Ads links found for {parent}."
        return "\n".join(
            f"- {l.name} (customer_id: {l.customer_id})" for l in links
        )
    except Exception as e:
        return f"Error listing Google Ads links: {e}"


@mcp.tool()
async def get_custom_dimensions_and_metrics(property_id: str) -> str:
    """List custom dimensions and custom metrics for a GA4 property.

    Args:
        property_id: GA4 property id, e.g. "123456789".
    """
    try:
        client = get_admin_client(_get_authenticated_user_email())
        parent = _normalize_property(property_id)
        dims = await asyncio.to_thread(
            lambda: list(client.list_custom_dimensions(parent=parent))
        )
        mets = await asyncio.to_thread(
            lambda: list(client.list_custom_metrics(parent=parent))
        )
        out = {
            "custom_dimensions": [
                {"parameter_name": d.parameter_name, "display_name": d.display_name,
                 "scope": str(d.scope)}
                for d in dims
            ],
            "custom_metrics": [
                {"parameter_name": m.parameter_name, "display_name": m.display_name,
                 "measurement_unit": str(m.measurement_unit)}
                for m in mets
            ],
        }
        return json.dumps(out, indent=2)
    except Exception as e:
        return f"Error retrieving custom dimensions/metrics: {e}"


@mcp.tool()
async def run_report(
    property_id: str,
    dimensions: str = "date",
    metrics: str = "activeUsers",
    start_date: str = "28daysAgo",
    end_date: str = "today",
    row_limit: int = 100,
    order_by_metric: Optional[str] = None,
    descending: bool = True,
) -> str:
    """Run a core GA4 report via the Data API.

    Args:
        property_id: GA4 property id, e.g. "123456789".
        dimensions: Comma-separated GA4 dimension names (e.g. "date,country").
        metrics: Comma-separated GA4 metric names (e.g. "activeUsers,sessions").
        start_date: Start date ("YYYY-MM-DD", "NdaysAgo", "today", "yesterday").
        end_date: End date (same formats as start_date).
        row_limit: Max rows to return (default 100).
        order_by_metric: Optional metric name to sort by.
        descending: Sort direction when order_by_metric is set.
    """
    try:
        user_email = _get_authenticated_user_email()
        client = get_data_client(user_email)

        dimension_list = [d.strip() for d in dimensions.split(",") if d.strip()]
        metric_list = [m.strip() for m in metrics.split(",") if m.strip()]

        order_bys = None
        if order_by_metric:
            order_bys = [
                OrderBy(
                    metric=OrderBy.MetricOrderBy(metric_name=order_by_metric),
                    desc=descending,
                )
            ]

        request = RunReportRequest(
            property=_normalize_property(property_id),
            dimensions=[Dimension(name=d) for d in dimension_list],
            metrics=[Metric(name=m) for m in metric_list],
            date_ranges=[DateRange(start_date=start_date, end_date=end_date)],
            limit=int(row_limit),
            order_bys=order_bys,
        )
        response = await asyncio.to_thread(lambda: client.run_report(request))

        header = dimension_list + metric_list
        rows: List[str] = [" | ".join(header), "-" * 80]
        for row in response.rows:
            values = [dv.value for dv in row.dimension_values] + [
                mv.value for mv in row.metric_values
            ]
            rows.append(" | ".join(values))
        if len(rows) <= 2:
            return f"No data for {property_id} in {start_date}..{end_date}."
        return "\n".join(rows)
    except Exception as e:
        return f"Error running report: {e}"


@mcp.tool()
async def run_realtime_report(
    property_id: str,
    dimensions: str = "country",
    metrics: str = "activeUsers",
    row_limit: int = 100,
) -> str:
    """Run a GA4 realtime report via the Data API.

    Args:
        property_id: GA4 property id, e.g. "123456789".
        dimensions: Comma-separated realtime dimension names.
        metrics: Comma-separated realtime metric names.
        row_limit: Max rows to return.
    """
    try:
        client = get_data_client(_get_authenticated_user_email())
        dimension_list = [d.strip() for d in dimensions.split(",") if d.strip()]
        metric_list = [m.strip() for m in metrics.split(",") if m.strip()]
        request = RunRealtimeReportRequest(
            property=_normalize_property(property_id),
            dimensions=[Dimension(name=d) for d in dimension_list],
            metrics=[Metric(name=m) for m in metric_list],
            limit=int(row_limit),
        )
        response = await asyncio.to_thread(lambda: client.run_realtime_report(request))
        header = dimension_list + metric_list
        rows: List[str] = [" | ".join(header), "-" * 80]
        for row in response.rows:
            values = [dv.value for dv in row.dimension_values] + [
                mv.value for mv in row.metric_values
            ]
            rows.append(" | ".join(values))
        if len(rows) <= 2:
            return f"No realtime data for {property_id}."
        return "\n".join(rows)
    except Exception as e:
        return f"Error running realtime report: {e}"


if __name__ == "__main__":
    # stdio transport (local, single user). HTTP transport is served by server_http.py.
    mcp.run()
```

> **Optional `run_funnel_report`:** funnel reports live in the **v1alpha** Data client. If you need
> it, add `google.analytics.data_v1alpha` imports and a `BetaAnalyticsDataClient`-equivalent alpha
> client, then build a `RunFunnelReportRequest`. It's omitted from the core set above because it's
> an alpha surface and not needed for most analytics questions.

---

## 10. The HTTP entrypoint (`server_http.py`)

Copy `server_http.py` from `mcp-gsc` and make three edits: import `ga4_server` instead of
`gsc_server`, set the GA4 scope, and (optionally) rename env fallbacks. The OAuth 2.1 wiring is
unchanged. The essential structure:

```python
# server_http.py
import os, logging
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.middleware import Middleware
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse

logging.basicConfig(level=logging.INFO, format="%(levelname)s:%(name)s:%(message)s")

import ga4_server  # <-- was gsc_server

logger = logging.getLogger(__name__)

SCOPES = ["https://www.googleapis.com/auth/analytics.readonly"]  # <-- GA4 scope
MCP_ENABLE_OAUTH21 = os.getenv("MCP_ENABLE_OAUTH21", "").lower() in ("1", "true", "yes")


class BearerAuthMiddleware(BaseHTTPMiddleware):
    """Static shared-token gate (used when OAuth 2.1 is disabled)."""
    async def dispatch(self, request: Request, call_next):
        path = request.url.path
        if path.startswith("/oauth2/") or path.startswith("/.well-known/"):
            return await call_next(request)
        required = os.getenv("MCP_BEARER_TOKEN")
        if required:
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or auth.split(" ", 1)[1] != required:
                return JSONResponse({"error": "Unauthorized"}, status_code=401)
        return await call_next(request)


try:
    mcp = getattr(ga4_server, "mcp")
except AttributeError as e:
    raise RuntimeError("Expected ga4_server.py to expose a FastMCP instance named `mcp`.") from e

_auth_provider = None

if MCP_ENABLE_OAUTH21:
    from auth.oauth_config import get_oauth_config
    from auth.google_oauth_provider import GoogleOAuthProvider

    config = get_oauth_config()
    base_url = config.get_oauth_base_url()
    if not config.is_configured():
        logger.warning("OAuth 2.1 enabled but GOOGLE_OAUTH_CLIENT_ID/SECRET not configured")
    else:
        _auth_provider = GoogleOAuthProvider(base_url=base_url)
        mcp.auth = _auth_provider
        logger.info("OAuth 2.1 per-user authentication enabled")
else:
    logger.info("OAuth 2.1 disabled - using legacy authentication mode")


def _create_app():
    mcp_app = mcp.http_app()
    if MCP_ENABLE_OAUTH21 and _auth_provider:
        # The provider registers /authorize, /token, /register, /oauth2callback,
        # and the .well-known metadata routes itself.
        return mcp_app
    # Non-OAuth mode: optional static bearer-token gate in front of /mcp.
    routes = [Mount("/", app=mcp_app)]
    return Starlette(
        routes=routes,
        middleware=[Middleware(BearerAuthMiddleware)],
        lifespan=mcp_app.lifespan,
    )


app = _create_app()
```

Run it with uvicorn:

```bash
uvicorn server_http:app --host 0.0.0.0 --port 8000
```

The MCP endpoint is served at `POST/GET /mcp` (Streamable HTTP). The OAuth endpoints live at
`/authorize`, `/token`, `/register`, `/oauth2callback`, and `/.well-known/*`.

---

## 11. Environment variables reference

| Variable | Mode | Purpose |
|---|---|---|
| `MCP_ENABLE_OAUTH21` | HTTP | `true` to enable the per-user OAuth 2.1 Authorization Server. |
| `GOOGLE_OAUTH_CLIENT_ID` | HTTP | Google OAuth **Web** client id. |
| `GOOGLE_OAUTH_CLIENT_SECRET` | HTTP | Google OAuth client secret. |
| `GA4_MCP_BASE_URI` / `GA4_EXTERNAL_URL` | HTTP | Public base URL of the server (used to build redirect + metadata). Set `GA4_EXTERNAL_URL` to your `https://` domain in production. |
| `PORT` | HTTP | Listen port (default 8000). Render sets this automatically. |
| `GOOGLE_MCP_CREDENTIALS_DIR` | HTTP | **Persistent** directory for per-user Google tokens + MCP OAuth state. Point at a mounted disk. |
| `MCP_OAUTH_STATE_PERSIST` | HTTP | `true` (default) to persist MCP clients/tokens across restarts. |
| `MCP_BEARER_TOKEN` | HTTP | Static shared token gate when OAuth 2.1 is disabled. |
| `GA4_SKIP_OAUTH` | stdio | `true` to force service-account-only auth. |
| `GA4_CREDENTIALS_PATH` | stdio | Path to a service-account JSON. |
| `GA4_OAUTH_TOKEN_PATH` | stdio | Path to a single pre-provisioned OAuth token JSON. |
| `GOOGLE_APPLICATION_CREDENTIALS` | either | Standard ADC path (works like the official repo). |

> If you renamed env fallbacks to `GA4_*` per 8.6, the `GA4_OAUTH_CLIENT_ID` etc. also apply. The
> generic `GOOGLE_OAUTH_*` names always work with the unmodified copied code.

---

## 12. Running locally (stdio, single user)

This mirrors the official repo's model exactly — provider-agnostic, one identity.

**Option A — ADC (like the official repo):**

```bash
gcloud auth application-default login \
  --scopes=https://www.googleapis.com/auth/analytics.readonly,https://www.googleapis.com/auth/cloud-platform
python ga4_server.py
```

**Option B — a single OAuth token file:** run any of the OAuth2 quickstart flows once to produce a
`ga4_token.json` and point `GA4_OAUTH_TOKEN_PATH` at it.

Any stdio-capable MCP client config (works for Claude Desktop, Cursor, VS Code, Gemini CLI, etc.):

```json
{
  "mcpServers": {
    "ga4": {
      "command": "/FULL/PATH/mcp-ga4/.venv/bin/python",
      "args": ["/FULL/PATH/mcp-ga4/ga4_server.py"],
      "env": {
        "GOOGLE_APPLICATION_CREDENTIALS": "/FULL/PATH/adc.json"
      }
    }
  }
}
```

---

## 13. Running remotely (HTTP + OAuth 2.1, multi-user)

This is the piece the official repo doesn't provide: hosted, per-user login with persistence.

### 13.1 Deploy (Render example)

- **Build:** `pip install -r requirements.txt`
- **Start:** `uvicorn server_http:app --host 0.0.0.0 --port $PORT`
- **Attach a persistent disk** (e.g. mount at `/data`).
- **Environment:**

```
MCP_ENABLE_OAUTH21=true
GOOGLE_OAUTH_CLIENT_ID=xxxxx.apps.googleusercontent.com
GOOGLE_OAUTH_CLIENT_SECRET=xxxxx
GA4_EXTERNAL_URL=https://your-service.onrender.com
GOOGLE_MCP_CREDENTIALS_DIR=/data
MCP_OAUTH_STATE_PERSIST=true
```

- In Google Cloud, add the redirect URI `https://your-service.onrender.com/oauth2callback` to your
  **Web** OAuth client.

### 13.2 What persistence buys you

- `GOOGLE_MCP_CREDENTIALS_DIR/<email>.json` — each user's Google refresh token. After first login,
  the server refreshes the Google access token automatically; the user never re-consents.
- `GOOGLE_MCP_CREDENTIALS_DIR/mcp_oauth/server_state.json` — registered MCP clients + issued MCP
  tokens, so a redeploy doesn't invalidate active client sessions.

Because both live on the mounted disk, **restarts and redeploys preserve every user's login** —
which is the core requirement.

### 13.3 The login flow (per user, once)

1. The MCP client discovers `/.well-known/oauth-protected-resource` → the authorization server.
2. The client dynamically registers (`/register`) and starts PKCE auth at `/authorize`.
3. Our server redirects the user's browser to Google consent (`analytics.readonly`).
4. Google calls back to `/oauth2callback`; we store the user's Google creds keyed by verified email.
5. We issue an MCP auth code → the client exchanges it at `/token` for MCP access/refresh tokens.
6. Every `/mcp` call carries the MCP bearer token; middleware resolves it to the user email; tools
   load that user's Google creds and call GA4.

---

## 14. Connecting clients (ANY provider)

The server is provider-agnostic. Pick the mode your client supports.

### Claude (Desktop / web — remote connector)
Add a custom connector pointing at `https://your-service.onrender.com/mcp`. Claude runs the OAuth
2.1 flow in a browser; the user logs into Google once.

### ChatGPT (Developer Mode / connectors)
Add an MCP connector with the same `/mcp` URL. ChatGPT performs the OAuth 2.1 handshake. Your GA4
tools appear to the model — no Gemini, no Google model involved.

### Cursor / VS Code (Copilot MCP) / Cline / Windsurf
Add an HTTP MCP server entry with URL `https://your-service.onrender.com/mcp`. These clients
implement MCP OAuth; they'll open the Google login in a browser.

Example (Cursor `~/.cursor/mcp.json`, HTTP + OAuth):

```json
{
  "mcpServers": {
    "ga4": { "url": "https://your-service.onrender.com/mcp" }
  }
}
```

### Gemini CLI / Gemini Code Assist
Same as the official repo, but pointed at your server (stdio or HTTP). Included only for parity —
not required.

### Your own client (OpenAI / Anthropic / Mistral / local LLM)
Use any MCP client library (the official `mcp` Python/TS SDK, or framework MCP adapters). For the
remote server, either implement the OAuth 2.1 flow or run in **static bearer-token** mode:

```
MCP_ENABLE_OAUTH21=false
MCP_BEARER_TOKEN=some-long-random-string
```

Then send `Authorization: Bearer some-long-random-string` to `/mcp`. In this mode the server uses a
single Google identity (ADC / service account / token file), which is ideal for a trusted backend
that fans GA4 data out to whatever model provider you like.

> **Key point for the investigation:** in every one of these, the model provider only ever sees MCP
> tool schemas and text results. Google credentials stay on the server. There is nothing
> Gemini-specific — any model from any provider can drive these tools.

---

## 15. Testing with MCP Inspector

```bash
npx @modelcontextprotocol/inspector
```

- Transport: **Streamable HTTP**, URL `http://localhost:8000/mcp`.
- With OAuth 2.1 enabled, the Inspector will walk you through the Google login and then let you
  call `get_account_summaries`, `run_report`, etc.
- With `MCP_BEARER_TOKEN` set, put the token in the Authorization header field instead.

Quick unauthenticated sanity checks:

```bash
curl https://your-service.onrender.com/.well-known/oauth-protected-resource
curl https://your-service.onrender.com/.well-known/oauth-authorization-server
```

---

## 16. Security notes

- **Read-only scope.** `analytics.readonly` cannot mutate GA4 config or data.
- **Verified email only.** The provider rejects Google identities whose `email_verified` is false.
- **Credentials never leave the server.** The MCP client and the LLM only get opaque MCP tokens and
  text results.
- **Least-privilege file perms.** Credential and state files are written `0600` in a `0700`
  directory, with path-traversal protection on the email→filename mapping.
- **PKCE + exact redirect URI** are enforced in OAuth 2.1 mode.
- **Rotate** `MCP_BEARER_TOKEN` if you use static-token mode; treat it like a password.
- Keep the persistent disk private — it contains refresh tokens.

---

## 17. Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| `redirect_uri_mismatch` at Google | Add `https://<domain>/oauth2callback` to the Web OAuth client's authorized redirect URIs; make sure `GA4_EXTERNAL_URL` matches the public domain. |
| Client can't discover auth server | Confirm `MCP_ENABLE_OAUTH21=true` and that `/.well-known/oauth-protected-resource` returns JSON. |
| Users logged out after every redeploy | `GOOGLE_MCP_CREDENTIALS_DIR` isn't on a persistent disk, or `MCP_OAUTH_STATE_PERSIST` is false. |
| `No credentials found for user ...` | The user hasn't completed the browser login yet, or their email file is missing from the creds dir. |
| `PERMISSION_DENIED` from GA4 | The logged-in Google user lacks access to that GA4 property. Grant at least Viewer in GA4 Admin. |
| `403 accessNotConfigured` / API disabled | Enable **Analytics Data API** and **Analytics Admin API** in the Cloud project of the OAuth client. |
| Report returns no rows | Check `property_id` is the **GA4** numeric id (not a UA id), and that the date range has data. |
| `invalid_grant` on refresh | The Google refresh token was revoked/expired; delete the user's creds file and have them log in again. |

---

### Appendix: mapping to the official GA4 repo tools

| Official `analytics-mcp` tool | This server | GA4 API call |
|---|---|---|
| `get_account_summaries` | `get_account_summaries` | Admin `list_account_summaries` |
| `get_property_details` | `get_property_details` | Admin `get_property` |
| `list_google_ads_links` | `list_google_ads_links` | Admin `list_google_ads_links` |
| `get_custom_dimensions_and_metrics` | `get_custom_dimensions_and_metrics` | Admin `list_custom_dimensions` + `list_custom_metrics` |
| `run_report` | `run_report` | Data `run_report` |
| `run_realtime_report` | `run_realtime_report` | Data `run_realtime_report` |
| `run_funnel_report` | (optional add-on) | Data v1alpha `run_funnel_report` |

The difference from the official repo is entirely in the **transport + auth layer**: we add hosted,
per-user OAuth 2.1 with persistent login, reusing the exact `auth/` module from `mcp-gsc`.
