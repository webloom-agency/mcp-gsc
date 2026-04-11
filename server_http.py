# server_http.py
import os, json, contextlib, logging
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse

import gsc_server

logger = logging.getLogger(__name__)

# ==== Config (env-driven) ====
SCOPES = ["https://www.googleapis.com/auth/webmasters"]

MCP_ENABLE_OAUTH21 = os.getenv("MCP_ENABLE_OAUTH21", "").lower() in ("1", "true", "yes")

# Legacy OAuth config (used when OAuth21 is disabled)
CLIENT_ID = os.getenv("GOOGLE_OAUTH_CLIENT_ID") or os.getenv("GSC_OAUTH_CLIENT_ID")
CLIENT_SECRET = os.getenv("GOOGLE_OAUTH_CLIENT_SECRET") or os.getenv("GSC_OAUTH_CLIENT_SECRET")
REDIRECT_URI = os.getenv("GOOGLE_OAUTH_REDIRECT_URI") or os.getenv("GSC_OAUTH_REDIRECT_URI")

CREDENTIALS_DIR = os.getenv("GOOGLE_MCP_CREDENTIALS_DIR") or os.getenv("GSC_MCP_CREDENTIALS_DIR") or "/data"
TOKEN_PATH = os.getenv("GSC_OAUTH_TOKEN_PATH") or os.path.join(CREDENTIALS_DIR, "gsc_token.json")

CLIENT_SECRETS = os.getenv("GSC_OAUTH_CLIENT_SECRETS_FILE", "/etc/secrets/client_secrets.json")

# ---- Bearer auth middleware (used when OAuth21 is NOT enabled) ----
class BearerAuthMiddleware(BaseHTTPMiddleware):
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

# ---- Legacy OAuth helpers (only used when MCP_ENABLE_OAUTH21 is false) ----
_GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
_GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"


def _flow():
    from google_auth_oauthlib.flow import Flow
    if CLIENT_ID and CLIENT_SECRET and REDIRECT_URI:
        client_config = {
            "web": {
                "client_id": CLIENT_ID,
                "client_secret": CLIENT_SECRET,
                "auth_uri": _GOOGLE_AUTH_URI,
                "token_uri": _GOOGLE_TOKEN_URI,
                "redirect_uris": [REDIRECT_URI],
                "javascript_origins": [],
            }
        }
        return Flow.from_client_config(
            client_config,
            scopes=SCOPES,
            redirect_uri=REDIRECT_URI,
        )
    return Flow.from_client_secrets_file(
        CLIENT_SECRETS,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )


def _validate_oauth_env():
    if not REDIRECT_URI:
        return "GOOGLE_OAUTH_REDIRECT_URI (or GSC_OAUTH_REDIRECT_URI) is not set."
    if CLIENT_ID and CLIENT_SECRET:
        return None
    if os.path.exists(CLIENT_SECRETS):
        return None
    return (
        "No OAuth client configured. Provide GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET (or GSC_* vars) "
        "or mount a client secrets file and set GSC_OAUTH_CLIENT_SECRETS_FILE."
    )


async def oauth_authorize(request: Request):
    err = _validate_oauth_env()
    if err:
        return JSONResponse({"error": err}, status_code=500)
    try:
        flow = _flow()
        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes=False,
            prompt="consent",
        )
        return JSONResponse({"auth_url": auth_url, "state": state})
    except Exception as e:
        return JSONResponse({"error": f"oauth_authorize failed: {str(e)}"}, status_code=500)


async def oauth_start(request: Request):
    err = _validate_oauth_env()
    if err:
        return JSONResponse({"error": err}, status_code=500)
    try:
        flow = _flow()
        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes=False,
            prompt="consent",
        )
        return RedirectResponse(auth_url)
    except Exception as e:
        return JSONResponse({"error": f"oauth_start failed: {str(e)}"}, status_code=500)


async def oauth_callback(request: Request):
    err = _validate_oauth_env()
    if err:
        return JSONResponse({"error": err}, status_code=500)
    try:
        flow = _flow()
        flow.fetch_token(authorization_response=str(request.url))
        creds = flow.credentials
        os.makedirs(os.path.dirname(TOKEN_PATH), exist_ok=True)
        with open(TOKEN_PATH, "w") as f:
            f.write(creds.to_json())
        return JSONResponse({"status": "ok", "token_path": TOKEN_PATH})
    except Exception as e:
        return JSONResponse({"error": f"oauth_callback failed: {str(e)}", "token_path": TOKEN_PATH}, status_code=500)


async def oauth_exchange(request: Request):
    err = _validate_oauth_env()
    if err:
        return JSONResponse({"error": err}, status_code=500)
    try:
        authorization_response = request.query_params.get("authorization_response")
        if not authorization_response and request.method == "POST":
            try:
                body = await request.json()
                authorization_response = body.get("authorization_response")
            except Exception:
                authorization_response = None
        if not authorization_response:
            return JSONResponse({"error": "authorization_response is required"}, status_code=400)

        flow = _flow()
        flow.fetch_token(authorization_response=authorization_response)
        creds = flow.credentials
        os.makedirs(os.path.dirname(TOKEN_PATH), exist_ok=True)
        with open(TOKEN_PATH, "w") as f:
            f.write(creds.to_json())
        return JSONResponse({"status": "ok", "token_path": TOKEN_PATH})
    except Exception as e:
        return JSONResponse({"error": f"oauth_exchange failed: {str(e)}", "token_path": TOKEN_PATH}, status_code=500)


# ---- Wire the MCP server ----
try:
    mcp = getattr(gsc_server, "mcp")
except AttributeError as e:
    raise RuntimeError(
        "Expected gsc_server.py to expose a FastMCP instance named `mcp`."
    ) from e

# ---- Configure OAuth 2.1 auth provider when enabled ----
_auth_provider = None

if MCP_ENABLE_OAUTH21:
    try:
        from auth.oauth_config import set_transport_mode, get_oauth_config
        from auth.oauth21_session_store import set_auth_provider
        from auth.google_remote_auth_provider import GoogleRemoteAuthProvider, REMOTEAUTHPROVIDER_AVAILABLE

        set_transport_mode("streamable-http")
        config = get_oauth_config()

        if not config.is_configured():
            logger.warning("OAuth 2.1 enabled but GOOGLE_OAUTH_CLIENT_ID / GOOGLE_OAUTH_CLIENT_SECRET not configured")
        elif not REMOTEAUTHPROVIDER_AVAILABLE:
            logger.error("OAuth 2.1 enabled but FastMCP 2.11.1+ is not installed (missing RemoteAuthProvider)")
        else:
            _auth_provider = GoogleRemoteAuthProvider()
            mcp.auth = _auth_provider
            set_auth_provider(_auth_provider)
            logger.info("OAuth 2.1 per-user authentication enabled")
    except Exception as e:
        logger.error(f"Failed to initialize OAuth 2.1 auth: {e}", exc_info=True)
else:
    logger.info("OAuth 2.1 disabled - using legacy authentication mode")


# ---- Lifespan ----
@contextlib.asynccontextmanager
async def lifespan(app):
    async with mcp.session_manager.run():
        yield


# ---- Build routes and app ----
def _create_app():
    """Build the Starlette app with appropriate routes and middleware."""
    mcp_app = mcp.streamable_http_app()

    # Add MCPSessionMiddleware when OAuth21 is enabled
    if MCP_ENABLE_OAUTH21 and _auth_provider:
        try:
            from auth.mcp_session_middleware import MCPSessionMiddleware
            mcp_app.user_middleware.insert(0, Middleware(MCPSessionMiddleware))
            mcp_app.middleware_stack = mcp_app.build_middleware_stack()
            logger.info("MCPSessionMiddleware added to MCP app")
        except Exception as e:
            logger.error(f"Failed to add MCPSessionMiddleware: {e}")

    if MCP_ENABLE_OAUTH21 and _auth_provider:
        # OAuth 2.1 mode: GoogleRemoteAuthProvider handles OAuth routes via mcp.auth
        routes = [
            Mount("/", app=mcp_app),
        ]
        middleware = []
    else:
        # Legacy mode: use old OAuth routes and bearer auth
        routes = [
            Route("/oauth2/authorize", oauth_authorize),
            Route("/oauth2/start", oauth_start),
            Route("/oauth2/callback", oauth_callback),
            Route("/oauth2/exchange", oauth_exchange),
            Mount("/", app=mcp_app),
        ]
        middleware = [Middleware(BearerAuthMiddleware)]

    return Starlette(
        routes=routes,
        middleware=middleware,
        lifespan=lifespan,
    )


app = _create_app()
