# server_http.py
import os, json, contextlib
from starlette.applications import Starlette
from starlette.routing import Mount, Route
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse
from google_auth_oauthlib.flow import Flow
from google.oauth2.credentials import Credentials

import gsc_server  # from the repo (we will ensure it exports/uses a FastMCP instance)

# ==== Config (env-driven) ====
SCOPES = ["https://www.googleapis.com/auth/webmasters"]
CLIENT_SECRETS = os.getenv("GSC_OAUTH_CLIENT_SECRETS_FILE", "/etc/secrets/client_secrets.json")
TOKEN_PATH = os.getenv("GSC_OAUTH_TOKEN_PATH", "/data/gsc_token.json")
# Accept either GSC_* or GOOGLE_* names for convenience
CLIENT_ID = os.getenv("GSC_OAUTH_CLIENT_ID") or os.getenv("GOOGLE_OAUTH_CLIENT_ID")
CLIENT_SECRET = os.getenv("GSC_OAUTH_CLIENT_SECRET") or os.getenv("GOOGLE_OAUTH_CLIENT_SECRET")
REDIRECT_URI = os.getenv("GSC_OAUTH_REDIRECT_URI") or os.getenv("GOOGLE_OAUTH_REDIRECT_URI")  # must be set

# ---- Bearer auth middleware ----
class BearerAuthMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        # allow OAuth endpoints without Bearer
        path = request.url.path
        if path.startswith("/oauth2/"):
            return await call_next(request)
        required = os.getenv("MCP_BEARER_TOKEN")
        if required:
            auth = request.headers.get("Authorization", "")
            if not auth.startswith("Bearer ") or auth.split(" ", 1)[1] != required:
                return JSONResponse({"error": "Unauthorized"}, status_code=401)
        return await call_next(request)

# ---- OAuth helpers ----
_GOOGLE_AUTH_URI = "https://accounts.google.com/o/oauth2/auth"
_GOOGLE_TOKEN_URI = "https://oauth2.googleapis.com/token"


def _flow():
    # Prefer explicit client_id/secret from env if provided
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
    # Otherwise fall back to secrets file
    return Flow.from_client_secrets_file(
        CLIENT_SECRETS,
        scopes=SCOPES,
        redirect_uri=REDIRECT_URI,
    )


def _validate_oauth_env():
    if not REDIRECT_URI:
        return "GSC_OAUTH_REDIRECT_URI (or GOOGLE_OAUTH_REDIRECT_URI) is not set."
    # Valid if either env client config or secrets file exists
    if CLIENT_ID and CLIENT_SECRET:
        return None
    if os.path.exists(CLIENT_SECRETS):
        return None
    return (
        "No OAuth client configured. Provide GSC_OAUTH_CLIENT_ID and GSC_OAUTH_CLIENT_SECRET (or GOOGLE_* vars) "
        "or mount a client secrets file and set GSC_OAUTH_CLIENT_SECRETS_FILE."
    )


async def oauth_start(request: Request):
    err = _validate_oauth_env()
    if err:
        return JSONResponse({"error": err}, status_code=500)
    try:
        flow = _flow()
        auth_url, state = flow.authorization_url(
            access_type="offline",
            include_granted_scopes=False,  # avoid inheriting previous app scopes (prevents scope mismatch)
            prompt="consent",
        )
        # you can store state in signed cookies/session if desired; for simplicity we skip it here
        return RedirectResponse(auth_url)
    except Exception as e:
        return JSONResponse({"error": f"oauth_start failed: {str(e)}"}, status_code=500)


async def oauth_callback(request: Request):
    err = _validate_oauth_env()
    if err:
        return JSONResponse({"error": err}, status_code=500)
    try:
        # Rebuild flow and exchange code
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
    # Accept forwarded authorization_response (GET query or POST JSON)
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

# ---- Wire the MCP server (exported by gsc_server) to Streamable HTTP ----
try:
    mcp = getattr(gsc_server, "mcp")
except AttributeError as e:
    raise RuntimeError(
        "Expected gsc_server.py to expose a FastMCP instance named `mcp`."
    ) from e

# If you host multiple servers or need lifecycle, you can manage the session manager here.
@contextlib.asynccontextmanager
async def lifespan(app):
    # Start MCP session manager on startup (recommended)
    async with mcp.session_manager.run():
        yield

routes = [
    Route("/oauth2/start", oauth_start),
    Route("/oauth2/callback", oauth_callback),
    Route("/oauth2/exchange", oauth_exchange),
    # Mount MCP server Streamable HTTP app at '/' (its endpoints are under /mcp by default)
    Mount("/", app=mcp.streamable_http_app()),
]

app = Starlette(
    routes=routes,
    middleware=[Middleware(BearerAuthMiddleware)],
    lifespan=lifespan,
)
