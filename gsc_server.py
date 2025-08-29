from typing import Any, Dict, List, Optional
import os
import json
from datetime import datetime, timedelta

import google.auth
from google.auth.transport.requests import Request
from google.oauth2 import service_account
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from googleapiclient.discovery import build
from googleapiclient.errors import HttpError
from urllib.parse import urlparse
import httplib2
import google_auth_httplib2
import asyncio
import random

# MCP
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("gsc-server")

# Path to your service account JSON or user credentials JSON
# First check if GSC_CREDENTIALS_PATH environment variable is set
# Then try looking in the script directory and current working directory as fallbacks
GSC_CREDENTIALS_PATH = os.environ.get("GSC_CREDENTIALS_PATH")
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
POSSIBLE_CREDENTIAL_PATHS = [
    GSC_CREDENTIALS_PATH,  # First try the environment variable if set
    os.path.join(SCRIPT_DIR, "service_account_credentials.json"),
    os.path.join(os.getcwd(), "service_account_credentials.json"),
    # Add any other potential paths here
]

# OAuth client secrets file path
OAUTH_CLIENT_SECRETS_FILE = os.environ.get("GSC_OAUTH_CLIENT_SECRETS_FILE")
if not OAUTH_CLIENT_SECRETS_FILE:
    OAUTH_CLIENT_SECRETS_FILE = os.path.join(SCRIPT_DIR, "client_secrets.json")

# Token file path for storing OAuth tokens (legacy local flow)
TOKEN_FILE = os.path.join(SCRIPT_DIR, "token.json")

# Environment variable to skip OAuth authentication
SKIP_OAUTH = os.environ.get("GSC_SKIP_OAUTH", "").lower() in ("true", "1", "yes")

SCOPES = ["https://www.googleapis.com/auth/webmasters"]

# HTTP timeout for Google API calls (seconds)
try:
    GSC_HTTP_TIMEOUT_SECONDS = int(os.getenv("GSC_HTTP_TIMEOUT_SECONDS", "180"))
except ValueError:
    GSC_HTTP_TIMEOUT_SECONDS = 180

# Retry/backoff configuration for Google API calls
def _get_int_env(name: str, default_value: int) -> int:
    try:
        return int(os.getenv(name, str(default_value)))
    except Exception:
        return default_value

def _get_float_env(name: str, default_value: float) -> float:
    try:
        return float(os.getenv(name, str(default_value)))
    except Exception:
        return default_value

GSC_REQUEST_RETRIES = _get_int_env("GSC_REQUEST_RETRIES", 5)
GSC_RETRY_BACKOFF_SECONDS = _get_float_env("GSC_RETRY_BACKOFF_SECONDS", 2.0)
GSC_SLEEP_BETWEEN_REQUESTS_MS = _get_int_env("GSC_SLEEP_BETWEEN_REQUESTS_MS", 1000)
GSC_RETRY_JITTER_MS = _get_int_env("GSC_RETRY_JITTER_MS", 300)
GSC_MAX_CONCURRENT_INSPECTIONS = _get_int_env("GSC_MAX_CONCURRENT_INSPECTIONS", 1)
INSPECTION_SEMAPHORE = asyncio.Semaphore(max(1, GSC_MAX_CONCURRENT_INSPECTIONS))

# Prefer a pre-provisioned OAuth token on disk (e.g., saved by HTTP callback) if available
# Default to GOOGLE_MCP_CREDENTIALS_DIR/gsc_token.json, falling back to /data/gsc_token.json
DEFAULT_CREDENTIALS_DIR = os.getenv("GOOGLE_MCP_CREDENTIALS_DIR") or os.getenv("GSC_MCP_CREDENTIALS_DIR") or "/data"
OAUTH_TOKEN_PATH = os.getenv("GSC_OAUTH_TOKEN_PATH", os.path.join(DEFAULT_CREDENTIALS_DIR, "gsc_token.json"))

def _load_oauth_credentials_if_any():
    if os.path.exists(OAUTH_TOKEN_PATH):
        with open(OAUTH_TOKEN_PATH) as f:
            data = json.load(f)
        return Credentials.from_authorized_user_info(data, scopes=SCOPES)
    return None

# Build a Search Console client using an authorized HTTP with timeout
def _build_gsc_service(creds: Credentials):
    http = httplib2.Http(timeout=GSC_HTTP_TIMEOUT_SECONDS)
    authed_http = google_auth_httplib2.AuthorizedHttp(creds, http=http)
    return build("searchconsole", "v1", http=authed_http)

# Simple retry helper for synchronous googleapiclient .execute()
async def _execute_with_retries(execute_callable):
    last_exc = None
    for attempt in range(GSC_REQUEST_RETRIES + 1):
        try:
            # Run blocking execute() off the event loop
            return await asyncio.to_thread(execute_callable)
        except HttpError as e:
            last_exc = e
            status = getattr(getattr(e, "resp", None), "status", None)
            # Transient errors to retry
            if status in {408, 429, 500, 502, 503, 504}:
                pass
            else:
                raise
        except Exception as e:
            last_exc = e
        # Backoff with jitter
        if attempt < GSC_REQUEST_RETRIES:
            backoff = (GSC_RETRY_BACKOFF_SECONDS ** (attempt + 1))
            jitter = random.uniform(0, max(0, GSC_RETRY_JITTER_MS) / 1000.0)
            await asyncio.sleep(backoff + jitter)
    raise last_exc

# --- Property resolution helpers ---

def _list_property_urls(service) -> List[str]:
    try:
        site_list = service.sites().list().execute()
        return [entry.get("siteUrl", "") for entry in site_list.get("siteEntry", [])]
    except Exception:
        return []


def _normalize_domain(value: str) -> str:
    value = (value or "").strip()
    if not value:
        return value
    # If URL, extract hostname
    if value.startswith("http://") or value.startswith("https://"):
        try:
            parsed = urlparse(value)
            return (parsed.hostname or value).lower()
        except Exception:
            return value.lower()
    # If sc-domain: keep only the domain portion
    if value.startswith("sc-domain:"):
        return value.split(":", 1)[1].lower()
    # Otherwise treat as hostname/domain
    return value.lower()


def _ensure_trailing_slash(url: str) -> str:
    if url and url.startswith("http") and not url.endswith("/"):
        return url + "/"
    return url


def _resolve_site_url(service, provided: str) -> str:
    """
    Resolve a user-provided identifier (bare domain, hostname, URL, or sc-domain) to an
    actual Search Console property URL present in the user's properties.
    Prefers domain property when available; otherwise matches URL properties by candidates or longest prefix.
    """
    if not provided:
        return provided

    provided = provided.strip()
    available = _list_property_urls(service)
    available_set = set(available)

    # Quick exact matches (handle missing trailing slash for URL props)
    if provided in available_set:
        return provided
    if (provided.startswith("http://") or provided.startswith("https://")):
        with_slash = _ensure_trailing_slash(provided)
        if with_slash in available_set:
            return with_slash

    # If already sc-domain but not exact, try normalized domain
    if provided.startswith("sc-domain:"):
        dom = _normalize_domain(provided)
        candidates = [f"sc-domain:{dom}", f"sc-domain:{dom.lstrip('www.')}" ]
        for c in candidates:
            if c in available_set:
                return c

    # Otherwise build candidates from domain/hostname
    dom = _normalize_domain(provided)
    dom_nowww = dom.lstrip("www.")
    candidates = [
        f"sc-domain:{dom_nowww}",
        f"sc-domain:{dom}",
        f"https://{dom}/",
        f"https://www.{dom_nowww}/",
        f"http://{dom}/",
        f"http://www.{dom_nowww}/",
    ]
    for c in candidates:
        if c in available_set:
            return c

    # If provided looks like a URL, choose the longest property that is a prefix of it
    if provided.startswith("http://") or provided.startswith("https://"):
        provided_url = _ensure_trailing_slash(provided)
        best = ""
        for prop in available:
            if prop and provided_url.startswith(prop) and len(prop) > len(best):
                best = prop
        if best:
            return best

    # Fallback to provided (let API error if invalid)
    return provided

def get_gsc_service():
    """
    Returns an authorized Search Console service object.
    First tries OAuth authentication, then falls back to service account.
    """
    # Try OAuth authentication first if not skipped
    if not SKIP_OAUTH:
        # Prefer credentials loaded from a persisted token file (for non-interactive environments)
        creds = _load_oauth_credentials_if_any()
        if creds is not None:
            return _build_gsc_service(creds)
        try:
            return get_gsc_service_oauth()
        except Exception as e:
            # If OAuth fails, try service account
            pass
    
    # Try service account authentication
    for cred_path in POSSIBLE_CREDENTIAL_PATHS:
        if cred_path and os.path.exists(cred_path):
            try:
                creds = service_account.Credentials.from_service_account_file(
                    cred_path, scopes=SCOPES
                )
                return _build_gsc_service(creds)
            except Exception as e:
                continue  # Try the next path if this one fails
    
    # If we get here, none of the authentication methods worked
    raise FileNotFoundError(
        f"Authentication failed. Please either:\n"
        f"1. Set up OAuth by placing a client_secrets.json file in the script directory, or\n"
        f"2. Set the GSC_CREDENTIALS_PATH environment variable or place a service account credentials file in one of these locations: "
        f"{', '.join([p for p in POSSIBLE_CREDENTIAL_PATHS[1:] if p])}"
    )

def get_gsc_service_oauth():
    """
    Returns an authorized Search Console service object using OAuth.
    """
    creds = None
    
    # Check if token file exists
    if os.path.exists(TOKEN_FILE):
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)
    
    # If credentials don't exist or are invalid, get new ones
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            creds.refresh(Request())
        else:
            # Check if client secrets file exists
            if not os.path.exists(OAUTH_CLIENT_SECRETS_FILE):
                raise FileNotFoundError(
                    f"OAuth client secrets file not found. Please place a client_secrets.json file in the script directory "
                    f"or set the GSC_OAUTH_CLIENT_SECRETS_FILE environment variable."
                )
            
            # Start OAuth flow
            flow = InstalledAppFlow.from_client_secrets_file(OAUTH_CLIENT_SECRETS_FILE, SCOPES)
            creds = flow.run_local_server(port=0)
            
            # Save the credentials for future use
            with open(TOKEN_FILE, 'w') as token:
                token.write(creds.to_json())
    
    # Build and return the service
    return _build_gsc_service(creds)

@mcp.tool()
async def list_properties() -> str:
    """
    Retrieves and returns the user's Search Console properties.
    """
    try:
        service = get_gsc_service()
        site_list = service.sites().list().execute()

        # site_list is typically something like:
        # {
        #   "siteEntry": [
        #       {"siteUrl": "...", "permissionLevel": "..."},
        #       ...
        #   ]
        # }
        sites = site_list.get("siteEntry", [])

        if not sites:
            return "No Search Console properties found."

        # Format the results for easy reading
        lines = []
        for site in sites:
            site_url = site.get("siteUrl", "Unknown")
            permission = site.get("permissionLevel", "Unknown permission")
            lines.append(f"- {site_url} ({permission})")

        return "\n".join(lines)
    except FileNotFoundError as e:
        return (
            "Error: Service account credentials file not found.\n\n"
            "To access Google Search Console, please:\n"
            "1. Create a service account in Google Cloud Console\n"
            "2. Download the JSON credentials file\n"
            "3. Save it as 'service_account_credentials.json' in the same directory as this script\n"
            "4. Share your GSC properties with the service account email"
        )
    except Exception as e:
        return f"Error retrieving properties: {str(e)}"

@mcp.tool()
async def add_site(site_url: str) -> str:
    """
    Add a site to your Search Console properties.
    
    Args:
        site_url: The URL of the site to add (must be exact match e.g. https://example.com, or https://www.example.com, or https://subdomain.example.com/path/, for domain properties use format: sc-domain:example.com)
    """
    try:
        service = get_gsc_service()
        
        # Add the site
        response = service.sites().add(siteUrl=site_url).execute()
        
        # Format the response
        result_lines = [f"Site {site_url} has been added to Search Console."]
        
        # Add permission level if available
        if "permissionLevel" in response:
            result_lines.append(f"Permission level: {response['permissionLevel']}")
        
        return "\n".join(result_lines)
    except HttpError as e:
        error_content = json.loads(e.content.decode('utf-8'))
        error_details = error_content.get('error', {})
        error_code = e.resp.status
        error_message = error_details.get('message', str(e))
        error_reason = error_details.get('errors', [{}])[0].get('reason', '')
        
        if error_code == 409:
            return f"Site {site_url} is already added to Search Console."
        elif error_code == 403:
            if error_reason == 'forbidden':
                return f"Error: You don't have permission to add this site. Please verify ownership first."
            elif error_reason == 'quotaExceeded':
                return f"Error: API quota exceeded. Please try again later."
            else:
                return f"Error: Permission denied. {error_message}"
        elif error_code == 400:
            if error_reason == 'invalidParameter':
                return f"Error: Invalid site URL format. Please check the URL format and try again."
            else:
                return f"Error: Bad request. {error_message}"
        elif error_code == 401:
            return f"Error: Unauthorized. Please check your credentials."
        elif error_code == 429:
            return f"Error: Too many requests. Please try again later."
        elif error_code == 500:
            return f"Error: Internal server error from Google Search Console API. Please try again later."
        elif error_code == 503:
            return f"Error: Service unavailable. Google Search Console API is currently down. Please try again later."
        else:
            return f"Error adding site (HTTP {error_code}): {error_message}"
    except Exception as e:
        return f"Error adding site: {str(e)}"

@mcp.tool()
async def delete_site(site_url: str) -> str:
    """
    Remove a site from your Search Console properties.
    
    Args:
        site_url: The URL of the site to remove (must be exact match e.g. https://example.com, or https://www.example.com, or https://subdomain.example.com/path/, for domain properties use format: sc-domain:example.com)
    """
    try:
        service = get_gsc_service()
        
        # Delete the site
        service.sites().delete(siteUrl=site_url).execute()
        
        return f"Site {site_url} has been removed from Search Console."
    except HttpError as e:
        error_content = json.loads(e.content.decode('utf-8'))
        error_details = error_content.get('error', {})
        error_code = e.resp.status
        error_message = error_details.get('message', str(e))
        error_reason = error_details.get('errors', [{}])[0].get('reason', '')
        
        if error_code == 404:
            return f"Site {site_url} was not found in Search Console."
        elif error_code == 403:
            if error_reason == 'forbidden':
                return f"Error: You don't have permission to remove this site."
            elif error_reason == 'quotaExceeded':
                return f"Error: API quota exceeded. Please try again later."
            else:
                return f"Error: Permission denied. {error_message}"
        elif error_code == 400:
            if error_reason == 'invalidParameter':
                return f"Error: Invalid site URL format. Please check the URL format and try again."
            else:
                return f"Error: Bad request. {error_message}"
        elif error_code == 401:
            return f"Error: Unauthorized. Please check your credentials."
        elif error_code == 429:
            return f"Error: Too many requests. Please try again later."
        elif error_code == 500:
            return f"Error: Internal server error from Google Search Console API. Please try again later."
        elif error_code == 503:
            return f"Error: Service unavailable. Google Search Console API is currently down. Please try again later."
        else:
            return f"Error removing site (HTTP {error_code}): {error_message}"
    except Exception as e:
        return f"Error removing site: {str(e)}"

@mcp.tool()
async def get_search_analytics(site_url: str, days: int = 28, dimensions: str = "query", row_limit: int = 1000, start_row: int = 0, auto_paginate: Optional[bool] = None) -> str:
    """
    Get search analytics data for a specific property.
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match)
        days: Number of days to look back (default: 28)
        dimensions: Dimensions to group by (default: query). Options: query, page, device, country, date
                   You can provide multiple dimensions separated by comma (e.g., "query,page")
        row_limit: Max rows to return (default 1000, API max 25000)
        start_row: Starting row for pagination (default 0)
        auto_paginate: If true, fetches all pages up to the global max. Defaults to env GSC_AUTO_PAGINATE_DEFAULT.
    """
    try:
        service = get_gsc_service()
        site_url = _resolve_site_url(service, site_url)
        
        # Calculate date range
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)
        
        # Parse dimensions
        dimension_list = [d.strip() for d in dimensions.split(",")]
        
        # Build request
        request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": dimension_list,
            "rowLimit": min(int(row_limit), 25000),
            "startRow": int(start_row),
        }
        
        # Execute request (optionally auto-paginate)
        effective_auto = GSC_AUTO_PAGINATE_DEFAULT if auto_paginate is None else bool(auto_paginate)
        if effective_auto:
            rows = await _sa_query_all(service, site_url, request, GSC_AUTO_PAGINATE_MAX_ROWS)
        else:
            response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()
            rows = response.get("rows", [])
        
        if not rows:
            return f"No search analytics data found for {site_url} in the last {days} days."
        
        # Format results
        result_lines = [f"Search analytics for {site_url} (last {days} days):"]
        result_lines.append("\n" + "-" * 80 + "\n")
        
        # Create header based on dimensions
        header = []
        for dim in dimension_list:
            header.append(dim.capitalize())
        header.extend(["Clicks", "Impressions", "CTR", "Position"])
        result_lines.append(" | ".join(header))
        result_lines.append("-" * 80)
        
        # Add data rows
        for row in rows:
            data = []
            # Add dimension values
            for dim_value in row.get("keys", []):
                data.append(dim_value[:100])  # Truncate long values for readability
            
            # Add metrics
            data.append(str(row.get("clicks", 0)))
            data.append(str(row.get("impressions", 0)))
            data.append(f"{row.get('ctr', 0) * 100:.2f}%")
            data.append(f"{row.get('position', 0):.1f}")
            
            result_lines.append(" | ".join(data))
        
        # Pagination hint only if not auto-paginating
        if not effective_auto:
            shown = len(rows)
            if shown == min(int(row_limit), 25000):
                next_start = int(start_row) + shown
                result_lines.append("\nThere may be more results. To fetch next page, call with:")
                result_lines.append(f"start_row: {next_start}, row_limit: {row_limit}")
        
        return "\n".join(result_lines)
    except Exception as e:
        return f"Error retrieving search analytics: {str(e)}"

@mcp.tool()
async def get_site_details(site_url: str) -> str:
    """
    Get detailed information about a specific Search Console property.
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match)
    """
    try:
        service = get_gsc_service()
        site_url = _resolve_site_url(service, site_url)
        
        # Get site details
        site_info = service.sites().get(siteUrl=site_url).execute()
        
        # Format the results
        result_lines = [f"Site details for {site_url}:"]
        result_lines.append("-" * 50)
        
        # Add basic info
        result_lines.append(f"Permission level: {site_info.get('permissionLevel', 'Unknown')}")
        
        # Add verification info if available
        if "siteVerificationInfo" in site_info:
            verify_info = site_info["siteVerificationInfo"]
            result_lines.append(f"Verification state: {verify_info.get('verificationState', 'Unknown')}")
            
            if "verifiedUser" in verify_info:
                result_lines.append(f"Verified by: {verify_info['verifiedUser']}")
                
            if "verificationMethod" in verify_info:
                result_lines.append(f"Verification method: {verify_info['verificationMethod']}")
        
        # Add ownership info if available
        if "ownershipInfo" in site_info:
            owner_info = site_info["ownershipInfo"]
            result_lines.append("\nOwnership Information:")
            result_lines.append(f"Owner: {owner_info.get('owner', 'Unknown')}")
            
            if "verificationMethod" in owner_info:
                result_lines.append(f"Ownership verification: {owner_info['verificationMethod']}")
        
        return "\n".join(result_lines)
    except Exception as e:
        return f"Error retrieving site details: {str(e)}"

@mcp.tool()
async def get_sitemaps(site_url: str) -> str:
    """
    List all sitemaps for a specific Search Console property.
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match)
    """
    try:
        service = get_gsc_service()
        site_url = _resolve_site_url(service, site_url)
        
        # Get sitemaps list
        sitemaps = service.sitemaps().list(siteUrl=site_url).execute()
        
        if not sitemaps.get("sitemap"):
            return f"No sitemaps found for {site_url}."
        
        # Format the results
        result_lines = [f"Sitemaps for {site_url}:"]
        result_lines.append("-" * 80)
        
        # Header
        result_lines.append("Path | Last Downloaded | Status | Indexed URLs | Errors")
        result_lines.append("-" * 80)
        
        # Add each sitemap
        for sitemap in sitemaps.get("sitemap", []):
            path = sitemap.get("path", "Unknown")
            last_downloaded = sitemap.get("lastDownloaded", "Never")
            
            # Format last downloaded date if it exists
            if last_downloaded != "Never":
                try:
                    # Convert to more readable format
                    dt = datetime.fromisoformat(last_downloaded.replace('Z', '+00:00'))
                    last_downloaded = dt.strftime("%Y-%m-%d %H:%M")
                except:
                    pass
            
            status = "Valid"
            if "errors" in sitemap and sitemap["errors"] > 0:
                status = "Has errors"
            
            # Get counts
            warnings = sitemap.get("warnings", 0)
            errors = sitemap.get("errors", 0)
            
            # Get contents if available
            indexed_urls = "N/A"
            if "contents" in sitemap:
                for content in sitemap["contents"]:
                    if content.get("type") == "web":
                        indexed_urls = content.get("submitted", "0")
                        break
            
            result_lines.append(f"{path} | {last_downloaded} | {status} | {indexed_urls} | {errors}")
        
        return "\n".join(result_lines)
    except Exception as e:
        return f"Error retrieving sitemaps: {str(e)}"

@mcp.tool()
async def inspect_url_enhanced(site_url: str, page_url: str) -> str:
    """
    Enhanced URL inspection to check indexing status and rich results in Google.
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match, for domain properties use format: sc-domain:example.com)
        page_url: The specific URL to inspect
    """
    try:
        await INSPECTION_SEMAPHORE.acquire()
        try:
            service = get_gsc_service()
            site_url = _resolve_site_url(service, site_url)
            
            # Build request
            request = {
                "inspectionUrl": page_url,
                "siteUrl": site_url
            }
            
            # Execute request
            response = await _execute_with_retries(lambda: service.urlInspection().index().inspect(body=request).execute())
            
            if not response or "inspectionResult" not in response:
                return f"No inspection data found for {page_url}."
            
            inspection = response["inspectionResult"]
            
            # Format the results
            result_lines = [f"URL Inspection for {page_url}:"]
            result_lines.append("-" * 80)
            
            # Add inspection result link if available
            if "inspectionResultLink" in inspection:
                result_lines.append(f"Search Console Link: {inspection['inspectionResultLink']}")
                result_lines.append("-" * 80)
            
            # Indexing status section
            index_status = inspection.get("indexStatusResult", {})
            verdict = index_status.get("verdict", "UNKNOWN")
            
            result_lines.append(f"Indexing Status: {verdict}")
            
            # Coverage state
            if "coverageState" in index_status:
                result_lines.append(f"Coverage: {index_status['coverageState']}")
            
            # Last crawl
            if "lastCrawlTime" in index_status:
                try:
                    crawl_time = datetime.fromisoformat(index_status["lastCrawlTime"].replace('Z', '+00:00'))
                    result_lines.append(f"Last Crawled: {crawl_time.strftime('%Y-%m-%d %H:%M')}")
                except:
                    result_lines.append(f"Last Crawled: {index_status['lastCrawlTime']}")
            
            # Page fetch
            if "pageFetchState" in index_status:
                result_lines.append(f"Page Fetch: {index_status['pageFetchState']}")
            
            # Robots.txt status
            if "robotsTxtState" in index_status:
                result_lines.append(f"Robots.txt: {index_status['robotsTxtState']}")
            
            # Indexing state
            if "indexingState" in index_status:
                result_lines.append(f"Indexing State: {index_status['indexingState']}")
            
            # Canonical information
            if "googleCanonical" in index_status:
                result_lines.append(f"Google Canonical: {index_status['googleCanonical']}")
            
            if "userCanonical" in index_status and index_status.get("userCanonical") != index_status.get("googleCanonical"):
                result_lines.append(f"User Canonical: {index_status['userCanonical']}")
            
            # Crawled as
            if "crawledAs" in index_status:
                result_lines.append(f"Crawled As: {index_status['crawledAs']}")
            
            # Referring URLs
            if "referringUrls" in index_status and index_status["referringUrls"]:
                result_lines.append("\nReferring URLs:")
                for url in index_status["referringUrls"][:5]:  # Limit to 5 examples
                    result_lines.append(f"- {url}")
                
                if len(index_status["referringUrls"]) > 5:
                    result_lines.append(f"... and {len(index_status['referringUrls']) - 5} more")
            
            # Rich results
            if "richResultsResult" in inspection:
                rich = inspection["richResultsResult"]
                result_lines.append(f"\nRich Results: {rich.get('verdict', 'UNKNOWN')}")
                
                if "detectedItems" in rich and rich["detectedItems"]:
                    result_lines.append("Detected Rich Result Types:")
                    
                    for item in rich["detectedItems"]:
                        rich_type = item.get("richResultType", "Unknown")
                        result_lines.append(f"- {rich_type}")
                        
                        # If there are items with names, show them
                        if "items" in item and item["items"]:
                            for i, subitem in enumerate(item["items"][:3]):  # Limit to 3 examples
                                if "name" in subitem:
                                    result_lines.append(f"  • {subitem['name']}")
                            
                            if len(item["items"]) > 3:
                                result_lines.append(f"  • ... and {len(item['items']) - 3} more items")
                
                # Check for issues
                if "richResultsIssues" in rich and rich["richResultsIssues"]:
                    result_lines.append("\nRich Results Issues:")
                    for issue in rich["richResultsIssues"]:
                        severity = issue.get("severity", "Unknown")
                        message = issue.get("message", "Unknown issue")
                        result_lines.append(f"- [{severity}] {message}")
            
            return "\n".join(result_lines)
        finally:
            INSPECTION_SEMAPHORE.release()
    except Exception as e:
        return f"Error inspecting URL: {str(e)}"

@mcp.tool()
async def batch_url_inspection(site_url: str, urls: str) -> str:
    """
    Inspect multiple URLs in batch (within API limits).
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match, for domain properties use format: sc-domain:example.com)
        urls: List of URLs to inspect, one per line
    """
    try:
        await INSPECTION_SEMAPHORE.acquire()
        try:
            service = get_gsc_service()
            site_url = _resolve_site_url(service, site_url)
            
            # Parse URLs
            url_list = [url.strip() for url in urls.split('\n') if url.strip()]
            
            if not url_list:
                return "No URLs provided for inspection."
            
            if len(url_list) > 10:
                return f"Too many URLs provided ({len(url_list)}). Please limit to 10 URLs per batch to avoid API quota issues."
            
            # Process each URL
            results = []
            
            for page_url in url_list:
                # Build request
                request = {
                    "inspectionUrl": page_url,
                    "siteUrl": site_url
                }
                
                try:
                    # Execute request with retries
                    response = await _execute_with_retries(lambda: service.urlInspection().index().inspect(body=request).execute())
                    
                    if not response or "inspectionResult" not in response:
                        results.append(f"{page_url}: No inspection data found")
                        # Sleep between requests if configured
                        if GSC_SLEEP_BETWEEN_REQUESTS_MS > 0:
                            await asyncio.sleep(GSC_SLEEP_BETWEEN_REQUESTS_MS / 1000.0)
                        continue
                    
                    inspection = response["inspectionResult"]
                    index_status = inspection.get("indexStatusResult", {})
                    
                    # Get key information
                    verdict = index_status.get("verdict", "UNKNOWN")
                    coverage = index_status.get("coverageState", "Unknown")
                    last_crawl = "Never"
                    
                    if "lastCrawlTime" in index_status:
                        try:
                            crawl_time = datetime.fromisoformat(index_status["lastCrawlTime"].replace('Z', '+00:00'))
                            last_crawl = crawl_time.strftime('%Y-%m-%d')
                        except:
                            last_crawl = index_status["lastCrawlTime"]
                    
                    # Check for rich results
                    rich_results = "None"
                    if "richResultsResult" in inspection:
                        rich = inspection["richResultsResult"]
                        if rich.get("verdict") == "PASS" and "detectedItems" in rich and rich["detectedItems"]:
                            rich_types = [item.get("richResultType", "Unknown") for item in rich["detectedItems"]]
                            rich_results = ", ".join(rich_types)
                    
                    # Format result
                    results.append(f"{page_url}:\n  Status: {verdict} - {coverage}\n  Last Crawl: {last_crawl}\n  Rich Results: {rich_results}\n")
                
                except Exception as e:
                    results.append(f"{page_url}: Error - {str(e)}")
                
                # Sleep between requests if configured
                if GSC_SLEEP_BETWEEN_REQUESTS_MS > 0:
                    await asyncio.sleep(GSC_SLEEP_BETWEEN_REQUESTS_MS / 1000.0)
            
            # Combine results
            return f"Batch URL Inspection Results for {site_url}:\n\n" + "\n".join(results)
        finally:
            INSPECTION_SEMAPHORE.release()
    
    except Exception as e:
        return f"Error performing batch inspection: {str(e)}"

@mcp.tool()
async def check_indexing_issues(site_url: str, urls: str) -> str:
    """
    Check for specific indexing issues across multiple URLs.
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match, for domain properties use format: sc-domain:example.com)
        urls: List of URLs to check, one per line
    """
    try:
        await INSPECTION_SEMAPHORE.acquire()
        try:
            service = get_gsc_service()
            site_url = _resolve_site_url(service, site_url)
            
            # Parse URLs
            url_list = [url.strip() for url in urls.split('\n') if url.strip()]
            
            if not url_list:
                return "No URLs provided for inspection."
            
            if len(url_list) > 10:
                return f"Too many URLs provided ({len(url_list)}). Please limit to 10 URLs per batch to avoid API quota issues."
            
            # Track issues by category
            issues_summary = {
                "not_indexed": [],
                "canonical_issues": [],
                "robots_blocked": [],
                "fetch_issues": [],
                "indexed": []
            }
            
            # Process each URL
            for page_url in url_list:
                # Build request
                request = {
                    "inspectionUrl": page_url,
                    "siteUrl": site_url
                }
                
                try:
                    # Execute request
                    response = await _execute_with_retries(lambda: service.urlInspection().index().inspect(body=request).execute())
                    
                    if not response or "inspectionResult" not in response:
                        issues_summary["not_indexed"].append(f"{page_url} - No inspection data found")
                        if GSC_SLEEP_BETWEEN_REQUESTS_MS > 0:
                            await asyncio.sleep(GSC_SLEEP_BETWEEN_REQUESTS_MS / 1000.0)
                        continue
                    
                    inspection = response["inspectionResult"]
                    index_status = inspection.get("indexStatusResult", {})
                    
                    # Check indexing status
                    verdict = index_status.get("verdict", "UNKNOWN")
                    coverage = index_status.get("coverageState", "Unknown")
                    
                    if verdict != "PASS" or "not indexed" in coverage.lower() or "excluded" in coverage.lower():
                        issues_summary["not_indexed"].append(f"{page_url} - {verdict} ({coverage})")
                    else:
                        issues_summary["indexed"].append(f"{page_url} - {verdict} ({coverage})")
                    
                    # Check canonical issues
                    google_canonical = index_status.get("googleCanonical")
                    user_canonical = index_status.get("userCanonical")
                    if user_canonical and google_canonical and user_canonical != google_canonical:
                        issues_summary["canonical_issues"].append(f"{page_url} - User: {user_canonical}, Google: {google_canonical}")
                    
                    # Check robots.txt issues
                    robots_state = index_status.get("robotsTxtState", "").lower()
                    if "blocked" in robots_state:
                        issues_summary["robots_blocked"].append(f"{page_url} - Robots: {index_status.get('robotsTxtState', 'Unknown')}")
                    
                    # Check fetch issues
                    fetch_state = index_status.get("pageFetchState", "").lower()
                    if fetch_state and fetch_state not in ("ok", "success"):
                        issues_summary["fetch_issues"].append(f"{page_url} - Fetch: {index_status.get('pageFetchState', 'Unknown')}")
                
                except Exception as e:
                    issues_summary["fetch_issues"].append(f"{page_url} - Error: {str(e)}")
                
                if GSC_SLEEP_BETWEEN_REQUESTS_MS > 0:
                    await asyncio.sleep(GSC_SLEEP_BETWEEN_REQUESTS_MS / 1000.0)
            
            # Format summary
            result_lines = [f"Indexing Issues Summary for {site_url}:"]
            result_lines.append("-" * 60)
            
            def _format_section(title: str, items: List[str]):
                result_lines.append(f"\n{title} ({len(items)}):")
                if not items:
                    result_lines.append("  - None")
                else:
                    for item in items:
                        result_lines.append(f"  - {item}")
            
            _format_section("Indexed", issues_summary["indexed"])
            _format_section("Not Indexed / Excluded", issues_summary["not_indexed"])
            _format_section("Canonical Issues", issues_summary["canonical_issues"])
            _format_section("Robots Blocked", issues_summary["robots_blocked"])
            _format_section("Fetch Issues / Errors", issues_summary["fetch_issues"])
            
            return "\n".join(result_lines)
        finally:
            INSPECTION_SEMAPHORE.release()
    except Exception as e:
        return f"Error checking indexing issues: {str(e)}"

@mcp.tool()
async def get_top_pages_with_indexing(site_url: str, days: int = 28, limit: int = 10, batch_size: int = 3) -> str:
    """
    Fetch top pages by clicks and inspect their indexing status in one controlled call.
    This avoids client-side parallel tool calls and respects server pacing.
    
    Args:
        site_url: GSC property (exact match or sc-domain:example.com)
        days: Lookback window (default 28)
        limit: Number of top pages to include (default 10)
        batch_size: Number of URLs to process between short pauses (default 3)
    """
    try:
        await INSPECTION_SEMAPHORE.acquire()
        try:
            service = get_gsc_service()
            site_url = _resolve_site_url(service, site_url)
            end_date = datetime.now().date()
            start_date = end_date - timedelta(days=days)
            # Get top pages
            req = {
                "startDate": start_date.strftime("%Y-%m-%d"),
                "endDate": end_date.strftime("%Y-%m-%d"),
                "dimensions": ["page"],
                "rowLimit": int(limit),
                "startRow": 0,
                "aggregationType": "auto",
            }
            sa = service.searchanalytics().query(siteUrl=site_url, body=req).execute()
            rows = sa.get("rows", [])
            if not rows:
                return f"No search analytics data found for {site_url} in the last {days} days."
            pages: List[Dict[str, Any]] = []
            for r in rows:
                keys = r.get("keys", [])
                if not keys:
                    continue
                page = keys[0]
                pages.append({
                    "url": page,
                    "clicks": r.get("clicks", 0),
                    "impressions": r.get("impressions", 0),
                    "ctr": r.get("ctr", 0.0),
                    "position": r.get("position", 0.0),
                })
            # Inspect
            results = []
            processed_in_batch = 0
            for p in pages:
                request = {"inspectionUrl": p["url"], "siteUrl": site_url}
                try:
                    resp = await _execute_with_retries(lambda: service.urlInspection().index().inspect(body=request).execute())
                    insp = resp.get("inspectionResult", {})
                    idx = insp.get("indexStatusResult", {})
                    verdict = idx.get("verdict", "UNKNOWN")
                    coverage = idx.get("coverageState", "Unknown")
                    last_crawl = idx.get("lastCrawlTime", "")
                    if last_crawl:
                        try:
                            last_crawl = datetime.fromisoformat(last_crawl.replace('Z', '+00:00')).strftime('%Y-%m-%d')
                        except:
                            pass
                    robots = idx.get("robotsTxtState", "")
                    gcanon = idx.get("googleCanonical", "")
                    ucanon = idx.get("userCanonical", "")
                    rich = insp.get("richResultsResult", {})
                    rich_status = rich.get("verdict", "UNKNOWN")
                    rich_types = []
                    for it in rich.get("detectedItems", []) or []:
                        t = it.get("richResultType")
                        if t:
                            rich_types.append(t)
                    results.append({
                        **p,
                        "index_verdict": verdict,
                        "coverage": coverage,
                        "last_crawl": last_crawl or "",
                        "google_canonical": gcanon,
                        "user_canonical": ucanon,
                        "robots": robots,
                        "rich": (", ".join(rich_types) if rich_types else (rich_status if rich_status != "UNKNOWN" else "None")),
                    })
                except Exception as e:
                    results.append({**p, "index_verdict": f"Error: {str(e)}", "coverage": "", "last_crawl": "", "google_canonical": "", "user_canonical": "", "robots": "", "rich": ""})
                # pacing
                processed_in_batch += 1
                if processed_in_batch >= max(1, int(batch_size)):
                    processed_in_batch = 0
                    if GSC_SLEEP_BETWEEN_REQUESTS_MS > 0:
                        await asyncio.sleep(GSC_SLEEP_BETWEEN_REQUESTS_MS / 1000.0)
            # Format table-like output
            out = [f"Top {len(results)} pages for {site_url} (last {days} days) with indexing status:"]
            header = [
                "URL", "Clicks", "Impr.", "CTR", "Pos.", "Index", "Coverage", "LastCrawl", "G-Canonical", "U-Canonical", "Robots", "Rich"
            ]
            out.append("\t".join(header))
            for r in results:
                out.append("\t".join([
                    r.get("url", ""),
                    str(r.get("clicks", 0)),
                    str(r.get("impressions", 0)),
                    f"{float(r.get('ctr', 0.0)) * 100:.2f}%",
                    f"{float(r.get('position', 0.0)):.1f}",
                    r.get("index_verdict", ""),
                    r.get("coverage", ""),
                    r.get("last_crawl", ""),
                    r.get("google_canonical", ""),
                    r.get("user_canonical", ""),
                    r.get("robots", ""),
                    r.get("rich", ""),
                ]))
            return "\n".join(out)
        finally:
            INSPECTION_SEMAPHORE.release()
    except Exception as e:
        return f"Error building top pages indexing report: {str(e)}"

@mcp.tool()
async def get_performance_overview(site_url: str, days: int = 28) -> str:
    """
    Get a performance overview for a specific property.
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match)
        days: Number of days to look back (default: 28)
    """
    try:
        service = get_gsc_service()
        site_url = _resolve_site_url(service, site_url)
        
        # Calculate date range
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)
        
        # Get total metrics
        total_request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": [],  # No dimensions for totals
            "rowLimit": 1
        }
        
        total_response = service.searchanalytics().query(siteUrl=site_url, body=total_request).execute()
        
        # Get by date for trend
        date_request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": ["date"],
            "rowLimit": days
        }
        
        date_response = service.searchanalytics().query(siteUrl=site_url, body=date_request).execute()
        
        # Format results
        result_lines = [f"Performance Overview for {site_url} (last {days} days):"]
        result_lines.append("-" * 80)
        
        # Add total metrics
        if total_response.get("rows"):
            row = total_response["rows"][0]
            result_lines.append(f"Total Clicks: {row.get('clicks', 0):,}")
            result_lines.append(f"Total Impressions: {row.get('impressions', 0):,}")
            result_lines.append(f"Average CTR: {row.get('ctr', 0) * 100:.2f}%")
            result_lines.append(f"Average Position: {row.get('position', 0):.1f}")
        else:
            result_lines.append("No data available for the selected period.")
            return "\n".join(result_lines)
        
        # Add trend data
        if date_response.get("rows"):
            result_lines.append("\nDaily Trend:")
            result_lines.append("Date | Clicks | Impressions | CTR | Position")
            result_lines.append("-" * 80)
            
            # Sort by date
            sorted_rows = sorted(date_response["rows"], key=lambda x: x["keys"][0])
            
            for row in sorted_rows:
                date_str = row["keys"][0]
                # Format date from YYYY-MM-DD to MM/DD
                try:
                    date_obj = datetime.strptime(date_str, "%Y-%m-%d")
                    date_formatted = date_obj.strftime("%m/%d")
                except:
                    date_formatted = date_str
                
                clicks = row.get("clicks", 0)
                impressions = row.get("impressions", 0)
                ctr = row.get("ctr", 0) * 100
                position = row.get("position", 0)
                
                result_lines.append(f"{date_formatted} | {clicks:.0f} | {impressions:.0f} | {ctr:.2f}% | {position:.1f}")
        
        return "\n".join(result_lines)
    except Exception as e:
        return f"Error retrieving performance overview: {str(e)}"

@mcp.tool()
async def get_advanced_search_analytics(
    site_url: str, 
    start_date: str = None, 
    end_date: str = None, 
    dimensions: str = "query", 
    search_type: str = "WEB",
    row_limit: int = 1000,
    start_row: int = 0,
    sort_by: str = "clicks",
    sort_direction: str = "descending",
    filter_dimension: str = None,
    filter_operator: str = "contains", 
    filter_expression: str = None,
    auto_paginate: Optional[bool] = None,
) -> str:
    """
    Get advanced search analytics data with sorting, filtering, and pagination.
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match)
        start_date: Start date in YYYY-MM-DD format (defaults to 28 days ago)
        end_date: End date in YYYY-MM-DD format (defaults to today)
        dimensions: Dimensions to group by, comma-separated (e.g., "query,page,device")
        search_type: Type of search results (WEB, IMAGE, VIDEO, NEWS, DISCOVER)
        row_limit: Maximum number of rows to return (max 25000)
        start_row: Starting row for pagination
        sort_by: Metric to sort by (clicks, impressions, ctr, position)
        sort_direction: Sort direction (ascending or descending)
        filter_dimension: Dimension to filter on (query, page, country, device)
        filter_operator: Filter operator (contains, equals, notContains, notEquals)
        filter_expression: Filter expression value
        auto_paginate: If true, fetches all pages up to the global max. Defaults to env GSC_AUTO_PAGINATE_DEFAULT.
    """
    try:
        service = get_gsc_service()
        site_url = _resolve_site_url(service, site_url)
        
        # Calculate date range if not provided
        if not end_date:
            end_date = datetime.now().date().strftime("%Y-%m-%d")
        if not start_date:
            start_date = (datetime.now().date() - timedelta(days=28)).strftime("%Y-%m-%d")
        
        # Parse dimensions
        dimension_list = [d.strip() for d in dimensions.split(",")]
        
        # Build request
        request = {
            "startDate": start_date,
            "endDate": end_date,
            "dimensions": dimension_list,
            "rowLimit": min(row_limit, 25000),  # Cap at API maximum
            "startRow": start_row,
            "searchType": search_type.upper()
        }
        
        # Add sorting
        if sort_by:
            metric_map = {
                "clicks": "CLICK_COUNT",
                "impressions": "IMPRESSION_COUNT",
                "ctr": "CTR",
                "position": "POSITION"
            }
            
            if sort_by in metric_map:
                request["orderBy"] = [{
                    "metric": metric_map[sort_by],
                    "direction": sort_direction.lower()
                }]
        
        # Add filtering if provided
        if filter_dimension and filter_expression:
            filter_group = {
                "filters": [{
                    "dimension": filter_dimension,
                    "operator": filter_operator,
                    "expression": filter_expression
                }]
            }
            request["dimensionFilterGroups"] = [filter_group]
        
        # Execute request (optionally auto-paginate)
        effective_auto = GSC_AUTO_PAGINATE_DEFAULT if auto_paginate is None else bool(auto_paginate)
        if effective_auto:
            rows = await _sa_query_all(service, site_url, request, GSC_AUTO_PAGINATE_MAX_ROWS)
        else:
            response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()
            rows = response.get("rows", [])
        
        if not rows:
            return (f"No search analytics data found for {site_url} with the specified parameters.\n\n"
                   f"Parameters used:\n"
                   f"- Date range: {start_date} to {end_date}\n"
                   f"- Dimensions: {dimensions}\n"
                   f"- Search type: {search_type}\n"
                   f"- Filter: {filter_dimension} {filter_operator} '{filter_expression}'" if filter_dimension else "- No filter applied")
        
        # Format results
        result_lines = [f"Search analytics for {site_url}:"]
        result_lines.append(f"Date range: {start_date} to {end_date}")
        result_lines.append(f"Search type: {search_type}")
        if filter_dimension:
            result_lines.append(f"Filter: {filter_dimension} {filter_operator} '{filter_expression}'")
        if effective_auto:
            result_lines.append(f"Showing all {len(rows)} rows (sorted by {sort_by} {sort_direction})")
        else:
            result_lines.append(f"Showing rows {start_row+1} to {start_row+len(rows)} (sorted by {sort_by} {sort_direction})")
        result_lines.append("\n" + "-" * 80 + "\n")
        
        # Create header based on dimensions
        header = []
        for dim in dimension_list:
            header.append(dim.capitalize())
        header.extend(["Clicks", "Impressions", "CTR", "Position"])
        result_lines.append(" | ".join(header))
        result_lines.append("-" * 80)
        
        # Add data rows
        for row in rows:
            data = []
            # Add dimension values
            for dim_value in row.get("keys", []):
                data.append(dim_value[:100])  # Increased truncation limit to 100 characters
            
            # Add metrics
            data.append(str(row.get("clicks", 0)))
            data.append(str(row.get("impressions", 0)))
            data.append(f"{row.get('ctr', 0) * 100:.2f}%")
            data.append(f"{row.get('position', 0):.1f}")
            
            result_lines.append(" | ".join(data))
        
        # Add pagination info if there might be more results
        if not effective_auto and len(rows) == row_limit:
            next_start = start_row + row_limit
            result_lines.append("\nThere may be more results available. To see the next page, use:")
            result_lines.append(f"start_row: {next_start}, row_limit: {row_limit}")
        
        return "\n".join(result_lines)
    except Exception as e:
        return f"Error retrieving advanced search analytics: {str(e)}"

@mcp.tool()
async def compare_search_periods(
    site_url: str,
    period1_start: str,
    period1_end: str,
    period2_start: str,
    period2_end: str,
    dimensions: str = "query",
    limit: int = 10,
    auto_paginate: Optional[bool] = None,
) -> str:
    """
    Compare search analytics data between two time periods.
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match)
        period1_start: Start date for period 1 (YYYY-MM-DD)
        period1_end: End date for period 1 (YYYY-MM-DD)
        period2_start: Start date for period 2 (YYYY-MM-DD)
        period2_end: End date for period 2 (YYYY-MM-DD)
        dimensions: Dimensions to group by (default: query)
        limit: Number of top results to compare (default: 10)
        auto_paginate: If true, fetches all pages up to the global max. Defaults to env GSC_AUTO_PAGINATE_DEFAULT.
    """
    try:
        service = get_gsc_service()
        site_url = _resolve_site_url(service, site_url)
        
        # Parse dimensions
        dimension_list = [d.strip() for d in dimensions.split(",")]
        
        # Build requests for both periods
        period1_request = {
            "startDate": period1_start,
            "endDate": period1_end,
            "dimensions": dimension_list,
            "rowLimit": 1000  # Default page size if not auto-paginating
        }
        
        period2_request = {
            "startDate": period2_start,
            "endDate": period2_end,
            "dimensions": dimension_list,
            "rowLimit": 1000
        }
        
        # Execute requests (optionally auto-paginate)
        effective_auto = GSC_AUTO_PAGINATE_DEFAULT if auto_paginate is None else bool(auto_paginate)
        if effective_auto:
            period1_rows = await _sa_query_all(service, site_url, period1_request, GSC_AUTO_PAGINATE_MAX_ROWS)
            period2_rows = await _sa_query_all(service, site_url, period2_request, GSC_AUTO_PAGINATE_MAX_ROWS)
        else:
            period1_response = service.searchanalytics().query(siteUrl=site_url, body=period1_request).execute()
            period2_response = service.searchanalytics().query(siteUrl=site_url, body=period2_request).execute()
            period1_rows = period1_response.get("rows", [])
            period2_rows = period2_response.get("rows", [])
        
        if not period1_rows and not period2_rows:
            return f"No data found for either period for {site_url}."
        
        # Aggregate by keys for comparison
        def to_key(row):
            return tuple(row.get("keys", []))
        
        p1_map: Dict[Any, Dict[str, Any]] = {to_key(r): r for r in period1_rows}
        p2_map: Dict[Any, Dict[str, Any]] = {to_key(r): r for r in period2_rows}
        
        # Compute deltas
        all_keys = set(p1_map.keys()) | set(p2_map.keys())
        deltas = []
        for k in all_keys:
            r1 = p1_map.get(k, {})
            r2 = p2_map.get(k, {})
            clicks_delta = float(r2.get("clicks", 0)) - float(r1.get("clicks", 0))
            impr_delta = float(r2.get("impressions", 0)) - float(r1.get("impressions", 0))
            ctr_delta = float(r2.get("ctr", 0)) - float(r1.get("ctr", 0))
            pos_delta = float(r2.get("position", 0)) - float(r1.get("position", 0))
            deltas.append((k, clicks_delta, impr_delta, ctr_delta, pos_delta, r1, r2))
        
        # Sort by impressions delta asc (drops first)
        deltas.sort(key=lambda x: x[2])
        
        # Format output
        lines = [
            f"Comparison for {site_url}",
            f"Period 1: {period1_start} to {period1_end} | Period 2: {period2_start} to {period2_end}",
            "\nKeys | ClicksΔ | ImprΔ | CTRΔ | PosΔ | P1(clicks,impr,ctr,pos) | P2(clicks,impr,ctr,pos)"
        ]
        count = 0
        for k, cΔ, iΔ, ctrΔ, pΔ, r1, r2 in deltas:
            dims = " / ".join([str(x) for x in k]) if k else "(total)"
            lines.append(
                " | ".join([
                    dims,
                    f"{cΔ:.0f}",
                    f"{iΔ:.0f}",
                    f"{(ctrΔ*100):.2f}%",
                    f"{pΔ:.1f}",
                    f"{r1.get('clicks',0):.0f},{r1.get('impressions',0):.0f},{(r1.get('ctr',0)*100):.2f}%,{r1.get('position',0):.1f}",
                    f"{r2.get('clicks',0):.0f},{r2.get('impressions',0):.0f},{(r2.get('ctr',0)*100):.2f}%,{r2.get('position',0):.1f}",
                ])
            )
            count += 1
            if limit and count >= int(limit):
                break
        return "\n".join(lines)
    except Exception as e:
        return f"Error comparing search periods: {str(e)}"

@mcp.tool()
async def get_search_by_page_query(
    site_url: str,
    page_url: str,
    days: int = 28
) -> str:
    """
    Get search analytics data for a specific page, broken down by query.
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match)
        page_url: The specific page URL to analyze
        days: Number of days to look back (default: 28)
    """
    try:
        service = get_gsc_service()
        site_url = _resolve_site_url(service, site_url)
        
        # Calculate date range
        end_date = datetime.now().date()
        start_date = end_date - timedelta(days=days)
        
        # Build request with page filter
        request = {
            "startDate": start_date.strftime("%Y-%m-%d"),
            "endDate": end_date.strftime("%Y-%m-%d"),
            "dimensions": ["query"],
            "dimensionFilterGroups": [{
                "filters": [{
                    "dimension": "page",
                    "operator": "equals",
                    "expression": page_url
                }]
            }],
            "rowLimit": 20,  # Top 20 queries for this page
            "orderBy": [{"metric": "CLICK_COUNT", "direction": "descending"}]
        }
        
        # Execute request
        response = service.searchanalytics().query(siteUrl=site_url, body=request).execute()
        
        if not response.get("rows"):
            return f"No search data found for page {page_url} in the last {days} days."
        
        # Format results
        result_lines = [f"Search queries for page {page_url} (last {days} days):"]
        result_lines.append("\n" + "-" * 80 + "\n")
        
        # Create header
        result_lines.append("Query | Clicks | Impressions | CTR | Position")
        result_lines.append("-" * 80)
        
        # Add data rows
        for row in response.get("rows", []):
            query = row.get("keys", ["Unknown"])[0]
            clicks = row.get("clicks", 0)
            impressions = row.get("impressions", 0)
            ctr = row.get("ctr", 0) * 100
            position = row.get("position", 0)
            
            result_lines.append(f"{query[:100]} | {clicks} | {impressions} | {ctr:.2f}% | {position:.1f}")
        
        # Add total metrics
        total_clicks = sum(row.get("clicks", 0) for row in response.get("rows", []))
        total_impressions = sum(row.get("impressions", 0) for row in response.get("rows", []))
        avg_ctr = (total_clicks / total_impressions * 100) if total_impressions > 0 else 0
        
        result_lines.append("-" * 80)
        result_lines.append(f"TOTAL | {total_clicks} | {total_impressions} | {avg_ctr:.2f}% | -")
        
        return "\n".join(result_lines)
    except Exception as e:
        return f"Error retrieving page query data: {str(e)}"

@mcp.tool()
async def list_sitemaps_enhanced(site_url: str, sitemap_index: str = None) -> str:
    """
    List all sitemaps for a specific Search Console property with detailed information.
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match)
        sitemap_index: Optional sitemap index URL to list child sitemaps
    """
    try:
        service = get_gsc_service()
        site_url = _resolve_site_url(service, site_url)
        
        # Get sitemaps list
        if sitemap_index:
            sitemaps = service.sitemaps().list(siteUrl=site_url, sitemapIndex=sitemap_index).execute()
            source = f"child sitemaps from index: {sitemap_index}"
        else:
            sitemaps = service.sitemaps().list(siteUrl=site_url).execute()
            source = "all submitted sitemaps"
        
        if not sitemaps.get("sitemap"):
            return f"No sitemaps found for {site_url}" + (f" in index {sitemap_index}" if sitemap_index else ".")
        
        # Format the results
        result_lines = [f"Sitemaps for {site_url} ({source}):"]
        result_lines.append("-" * 100)
        
        # Header
        result_lines.append("Path | Last Submitted | Last Downloaded | Type | URLs | Errors | Warnings")
        result_lines.append("-" * 100)
        
        # Add each sitemap
        for sitemap in sitemaps.get("sitemap", []):
            path = sitemap.get("path", "Unknown")
            
            # Format dates
            last_submitted = sitemap.get("lastSubmitted", "Never")
            if last_submitted != "Never":
                try:
                    dt = datetime.fromisoformat(last_submitted.replace('Z', '+00:00'))
                    last_submitted = dt.strftime("%Y-%m-%d %H:%M")
                except:
                    pass
            
            last_downloaded = sitemap.get("lastDownloaded", "Never")
            if last_downloaded != "Never":
                try:
                    dt = datetime.fromisoformat(last_downloaded.replace('Z', '+00:00'))
                    last_downloaded = dt.strftime("%Y-%m-%d %H:%M")
                except:
                    pass
            
            # Determine type
            sitemap_type = "Index" if sitemap.get("isSitemapsIndex", False) else "Sitemap"
            
            # Get counts
            errors = sitemap.get("errors", 0)
            warnings = sitemap.get("warnings", 0)
            
            # Get URL counts
            url_count = "N/A"
            if "contents" in sitemap:
                for content in sitemap["contents"]:
                    if content.get("type") == "web":
                        url_count = content.get("submitted", "0")
                        break
            
            result_lines.append(f"{path} | {last_submitted} | {last_downloaded} | {sitemap_type} | {url_count} | {errors} | {warnings}")
        
        # Add processing status if available
        pending_count = sum(1 for sitemap in sitemaps.get("sitemap", []) if sitemap.get("isPending", False))
        if pending_count > 0:
            result_lines.append(f"\nNote: {pending_count} sitemaps are still pending processing by Google.")
        
        return "\n".join(result_lines)
    except Exception as e:
        return f"Error retrieving sitemaps: {str(e)}"

@mcp.tool()
async def get_sitemap_details(site_url: str, sitemap_url: str) -> str:
    """
    Get detailed information about a specific sitemap.
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match)
        sitemap_url: The full URL of the sitemap to inspect
    """
    try:
        service = get_gsc_service()
        site_url = _resolve_site_url(service, site_url)
        
        # Get sitemap details
        details = service.sitemaps().get(siteUrl=site_url, feedpath=sitemap_url).execute()
        
        if not details:
            return f"No details found for sitemap {sitemap_url}."
        
        # Format the results
        result_lines = [f"Sitemap Details for {sitemap_url}:"]
        result_lines.append("-" * 80)
        
        # Basic info
        is_index = details.get("isSitemapsIndex", False)
        result_lines.append(f"Type: {'Sitemap Index' if is_index else 'Sitemap'}")
        
        # Status
        is_pending = details.get("isPending", False)
        result_lines.append(f"Status: {'Pending processing' if is_pending else 'Processed'}")
        
        # Dates
        if "lastSubmitted" in details:
            try:
                dt = datetime.fromisoformat(details["lastSubmitted"].replace('Z', '+00:00'))
                result_lines.append(f"Last Submitted: {dt.strftime('%Y-%m-%d %H:%M')}")
            except:
                result_lines.append(f"Last Submitted: {details['lastSubmitted']}")
        
        if "lastDownloaded" in details:
            try:
                dt = datetime.fromisoformat(details["lastDownloaded"].replace('Z', '+00:00'))
                result_lines.append(f"Last Downloaded: {dt.strftime('%Y-%m-%d %H:%M')}")
            except:
                result_lines.append(f"Last Downloaded: {details['lastDownloaded']}")
        
        # Errors and warnings
        result_lines.append(f"Errors: {details.get('errors', 0)}")
        result_lines.append(f"Warnings: {details.get('warnings', 0)}")
        
        # Content breakdown
        if "contents" in details and details["contents"]:
            result_lines.append("\nContent Breakdown:")
            for content in details["contents"]:
                content_type = content.get("type", "Unknown").upper()
                submitted = content.get("submitted", 0)
                indexed = content.get("indexed", "N/A")
                
                result_lines.append(f"- {content_type}: {submitted} submitted, {indexed} indexed")
        
        # If it's an index, suggest how to list child sitemaps
        if is_index:
            result_lines.append("\nThis is a sitemap index. To list child sitemaps, use:")
            result_lines.append(f"list_sitemaps_enhanced with sitemap_index={sitemap_url}")
        
        return "\n".join(result_lines)
    except Exception as e:
        return f"Error retrieving sitemap details: {str(e)}"

@mcp.tool()
async def submit_sitemap(site_url: str, sitemap_url: str) -> str:
    """
    Submit a new sitemap or resubmit an existing one to Google.
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match)
        sitemap_url: The full URL of the sitemap to submit
    """
    try:
        service = get_gsc_service()
        site_url = _resolve_site_url(service, site_url)
        
        # Submit the sitemap
        service.sitemaps().submit(siteUrl=site_url, feedpath=sitemap_url).execute()
        
        # Verify submission by getting details
        try:
            details = service.sitemaps().get(siteUrl=site_url, feedpath=sitemap_url).execute()
            
            # Format response
            result_lines = [f"Successfully submitted sitemap: {sitemap_url}"]
            
            # Add submission time if available
            if "lastSubmitted" in details:
                try:
                    dt = datetime.fromisoformat(details["lastSubmitted"].replace('Z', '+00:00'))
                    result_lines.append(f"Submission time: {dt.strftime('%Y-%m-%d %H:%M')}")
                except:
                    result_lines.append(f"Submission time: {details['lastSubmitted']}")
            
            # Add processing status
            is_pending = details.get("isPending", True)
            result_lines.append(f"Status: {'Pending processing' if is_pending else 'Processing started'}")
            
            # Add note about processing time
            result_lines.append("\nNote: Google may take some time to process the sitemap. Check back later for full details.")
            
            return "\n".join(result_lines)
        except:
            # If we can't get details, just return basic success message
            return f"Successfully submitted sitemap: {sitemap_url}\n\nGoogle will queue it for processing."
    
    except Exception as e:
        return f"Error submitting sitemap: {str(e)}"

@mcp.tool()
async def delete_sitemap(site_url: str, sitemap_url: str) -> str:
    """
    Delete (unsubmit) a sitemap from Google Search Console.
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match)
        sitemap_url: The full URL of the sitemap to delete
    """
    try:
        service = get_gsc_service()
        site_url = _resolve_site_url(service, site_url)
        
        # First check if the sitemap exists
        try:
            service.sitemaps().get(siteUrl=site_url, feedpath=sitemap_url).execute()
        except Exception as e:
            if "404" in str(e):
                return f"Sitemap not found: {sitemap_url}. It may have already been deleted or was never submitted."
            else:
                raise e
        
        # Delete the sitemap
        service.sitemaps().delete(siteUrl=site_url, feedpath=sitemap_url).execute()
        
        return f"Successfully deleted sitemap: {sitemap_url}\n\nNote: This only removes the sitemap from Search Console. Any URLs already indexed will remain in Google's index."
    
    except Exception as e:
        return f"Error deleting sitemap: {str(e)}"

@mcp.tool()
async def manage_sitemaps(site_url: str, action: str, sitemap_url: str = None, sitemap_index: str = None) -> str:
    """
    All-in-one tool to manage sitemaps (list, get details, submit, delete).
    
    Args:
        site_url: The URL of the site in Search Console (must be exact match)
        action: The action to perform (list, details, submit, delete)
        sitemap_url: The full URL of the sitemap (required for details, submit, delete)
        sitemap_index: Optional sitemap index URL for listing child sitemaps (only used with 'list' action)
    """
    try:
        # Validate inputs
        action = action.lower().strip()
        valid_actions = ["list", "details", "submit", "delete"]
        
        if action not in valid_actions:
            return f"Invalid action: {action}. Please use one of: {', '.join(valid_actions)}"
        
        if action in ["details", "submit", "delete"] and not sitemap_url:
            return f"The {action} action requires a sitemap_url parameter."
        
        # Perform the requested action
        if action == "list":
            return await list_sitemaps_enhanced(site_url, sitemap_index)
        elif action == "details":
            return await get_sitemap_details(site_url, sitemap_url)
        elif action == "submit":
            return await submit_sitemap(site_url, sitemap_url)
        elif action == "delete":
            return await delete_sitemap(site_url, sitemap_url)
    
    except Exception as e:
        return f"Error managing sitemaps: {str(e)}"

@mcp.tool()
async def get_creator_info() -> str:
    """
    Provides information about Amin Foroutan, the creator of the MCP-GSC tool.
    """
    creator_info = """
# About the Creator: Amin Foroutan

Amin Foroutan is an SEO consultant with over a decade of experience, specializing in technical SEO, Python-driven tools, and data analysis for SEO performance.

## Connect with Amin:

- **LinkedIn**: [Amin Foroutan](https://www.linkedin.com/in/ma-foroutan/)
- **Personal Website**: [aminforoutan.com](https://aminforoutan.com/)
- **YouTube**: [Amin Forout](https://www.youtube.com/channel/UCW7tPXg-rWdH4YzLrcAdBIw)
- **X (Twitter)**: [@aminfseo](https://x.com/aminfseo)

## Notable Projects:

Amin has created several popular SEO tools including:
- Advanced GSC Visualizer (6.4K+ users)
- SEO Render Insight Tool (3.5K+ users)
- Google AI Overview Impact Analysis (1.2K+ users)
- Google AI Overview Citation Analysis (900+ users)
- SEMRush Enhancer (570+ users)
- SEO Page Inspector (115+ users)

## Expertise:

Amin combines technical SEO knowledge with programming skills to create innovative solutions for SEO challenges.
"""
    return creator_info

@mcp.tool()
async def find_queries_dropped_week_over_week(
    site_url: str,
    country: str = "FRA",
    mode: str = "calendar",  # "calendar" = last Mon-Sun vs current Mon-today; "rolling" = prev 7d vs last 7d
    min_impressions_last_week: int = 10,
    search_type: str = "WEB",
    limit: int = 200,
) -> str:
    """
    Find queries that had impressions last week but zero this week for a given country.
    Auto-paginates to avoid sampling/rowLimit bias.

    Args:
        site_url: GSC property
        country: ISO-3166-1 alpha-3 (e.g., FRA)
        mode: "calendar" (default) compares last completed week (Mon-Sun) with current week (Mon-today);
              "rolling" compares previous 7 days vs last 7 days.
        min_impressions_last_week: Minimum impressions last week to include a query
        search_type: WEB/IMAGE/VIDEO/NEWS/DISCOVER
        limit: Max number of rows in the output
    """
    try:
        service = get_gsc_service()
        site_url = _resolve_site_url(service, site_url)
        country = (country or "FRA").upper()

        today = datetime.now().date()
        if mode.lower() == "rolling":
            this_week_start = today - timedelta(days=6)
            this_week_end = today
            last_week_end = this_week_start - timedelta(days=1)
            last_week_start = last_week_end - timedelta(days=6)
        else:
            # calendar weeks (Mon-Sun)
            iso_weekday = today.isoweekday()  # 1=Mon..7=Sun
            this_week_start = today - timedelta(days=iso_weekday - 1)
            this_week_end = today
            last_week_end = this_week_start - timedelta(days=1)
            last_week_start = last_week_end - timedelta(days=6)

        async def fetch_queries(start_date: str, end_date: str) -> Dict[str, Dict[str, float]]:
            start_row = 0
            all_rows: Dict[str, Dict[str, float]] = {}
            while True:
                body = {
                    "startDate": start_date,
                    "endDate": end_date,
                    "dimensions": ["query"],
                    "rowLimit": 25000,
                    "startRow": start_row,
                    "searchType": search_type.upper(),
                    "dimensionFilterGroups": [
                        {
                            "filters": [
                                {
                                    "dimension": "country",
                                    "operator": "equals",
                                    "expression": country,
                                }
                            ]
                        }
                    ],
                }
                resp = await _execute_with_retries(
                    lambda: service.searchanalytics().query(siteUrl=site_url, body=body).execute()
                )
                rows = resp.get("rows", [])
                if not rows:
                    break
                for r in rows:
                    keys = r.get("keys", [])
                    if not keys:
                        continue
                    q = keys[0]
                    metrics = all_rows.get(q) or {"clicks": 0.0, "impressions": 0.0, "ctr": 0.0, "position": 0.0, "count": 0}
                    # aggregate
                    metrics["clicks"] += float(r.get("clicks", 0.0))
                    metrics["impressions"] += float(r.get("impressions", 0.0))
                    metrics["ctr"] += float(r.get("ctr", 0.0))
                    metrics["position"] += float(r.get("position", 0.0))
                    metrics["count"] += 1
                    all_rows[q] = metrics
                # paginate
                got = len(rows)
                start_row += got
                if got < 25000:
                    break
            # average ctr/position if multiple buckets were returned (usually already aggregated)
            for q, m in all_rows.items():
                c = max(1, int(m.get("count", 1)))
                m["ctr"] = m["ctr"] / c
                m["position"] = m["position"] / c
            return all_rows

        last_start_str = last_week_start.strftime("%Y-%m-%d")
        last_end_str = last_week_end.strftime("%Y-%m-%d")
        this_start_str = this_week_start.strftime("%Y-%m-%d")
        this_end_str = this_week_end.strftime("%Y-%m-%d")

        last_week_data = await fetch_queries(last_start_str, last_end_str)
        this_week_data = await fetch_queries(this_start_str, this_end_str)

        this_week_queries = set(this_week_data.keys())
        dropped = [
            (q, m)
            for q, m in last_week_data.items()
            if m.get("impressions", 0.0) >= float(min_impressions_last_week) and q not in this_week_queries
        ]

        # sort by last week impressions desc
        dropped.sort(key=lambda item: item[1].get("impressions", 0.0), reverse=True)
        if limit and limit > 0:
            dropped = dropped[: int(limit)]

        if not dropped:
            return (
                f"No queries found that meet the criteria for {site_url} in {country}.\n"
                f"Last week: {last_start_str} to {last_end_str}; This week: {this_start_str} to {this_end_str}.\n"
                f"Threshold: impressions >= {min_impressions_last_week}."
            )

        lines = [
            f"Queries with impressions last week but none this week for {site_url} in {country}",
            f"Last week: {last_start_str} to {last_end_str}; This week: {this_start_str} to {this_end_str}",
            f"Search type: {search_type.upper()} | Threshold: impressions >= {min_impressions_last_week}",
            "",
            "Query\tImpr LW\tClicks LW\tCTR LW\tPos LW",
        ]
        for q, m in dropped:
            lines.append(
                "\t".join(
                    [
                        q,
                        f"{m.get('impressions', 0.0):.0f}",
                        f"{m.get('clicks', 0.0):.0f}",
                        f"{float(m.get('ctr', 0.0)) * 100:.2f}%",
                        f"{float(m.get('position', 0.0)):.1f}",
                    ]
                )
            )
        return "\n".join(lines)
    except Exception as e:
        return f"Error computing dropped queries WoW: {str(e)}"

if __name__ == "__main__":
    # Start the MCP server on stdio transport
    mcp.run(transport="stdio")
