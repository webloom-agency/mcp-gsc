"""Google Search Console OAuth scopes."""

SCOPES = ["https://www.googleapis.com/auth/webmasters"]


def get_current_scopes():
    """Return the scopes required for Google Search Console API access."""
    return SCOPES
