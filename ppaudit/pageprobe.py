"""Anonymous reachability probe for the site's published URLs.

The Dataverse audit says which pages *should* be gated (a web page access
control rule bound to a non-anonymous role). This asks the live site the
opposite question, with no credentials: what does an unauthenticated visitor
actually get back? A page that a rule protects but that still renders 200 to an
anonymous GET is the exact gap this whole tool exists to find, so the report
carries the observed answer next to the configured one.

Redirects are followed: Power Pages canonicalises a path with a trailing-slash
301, and gates a protected page by redirecting the anonymous caller to its
Azure AD B2C sign-in URL. The final landing URL is what classifies the result:
land on a login endpoint and the page is gated; a 200 anywhere else is open.
"""

from __future__ import annotations

import concurrent.futures
from typing import NamedTuple

import requests

from .constants import DEFAULT_USER_AGENT

# Substrings that mark the final URL as a sign-in / authorisation endpoint.
_LOGIN_MARKERS = ("/signin", "/login", "/authorize", "b2clogin",
                  "account/login", "/external-login")

# verdict -> the pill style the report uses for it.
OPEN = "open"            # 200 to an anonymous caller — reachable with no sign-in
GATED = "gated"          # redirected to sign-in, or 401/403 — protected
NOT_FOUND = "not found"  # 404 — no such page (a detached orphan lands here)
ERROR = "error"          # network failure or 5xx — inconclusive


class ProbeResult(NamedTuple):
    url: str
    status: int | None
    verdict: str
    final_path: str      # where the request landed, site-relative


def classify(status: int, final_url: str, base: str) -> str:
    """Turn a followed response into a verdict."""
    low = (final_url or "").lower()
    if any(marker in low for marker in _LOGIN_MARKERS):
        return GATED
    if status in (401, 403):
        return GATED
    if status == 404:
        return NOT_FOUND
    if status and 200 <= status < 400:
        return OPEN
    return ERROR


# --- data-endpoint (OData / Web API) classification --------------------------

# Endpoints answer with JSON/XML, not redirects, so status alone is not enough:
# a 200 can carry an error body, and a 404 can mean "surface disabled" rather
# than "no such table". These verdicts describe what the body actually says.
UNAVAILABLE = "unavailable"      # the OData/Web API surface is switched off here
DENIED = "denied"               # the surface answered, but read is not permitted
LEAK = "leak"                   # rows came back to an anonymous caller
EMPTY = "reachable (no rows)"   # answered, permitted, but returned nothing now


class EndpointResult(NamedTuple):
    url: str
    status: int | None
    verdict: str
    note: str


def classify_endpoint(status: int | None, body: str) -> tuple[str, str]:
    """Verdict + short note for a data-endpoint response body."""
    text = (body or "")[:600]
    low = text.lower()
    if "odata entityset api is not available" in low:
        return UNAVAILABLE, "OData EntitySet API is disabled for this site"
    if "don't have permission" in low or "do not have permission" in low \
            or '"90040120"' in text or status == 403:
        return DENIED, "read not permitted for an anonymous caller"
    if status == 404:
        return NOT_FOUND, "no such entity set"
    if status == 200:
        # A Web API/OData collection returns {"value":[...]}; rows means a leak.
        if '"value":[]' in text.replace(" ", "") or '"value": []' in text:
            return EMPTY, "answered anonymously but returned no rows"
        if '"value"' in text or "<feed" in low or "<entry" in low:
            return LEAK, "rows returned to an anonymous caller"
        return EMPTY, "answered anonymously"
    if status and 500 <= status < 600:
        return ERROR, f"server error {status}"
    return ERROR, f"unexpected response ({status})"


def probe_endpoints(urls, *, threads: int = 12, timeout: float = 15.0) -> dict[str, EndpointResult]:
    """GET each data-endpoint URL anonymously and read its body to classify it."""
    unique = [u for u in dict.fromkeys(urls) if u and u.startswith("http")]
    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    def one(url: str) -> EndpointResult:
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True)
            verdict, note = classify_endpoint(r.status_code, r.text)
            return EndpointResult(url, r.status_code, verdict, note)
        except requests.RequestException as exc:
            return EndpointResult(url, None, ERROR, str(exc)[:60])

    results: dict[str, EndpointResult] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        for res in pool.map(one, unique):
            results[res.url] = res
    return results


def probe_urls(urls, *, threads: int = 12, timeout: float = 15.0) -> dict[str, ProbeResult]:
    """GET every URL anonymously and classify what comes back.

    One request per distinct URL; a shared session reuses connections. Failures
    are captured as ``ERROR`` rather than raised, so one dead URL never aborts
    the sweep.
    """
    unique = [u for u in dict.fromkeys(urls) if u and u.startswith("http")]
    session = requests.Session()
    session.headers.update({"User-Agent": DEFAULT_USER_AGENT})

    def base_of(u: str) -> str:
        parts = u.split("/", 3)
        return "/".join(parts[:3]) if len(parts) >= 3 else u

    def one(url: str) -> ProbeResult:
        try:
            r = session.get(url, timeout=timeout, allow_redirects=True)
            final = r.url
            base = base_of(final)
            verdict = classify(r.status_code, final, base)
            path = final[len(base):] or "/" if final.startswith(base) else final
            return ProbeResult(url, r.status_code, verdict, path)
        except requests.RequestException as exc:
            return ProbeResult(url, None, ERROR, str(exc)[:60])

    results: dict[str, ProbeResult] = {}
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, threads)) as pool:
        for res in pool.map(one, unique):
            results[res.url] = res
    return results
