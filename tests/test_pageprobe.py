"""Anonymous reachability probe: verdict classification."""

from __future__ import annotations

from ppaudit import pageprobe as pp


def test_open_page_returns_200_at_its_own_url():
    assert pp.classify(200, "https://site/about-us/", "https://site") == pp.OPEN


def test_redirect_to_sign_in_is_gated():
    # Power Pages sends an unauthenticated visitor to a B2C login URL.
    assert pp.classify(200, "https://login.site/login?state=abc", "https://site") == pp.GATED
    assert pp.classify(200, "https://site/SignIn?returnUrl=x", "https://site") == pp.GATED


def test_forbidden_is_gated_and_missing_is_not_found():
    assert pp.classify(403, "https://site/secret/", "https://site") == pp.GATED
    assert pp.classify(404, "https://site/_dev/gone/", "https://site") == pp.NOT_FOUND


def test_server_error_is_inconclusive():
    assert pp.classify(500, "https://site/x/", "https://site") == pp.ERROR


def test_endpoint_odata_disabled_is_unavailable():
    v, note = pp.classify_endpoint(404, '{"Message":"OData EntitySet API is not available."}')
    assert v == pp.UNAVAILABLE


def test_endpoint_permission_denied_is_denied():
    v, _ = pp.classify_endpoint(403, '{"error":{"code":"90040120","message":"You don\'t have permission to read the contact table."}}')
    assert v == pp.DENIED


def test_endpoint_rows_returned_is_a_leak_and_empty_is_reachable():
    leak, _ = pp.classify_endpoint(200, '{"value":[{"contactid":"x"}]}')
    empty, _ = pp.classify_endpoint(200, '{"value":[]}')
    assert leak == pp.LEAK and empty == pp.EMPTY
