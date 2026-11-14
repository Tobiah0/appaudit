"""The local API must refuse other origins and unauthenticated changes."""

from appaudit import api

HOST = {"host": "127.0.0.1:8756"}


def test_normal_read_is_allowed():
    assert api.refusal("GET", HOST) is None
    assert api.refusal("GET", {"host": "localhost:8756", "sec-fetch-site": "same-origin"}) is None


def test_dns_rebinding_host_is_refused():
    assert api.refusal("GET", {"host": "evil.example:8756"}) == "unexpected Host header"
    assert api.refusal("GET", {}) == "unexpected Host header"


def test_cross_site_request_is_refused():
    assert api.refusal("GET", {**HOST, "sec-fetch-site": "cross-site"}) == "cross-site requests are refused"


def test_change_needs_the_session_token():
    assert api.refusal("POST", HOST) == "missing or wrong session token"
    assert api.refusal("POST", {**HOST, "x-appaudit-token": "guess"}) == "missing or wrong session token"
    assert api.refusal("POST", {**HOST, "x-appaudit-token": api.TOKEN}) is None


def test_every_changing_route_is_a_post():
    changing = [route for route in api.app.routes if getattr(route, "methods", None)
                and any(word in route.path for word in ("apply", "undo", "blocks", "helper", "scan", "refresh"))]
    assert changing
    for route in changing:
        if route.path == "/api/blocks" and "GET" in route.methods:
            continue
        assert route.methods <= {"POST"}, route.path
