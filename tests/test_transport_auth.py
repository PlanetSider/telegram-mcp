"""Tests for optional HTTP Basic / Bearer authentication on the HTTP transport."""

import base64

import pytest
from starlette.applications import Starlette
from starlette.responses import PlainTextResponse
from starlette.routing import Route
from starlette.testclient import TestClient

from telegram_mcp.transport.auth import (
    AUTH_PASSWORD_ENV,
    AUTH_TOKEN_ENV,
    AUTH_USER_ENV,
    HttpAuthConfig,
    HttpAuthMiddleware,
    wrap_with_auth,
)


async def _ok(request):
    return PlainTextResponse("ok")


def _app() -> Starlette:
    return Starlette(
        routes=[
            Route("/mcp", _ok, methods=["GET", "POST", "OPTIONS"]),
            Route("/media/{rest:path}", _ok, methods=["GET"]),
            Route("/upload/{rest:path}", _ok, methods=["GET", "POST"]),
        ]
    )


def _client(config: HttpAuthConfig) -> TestClient:
    return TestClient(HttpAuthMiddleware(_app(), config))


def _basic_header(credentials: str) -> dict:
    encoded = base64.b64encode(credentials.encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {encoded}"}


def _basic_config() -> HttpAuthConfig:
    return HttpAuthConfig(basic_user="alice", basic_password="s3cret")


def _bearer_config() -> HttpAuthConfig:
    return HttpAuthConfig(bearer_token="token-123")


def test_from_env_returns_none_without_credentials():
    assert HttpAuthConfig.from_env({}) is None
    assert HttpAuthConfig.from_env({AUTH_USER_ENV: "", AUTH_TOKEN_ENV: "  "}) is None


def test_from_env_reads_basic_pair():
    config = HttpAuthConfig.from_env({AUTH_USER_ENV: " alice ", AUTH_PASSWORD_ENV: "s3cret"})
    assert config is not None
    assert config.basic_enabled is True
    assert config.bearer_enabled is False
    assert config.schemes() == ("basic",)


def test_from_env_reads_bearer_token():
    config = HttpAuthConfig.from_env({AUTH_TOKEN_ENV: " token-123 "})
    assert config is not None
    assert config.bearer_enabled is True
    assert config.basic_enabled is False
    assert config.schemes() == ("bearer",)


def test_from_env_keeps_password_whitespace():
    config = HttpAuthConfig.from_env({AUTH_USER_ENV: "alice", AUTH_PASSWORD_ENV: " pass word "})
    assert config is not None
    assert config.basic_password == " pass word "


def test_from_env_rejects_half_configured_basic():
    with pytest.raises(ValueError, match="must be set together"):
        HttpAuthConfig.from_env({AUTH_USER_ENV: "alice"})
    with pytest.raises(ValueError, match="must be set together"):
        HttpAuthConfig.from_env({AUTH_PASSWORD_ENV: "s3cret"})


def test_wrap_with_auth_is_noop_without_credentials():
    app = _app()
    assert wrap_with_auth(app, {}) is app


def test_missing_credentials_rejected():
    response = _client(_basic_config()).get("/mcp")
    assert response.status_code == 401
    assert response.json()["error"] == "unauthorized"


def test_basic_credentials_accepted():
    response = _client(_basic_config()).get("/mcp", headers=_basic_header("alice:s3cret"))
    assert response.status_code == 200
    assert response.text == "ok"


def test_basic_wrong_password_rejected():
    response = _client(_basic_config()).get("/mcp", headers=_basic_header("alice:wrong"))
    assert response.status_code == 401


def test_basic_wrong_user_rejected():
    response = _client(_basic_config()).get("/mcp", headers=_basic_header("bob:s3cret"))
    assert response.status_code == 401


def test_basic_malformed_header_rejected():
    client = _client(_basic_config())
    assert client.get("/mcp", headers={"Authorization": "Basic !!!not-base64"}).status_code == 401
    assert client.get("/mcp", headers={"Authorization": "Basic"}).status_code == 401
    assert client.get("/mcp", headers={"Authorization": "Bearer anything"}).status_code == 401


def test_basic_without_colon_rejected():
    response = _client(_basic_config()).get("/mcp", headers=_basic_header("alices3cret"))
    assert response.status_code == 401


def test_basic_non_ascii_password_accepted():
    config = HttpAuthConfig(basic_user="alice", basic_password="pässwörd")
    response = _client(config).get("/mcp", headers=_basic_header("alice:pässwörd"))
    assert response.status_code == 200


def test_bearer_token_accepted():
    response = _client(_bearer_config()).get("/mcp", headers={"Authorization": "Bearer token-123"})
    assert response.status_code == 200


def test_bearer_wrong_token_rejected():
    response = _client(_bearer_config()).get("/mcp", headers={"Authorization": "Bearer nope"})
    assert response.status_code == 401


def test_either_scheme_works_when_both_enabled():
    config = HttpAuthConfig(basic_user="alice", basic_password="s3cret", bearer_token="token-123")
    client = _client(config)
    assert client.get("/mcp", headers=_basic_header("alice:s3cret")).status_code == 200
    assert client.get("/mcp", headers={"Authorization": "Bearer token-123"}).status_code == 200
    assert client.get("/mcp").status_code == 401


def test_www_authenticate_lists_enabled_schemes():
    config = HttpAuthConfig(basic_user="alice", basic_password="s3cret", bearer_token="token-123")
    challenge = _client(config).get("/mcp").headers["www-authenticate"].lower()
    assert "basic realm=" in challenge
    assert "bearer realm=" in challenge


def test_options_preflight_skips_authentication():
    response = _client(_basic_config()).options("/mcp", headers={"Origin": "http://localhost"})
    assert response.status_code in (200, 204, 405)
    assert response.status_code != 401


def test_signed_media_routes_skip_authentication():
    client = _client(_basic_config())
    assert client.get("/media/file.bin?expires=1&sig=abc").status_code == 200
    assert client.get("/upload/file.bin?expires=1&sig=abc").status_code == 200
