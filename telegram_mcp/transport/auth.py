"""Optional HTTP authentication for the streamable HTTP transport.

Credentials come from the environment, so a deployment that sets nothing keeps
the historical unauthenticated behaviour and no configuration file has to
change. Two independent schemes are supported:

* HTTP Basic -- ``MCP_AUTH_USER`` plus ``MCP_AUTH_PASSWORD``
* Bearer token -- ``MCP_AUTH_TOKEN``

Both may be enabled at once; either one is enough to get in, which lets a
browser (Basic) and a header-only client (Bearer) share one server.

The middleware guards the MCP endpoint only. CORS preflights carry no
credentials, and the signed media/upload routes authenticate themselves with an
HMAC in the URL, so a browser that opens such a link is not asked for a password
it cannot supply.
"""

from __future__ import annotations

import base64
import binascii
import hmac
import logging
import os
from typing import Mapping, Optional

from starlette.responses import JSONResponse
from starlette.types import ASGIApp, Receive, Scope, Send

from telegram_mcp.media_links import MEDIA_ROUTE_PREFIX, UPLOAD_ROUTE_PREFIX

logger = logging.getLogger(__name__)

AUTH_USER_ENV = "MCP_AUTH_USER"
AUTH_PASSWORD_ENV = "MCP_AUTH_PASSWORD"
AUTH_TOKEN_ENV = "MCP_AUTH_TOKEN"

REALM = "telegram-mcp"

_UNAUTHORIZED_BODY = {
    "error": "unauthorized",
    "message": "Valid credentials are required to use this MCP endpoint.",
}


class HttpAuthConfig:
    """Credentials that guard the HTTP transport."""

    def __init__(
        self,
        basic_user: Optional[str] = None,
        basic_password: Optional[str] = None,
        bearer_token: Optional[str] = None,
    ) -> None:
        self.basic_user = basic_user
        self.basic_password = basic_password
        self.bearer_token = bearer_token

    @property
    def basic_enabled(self) -> bool:
        return bool(self.basic_user and self.basic_password)

    @property
    def bearer_enabled(self) -> bool:
        return bool(self.bearer_token)

    @property
    def enabled(self) -> bool:
        return self.basic_enabled or self.bearer_enabled

    def schemes(self) -> tuple[str, ...]:
        """Return the enabled scheme names in challenge order."""
        schemes = []
        if self.basic_enabled:
            schemes.append("basic")
        if self.bearer_enabled:
            schemes.append("bearer")
        return tuple(schemes)

    @classmethod
    def from_env(cls, environ: Optional[Mapping[str, str]] = None) -> Optional["HttpAuthConfig"]:
        """Build the config from ``environ``, or None when nothing is configured."""
        env = os.environ if environ is None else environ
        user = (env.get(AUTH_USER_ENV) or "").strip()
        password = env.get(AUTH_PASSWORD_ENV) or ""
        token = (env.get(AUTH_TOKEN_ENV) or "").strip()

        if bool(user) != bool(password):
            raise ValueError(
                f"{AUTH_USER_ENV} and {AUTH_PASSWORD_ENV} must be set together; "
                "a half-configured Basic pair would silently disable authentication."
            )
        if not user and not token:
            return None
        return cls(
            basic_user=user or None,
            basic_password=password or None,
            bearer_token=token or None,
        )


class HttpAuthMiddleware:
    """ASGI middleware that rejects requests without valid HTTP credentials."""

    def __init__(self, app: ASGIApp, config: HttpAuthConfig) -> None:
        self.app = app
        self.config = config

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        path = scope.get("path", "")
        if scope.get("method") == "OPTIONS" or path.startswith(
            (MEDIA_ROUTE_PREFIX, UPLOAD_ROUTE_PREFIX)
        ):
            await self.app(scope, receive, send)
            return

        headers = {key.lower(): value for key, value in scope.get("headers", [])}
        authorization = headers.get(b"authorization", b"").decode("latin-1").strip()
        scheme, _, credentials = authorization.partition(" ")
        scheme = scheme.lower()
        credentials = credentials.strip()

        if credentials and (
            (scheme == "basic" and self._accepts_basic(credentials))
            or (scheme == "bearer" and self._accepts_bearer(credentials))
        ):
            await self.app(scope, receive, send)
            return

        client = scope.get("client")
        logger.warning(
            "Rejected unauthenticated %s %s from %s",
            scope.get("method"),
            path,
            client[0] if client else "unknown",
        )
        await self._send_unauthorized(scope, receive, send)

    def _accepts_basic(self, credentials: str) -> bool:
        if not self.config.basic_enabled:
            return False
        try:
            decoded = base64.b64decode(credentials.encode("latin-1"), validate=True)
            text = decoded.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            return False
        user, separator, password = text.partition(":")
        if not separator:
            return False
        expected_user = (self.config.basic_user or "").encode()
        expected_password = (self.config.basic_password or "").encode()
        return hmac.compare_digest(user.encode(), expected_user) and hmac.compare_digest(
            password.encode(), expected_password
        )

    def _accepts_bearer(self, credentials: str) -> bool:
        if not self.config.bearer_enabled:
            return False
        expected = (self.config.bearer_token or "").encode()
        return hmac.compare_digest(credentials.encode(), expected)

    async def _send_unauthorized(self, scope: Scope, receive: Receive, send: Send) -> None:
        response = JSONResponse(_UNAUTHORIZED_BODY, status_code=401)
        if self.config.basic_enabled:
            response.headers.append("www-authenticate", f'Basic realm="{REALM}"')
        if self.config.bearer_enabled:
            response.headers.append("www-authenticate", f'Bearer realm="{REALM}"')
        await response(scope, receive, send)


def wrap_with_auth(app: ASGIApp, environ: Optional[Mapping[str, str]] = None) -> ASGIApp:
    """Wrap ``app`` with HTTP authentication when credentials are configured."""
    config = HttpAuthConfig.from_env(environ)
    if config is None:
        return app
    logger.info("HTTP authentication enabled (%s)", ", ".join(config.schemes()))
    return HttpAuthMiddleware(app, config)
