"""OAuth 2.1 authorization server that lets claude.ai connect to the MCP endpoint.

Custom connectors there cannot send a fixed bearer token: they discover an
authorization server, register themselves and run the authorization code flow
with PKCE. FastMCP provides the protocol endpoints; this module adds the part
that decides who gets in.

There is a single resource owner. Approving a client means choosing on the
consent page whether it may only read or also manage the server, and typing the
admin token. The admin token is also accepted directly as a bearer token.
"""

import asyncio
import hashlib
import hmac
import html
import ipaddress
import json
import os
import secrets
import time
from pathlib import Path
from urllib.parse import urlparse

from fastmcp.server.auth.auth import (
    AccessToken,
    ClientRegistrationOptions,
    OAuthProvider,
    RevocationOptions,
)
from mcp.server.auth.provider import (
    AuthorizationCode,
    AuthorizationParams,
    RefreshToken,
    RegistrationError,
    TokenError,
    construct_redirect_uri,
)
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, RedirectResponse, Response

from discord_mcp.utils.logging import get_logger

logger = get_logger(__name__)

SCOPE_READ = "discord:read"
SCOPE_WRITE = "discord:write"
LEVEL_SCOPES = {
    "read": [SCOPE_READ],
    "write": [SCOPE_READ, SCOPE_WRITE],
}

ADMIN_CLIENT_ID = "admin"
MIN_ADMIN_TOKEN_LENGTH = 32

CONSENT_PATH = "/consent"
CONSENT_LIFETIME = 10 * 60
CODE_LIFETIME = 5 * 60
ACCESS_TOKEN_LIFETIME = 60 * 60
# MAX_CLIENTS bounds what unauthenticated registration can make us store.
MAX_CLIENTS = 100
MAX_REDIRECT_URIS = 5
MAX_PENDING = 1000

# Callbacks codes may be sent to, besides loopback addresses (used by local
# clients such as Claude Code).
ALLOWED_REDIRECT_URIS = (
    "https://claude.ai/api/mcp/auth_callback",
    "https://claude.com/api/mcp/auth_callback",
)


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def redirect_uri_allowed(uri: str) -> bool:
    if uri in ALLOWED_REDIRECT_URIS:
        return True
    parsed = urlparse(uri)
    if parsed.scheme != "http" or not parsed.hostname:
        return False
    if parsed.hostname == "localhost":
        return True
    try:
        return ipaddress.ip_address(parsed.hostname).is_loopback
    except ValueError:
        return False


class _Client(OAuthClientInformationFull):
    """A registered client. What it may do is chosen on the consent page, so
    the scopes it asks for are ignored instead of being rejected."""

    def validate_scope(self, requested_scope: str | None) -> list[str] | None:
        return None


CONSENT_PAGE = """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Authorize access to Discord</title>
<style>
body {{ font-family: system-ui, sans-serif; max-width: 26rem; margin: 4rem auto; padding: 0 1rem; line-height: 1.5; }}
input {{ box-sizing: border-box; width: 100%; padding: .6rem; margin: .5rem 0 1rem; font-size: 1rem; }}
input[type=radio] {{ width: auto; margin: 0 .5rem 0 0; }}
fieldset {{ border: 1px solid #8884; margin: 0 0 1.5rem; padding: .5rem 1rem; }}
fieldset label {{ display: block; margin: .4rem 0; }}
button {{ padding: .6rem 1.2rem; font-size: 1rem; }}
.error {{ color: #b00020; }}
code {{ word-break: break-all; }}
</style>
</head>
<body>
<h1>Allow access to Discord?</h1>
<p><strong>{client_name}</strong> wants to use the Discord bot behind this server.</p>
<p>After approval you are sent back to <code>{redirect_host}</code>.</p>
{error}
<form method="post" action="consent">
<input type="hidden" name="txn" value="{txn}">
<fieldset>
<legend>What it may do</legend>
<label><input type="radio" name="level" value="read"{read_checked}>Read only: look at channels, roles, members and messages</label>
<label><input type="radio" name="level" value="write"{write_checked}>Read &amp; manage: also send messages, change settings and moderate</label>
</fieldset>
<label for="admin_token">Server admin token (MCP_ADMIN_TOKEN)</label>
<input type="password" id="admin_token" name="admin_token" autocomplete="off" required autofocus>
<button type="submit">Allow</button>
</form>
</body>
</html>
"""


class ConsentOAuthProvider(OAuthProvider):
    """OAuth provider with a consent page guarded by the server's admin token.

    Registered clients and hashed tokens are kept in ``oauth.json`` in the data
    directory, so connections survive restarts.
    """

    # Makes guessing the admin token on the consent page slow.
    failed_login_delay = 2.0

    def __init__(self, *, public_url: str, admin_token: str, data_dir: str | Path):
        parsed = urlparse(public_url)
        if parsed.scheme not in ("http", "https") or not parsed.netloc:
            raise ValueError(
                f"invalid public URL {public_url!r}, expected something like https://mcp.example.com"
            )
        if len(admin_token) < MIN_ADMIN_TOKEN_LENGTH:
            raise ValueError(
                f"the admin token must be at least {MIN_ADMIN_TOKEN_LENGTH} characters, "
                "generate one with: openssl rand -hex 32"
            )
        super().__init__(
            base_url=public_url.rstrip("/"),
            client_registration_options=ClientRegistrationOptions(enabled=True),
            revocation_options=RevocationOptions(enabled=True),
        )
        self._public_url = public_url.rstrip("/")
        self._admin_hash = hashlib.sha256(admin_token.encode()).digest()
        self._path = Path(data_dir) / "oauth.json"
        self._path.parent.mkdir(parents=True, exist_ok=True)

        self._clients: dict[str, dict] = {}
        # Both keyed by the SHA-256 of the token.
        self._access: dict[str, dict] = {}
        self._refresh: dict[str, dict] = {}
        if self._path.exists():
            state = json.loads(self._path.read_text())
            self._clients = state.get("clients", {})
            self._access = state.get("access_tokens", {})
            self._refresh = state.get("refresh_tokens", {})

        # Authorization requests waiting on the consent page, and codes waiting
        # to be exchanged. Neither needs to survive a restart.
        self._pending: dict[str, dict] = {}
        self._codes: dict[str, AuthorizationCode] = {}
        # Serializes failed consent attempts.
        self._login_lock = asyncio.Lock()

    def _save(self) -> None:
        now = time.time()
        self._access = {h: g for h, g in self._access.items() if g["expires_at"] > now}
        state = {
            "clients": self._clients,
            "access_tokens": self._access,
            "refresh_tokens": self._refresh,
        }
        tmp = self._path.with_suffix(".json.tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, self._path)

    def _is_admin_token(self, token: str) -> bool:
        return hmac.compare_digest(hashlib.sha256(token.encode()).digest(), self._admin_hash)

    # ── Clients ────────────────────────────────────────────────────────────

    async def get_client(self, client_id: str) -> OAuthClientInformationFull | None:
        data = self._clients.get(client_id)
        return _Client.model_validate(data) if data else None

    async def register_client(self, client_info: OAuthClientInformationFull) -> None:
        """Dynamic client registration (RFC 7591). It is open to anyone: a
        registered client is worthless until the owner approves it."""
        uris = [str(uri) for uri in client_info.redirect_uris or []]
        if not uris or len(uris) > MAX_REDIRECT_URIS:
            raise RegistrationError(
                "invalid_redirect_uri",
                f"between 1 and {MAX_REDIRECT_URIS} redirect_uris are required",
            )
        for uri in uris:
            if not redirect_uri_allowed(uri):
                raise RegistrationError(
                    "invalid_redirect_uri", f"{uri} is not an allowed redirect URI"
                )
        if client_info.client_name and len(client_info.client_name) > 100:
            client_info.client_name = client_info.client_name[:100]
        if len(self._clients) >= MAX_CLIENTS and not self._evict_unused_client():
            raise RegistrationError("invalid_client_metadata", "too many registered clients")
        self._clients[client_info.client_id] = client_info.model_dump(
            mode="json", exclude_none=True
        )
        self._save()

    def _evict_unused_client(self) -> bool:
        """Drops the oldest client that was never approved, so that junk
        registrations cannot lock out real ones."""
        in_use = {g["client_id"] for g in self._refresh.values()}
        unused = [cid for cid in self._clients if cid not in in_use]
        if not unused:
            return False
        oldest = min(unused, key=lambda cid: self._clients[cid].get("client_id_issued_at", 0))
        del self._clients[oldest]
        return True

    # ── Authorization ──────────────────────────────────────────────────────

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        """Parks the request and sends the browser to the consent page."""
        now = time.time()
        self._pending = {t: p for t, p in self._pending.items() if p["expires_at"] > now}
        while len(self._pending) >= MAX_PENDING:
            del self._pending[next(iter(self._pending))]
        txn = secrets.token_urlsafe(32)
        self._pending[txn] = {
            "client_id": client.client_id,
            "client_name": client.client_name,
            "params": params,
            "expires_at": now + CONSENT_LIFETIME,
        }
        return f"{self._public_url}{CONSENT_PATH}?txn={txn}"

    async def consent_endpoint(self, request: Request) -> Response:
        """Serves the consent page and, once the admin token checks out, sends
        the browser back to the client with an authorization code."""
        form = await request.form() if request.method == "POST" else {}
        txn = str(form.get("txn") or request.query_params.get("txn") or "")
        pending = self._pending.get(txn)
        if pending is None or pending["expires_at"] < time.time():
            self._pending.pop(txn, None)
            return HTMLResponse(
                "This authorization request has expired. Start connecting again from the application.",
                status_code=400,
            )
        params: AuthorizationParams = pending["params"]
        level = str(form.get("level") or "read")
        if level not in LEVEL_SCOPES:
            level = "read"

        def render(status: int, error: str = "") -> Response:
            page = CONSENT_PAGE.format(
                client_name=html.escape(pending["client_name"] or "An application"),
                redirect_host=html.escape(urlparse(str(params.redirect_uri)).netloc),
                error=f'<p class="error">{html.escape(error)}</p>' if error else "",
                txn=html.escape(txn),
                read_checked=" checked" if level == "read" else "",
                write_checked=" checked" if level == "write" else "",
            )
            return HTMLResponse(
                page,
                status_code=status,
                headers={
                    "Cache-Control": "no-store",
                    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
                    "Referrer-Policy": "no-referrer",
                },
            )

        if request.method != "POST":
            return render(200)

        if not self._is_admin_token(str(form.get("admin_token") or "").strip()):
            async with self._login_lock:
                await asyncio.sleep(self.failed_login_delay)
            logger.warning("oauth_consent_rejected", client_id=pending["client_id"])
            return render(403, "That is not the admin token.")

        del self._pending[txn]
        now = time.time()
        self._codes = {c: a for c, a in self._codes.items() if a.expires_at > now}
        code = secrets.token_urlsafe(32)
        self._codes[code] = AuthorizationCode(
            code=code,
            client_id=pending["client_id"],
            scopes=LEVEL_SCOPES[level],
            expires_at=now + CODE_LIFETIME,
            code_challenge=params.code_challenge,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            resource=params.resource,
        )
        logger.info("oauth_client_approved", client_id=pending["client_id"], level=level)
        return RedirectResponse(
            construct_redirect_uri(str(params.redirect_uri), code=code, state=params.state),
            status_code=302,
            headers={"Cache-Control": "no-store"},
        )

    async def load_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: str
    ) -> AuthorizationCode | None:
        code = self._codes.get(authorization_code)
        if code is None or code.client_id != client.client_id:
            return None
        if code.expires_at < time.time():
            del self._codes[authorization_code]
            return None
        return code

    # ── Tokens ─────────────────────────────────────────────────────────────

    def _issue(self, client_id: str, scopes: list[str]) -> OAuthToken:
        access_token, refresh_token = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
        self._access[_hash_token(access_token)] = {
            "client_id": client_id,
            "scopes": scopes,
            "expires_at": int(time.time()) + ACCESS_TOKEN_LIFETIME,
        }
        # Refresh tokens live until used or replaced.
        self._refresh[_hash_token(refresh_token)] = {"client_id": client_id, "scopes": scopes}
        self._save()
        return OAuthToken(
            access_token=access_token,
            token_type="Bearer",
            expires_in=ACCESS_TOKEN_LIFETIME,
            refresh_token=refresh_token,
            scope=" ".join(scopes),
        )

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        # A code works once.
        if self._codes.pop(authorization_code.code, None) is None:
            raise TokenError("invalid_grant", "authorization code is invalid or already used")
        return self._issue(authorization_code.client_id, authorization_code.scopes)

    async def load_refresh_token(
        self, client: OAuthClientInformationFull, refresh_token: str
    ) -> RefreshToken | None:
        grant = self._refresh.get(_hash_token(refresh_token))
        if grant is None or grant["client_id"] != client.client_id:
            return None
        return RefreshToken(
            token=refresh_token, client_id=grant["client_id"], scopes=grant["scopes"]
        )

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        # Refresh tokens rotate: the one just used is replaced, with the
        # permissions chosen at approval whatever the request asks for.
        if self._refresh.pop(_hash_token(refresh_token.token), None) is None:
            raise TokenError("invalid_grant", "refresh token is invalid")
        return self._issue(refresh_token.client_id, refresh_token.scopes)

    async def load_access_token(self, token: str) -> AccessToken | None:
        if self._is_admin_token(token):
            return AccessToken(
                token=token, client_id=ADMIN_CLIENT_ID, scopes=LEVEL_SCOPES["write"]
            )
        grant = self._access.get(_hash_token(token))
        if grant is None or grant["expires_at"] < time.time():
            return None
        return AccessToken(
            token=token,
            client_id=grant["client_id"],
            scopes=grant["scopes"],
            expires_at=grant["expires_at"],
        )

    async def revoke_token(self, token: AccessToken | RefreshToken) -> None:
        """Disconnects the client: all of its tokens stop working."""
        if token.client_id == ADMIN_CLIENT_ID:
            return
        self._access = {h: g for h, g in self._access.items() if g["client_id"] != token.client_id}
        self._refresh = {
            h: g for h, g in self._refresh.items() if g["client_id"] != token.client_id
        }
        self._save()
