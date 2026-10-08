import asyncio
import base64
import hashlib
import json
import secrets
from types import SimpleNamespace
from urllib.parse import parse_qs, urlparse

import pytest
from conftest import ADMIN_TOKEN, PUBLIC_URL
from starlette.testclient import TestClient

import discord_mcp.main  # noqa: F401  (registers the tools)
from discord_mcp.discord.session import session_manager
from discord_mcp.mcp.oauth import ConsentOAuthProvider, redirect_uri_allowed
from discord_mcp.mcp.server import is_read_tool, mcp, oauth_provider

REDIRECT_URI = "https://claude.ai/api/mcp/auth_callback"


@pytest.fixture
def client(monkeypatch):
    guild = SimpleNamespace(id=1, name="OpenDock", member_count=3)
    session = SimpleNamespace(session_id="s", client=SimpleNamespace(guilds=[guild]))

    async def get_session_by_token(token):
        return session

    async def get_session(session_id):
        return session

    monkeypatch.setattr(session_manager, "get_session_by_token", get_session_by_token)
    monkeypatch.setattr(session_manager, "get_session", get_session)
    monkeypatch.setattr(oauth_provider, "failed_login_delay", 0)
    app = mcp.http_app(json_response=True, stateless_http=True)
    with TestClient(app, base_url=PUBLIC_URL, follow_redirects=False) as c:
        yield c


def register(client, redirect_uri=REDIRECT_URI):
    return client.post(
        "/register",
        json={
            "client_name": "Claude",
            "redirect_uris": [redirect_uri],
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        },
    )


def connect(client, level, admin_token=ADMIN_TOKEN):
    """Runs the whole flow and returns the token response."""
    client_id = register(client).json()["client_id"]
    verifier = secrets.token_urlsafe(48)
    challenge = (
        base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    )
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "state": "xyz",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "scope": "claudeai",
        },
    )
    assert response.status_code == 302, response.text
    consent = urlparse(response.headers["location"])
    assert consent.path == "/consent"
    txn = parse_qs(consent.query)["txn"][0]

    page = client.get("/consent", params={"txn": txn})
    assert page.status_code == 200 and "Claude" in page.text and "claude.ai" in page.text

    response = client.post("/consent", data={"txn": txn, "level": level, "admin_token": admin_token})
    if response.status_code != 302:
        return response
    callback = urlparse(response.headers["location"])
    assert response.headers["location"].startswith(REDIRECT_URI)
    query = parse_qs(callback.query)
    assert query["state"] == ["xyz"]
    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": query["code"][0],
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": verifier,
        },
    )
    assert response.status_code == 200, response.text
    return SimpleNamespace(client_id=client_id, code=query["code"][0], verifier=verifier, **response.json())


def rpc(client, token, method, params=None):
    headers = {"Accept": "application/json, text/event-stream"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    return client.post("/mcp", json=body, headers=headers)


def call(client, token, name, arguments=None):
    response = rpc(client, token, "tools/call", {"name": name, "arguments": arguments or {}})
    assert response.status_code == 200, response.text
    return response.json()["result"]


def tool_names(client, token):
    return {tool["name"] for tool in rpc(client, token, "tools/list").json()["result"]["tools"]}


def test_discovery(client):
    response = rpc(client, None, "tools/list")
    assert response.status_code == 401
    assert "/.well-known/oauth-protected-resource" in response.headers["www-authenticate"]

    resource = client.get("/.well-known/oauth-protected-resource/mcp").json()
    assert resource["resource"] == f"{PUBLIC_URL}/mcp"
    assert resource["authorization_servers"][0].rstrip("/") == PUBLIC_URL

    server = client.get("/.well-known/oauth-authorization-server").json()
    assert server["authorization_endpoint"] == f"{PUBLIC_URL}/authorize"
    assert server["token_endpoint"] == f"{PUBLIC_URL}/token"
    assert server["registration_endpoint"] == f"{PUBLIC_URL}/register"
    assert "S256" in server["code_challenge_methods_supported"]


def test_registration_only_accepts_known_callbacks(client):
    assert register(client).status_code == 201
    assert register(client, "http://localhost:53124/callback").status_code == 201
    assert register(client, "http://127.0.0.1:9/cb").status_code == 201
    response = register(client, "https://evil.example/callback")
    assert response.status_code == 400
    assert response.json()["error"] == "invalid_redirect_uri"
    assert not redirect_uri_allowed("https://claude.ai.evil.example/api/mcp/auth_callback")
    assert not redirect_uri_allowed("http://localhost.evil.example/cb")


def test_wrong_admin_token_is_rejected(client):
    response = connect(client, "write", admin_token="not the token")
    assert response.status_code == 403
    assert "not the admin token" in response.text


def test_garbage_bearer_token_is_rejected(client):
    assert rpc(client, "nope", "tools/list").status_code == 401


def test_admin_token_works_as_bearer(client):
    names = tool_names(client, ADMIN_TOKEN)
    assert {"list_guilds", "send_message_to_channel", "ban_member"} <= names
    result = call(client, ADMIN_TOKEN, "list_guilds")
    assert not result.get("isError")
    assert "OpenDock" in json.dumps(result)


def test_write_connection(client):
    tokens = connect(client, "write")
    assert tokens.scope == "discord:read discord:write"
    assert "send_message_to_channel" in tool_names(client, tokens.access_token)
    assert "OpenDock" in json.dumps(call(client, tokens.access_token, "list_guilds"))
    # Reaches the tool (which fails on the fake session) instead of being refused.
    result = call(client, tokens.access_token, "kick_member", {"user_id": "1", "guild_id": "1"})
    assert "read-only" not in json.dumps(result)
    result = call(
        client,
        tokens.access_token,
        "call_tool_bulk",
        {"tool": "kick_member", "tool_arguments": [{"user_id": "1", "guild_id": "1"}]},
    )
    assert "read-only" not in json.dumps(result)


def test_read_only_connection(client):
    tokens = connect(client, "read")
    assert tokens.scope == "discord:read"
    names = tool_names(client, tokens.access_token)
    assert "list_guilds" in names and "fetch_channel_history" in names
    assert not {"send_message_to_channel", "ban_member", "remove_channel", "edit_guild"} & names

    assert "OpenDock" in json.dumps(call(client, tokens.access_token, "list_guilds"))
    result = call(client, tokens.access_token, "kick_member", {"user_id": "1", "guild_id": "1"})
    assert result["isError"] and "read-only" in json.dumps(result)

    # Bulk calls cannot be used to get around it.
    bulk = {"tool": "kick_member", "tool_arguments": [{"user_id": "1", "guild_id": "1"}]}
    result = call(client, tokens.access_token, "call_tool_bulk", bulk)
    assert result["isError"] and "read-only" in json.dumps(result)
    bulk = {
        "tool_calls": [
            {"tool": "list_guilds", "arguments": {}},
            {"tool": "call_tool_bulk", "arguments": bulk},
        ]
    }
    result = call(client, tokens.access_token, "call_tools_bulk", bulk)
    assert result["isError"] and "read-only" in json.dumps(result)
    bulk = {"tool_calls": [{"tool": "list_guilds", "arguments": {}}]}
    result = call(client, tokens.access_token, "call_tools_bulk", bulk)
    assert not result.get("isError") and "OpenDock" in json.dumps(result)


def test_code_works_once_and_needs_the_verifier(client):
    tokens = connect(client, "read")
    response = client.post(
        "/token",
        data={
            "grant_type": "authorization_code",
            "code": tokens.code,
            "client_id": tokens.client_id,
            "redirect_uri": REDIRECT_URI,
            "code_verifier": tokens.verifier,
        },
    )
    assert response.status_code == 400 and response.json()["error"] == "invalid_grant"


def test_refresh_rotates_and_keeps_the_level(client):
    tokens = connect(client, "read")
    data = {
        "grant_type": "refresh_token",
        "refresh_token": tokens.refresh_token,
        "client_id": tokens.client_id,
    }
    response = client.post("/token", data={**data, "scope": "discord:read discord:write"})
    assert response.status_code == 400 and response.json()["error"] == "invalid_scope"

    response = client.post("/token", data=data)
    assert response.status_code == 200, response.text
    refreshed = response.json()
    assert refreshed["scope"] == "discord:read"
    assert "send_message_to_channel" not in tool_names(client, refreshed["access_token"])
    assert client.post("/token", data=data).status_code == 400


def test_tokens_survive_a_restart_and_are_stored_hashed(client):
    tokens = connect(client, "write")
    path = oauth_provider._path
    stored = path.read_text()
    assert tokens.access_token not in stored and tokens.refresh_token not in stored
    assert ADMIN_TOKEN not in stored
    assert path.stat().st_mode & 0o777 == 0o600

    reloaded = ConsentOAuthProvider(
        public_url=PUBLIC_URL, admin_token=ADMIN_TOKEN, data_dir=path.parent
    )
    access = asyncio.run(reloaded.load_access_token(tokens.access_token))
    assert access is not None and access.scopes == ["discord:read", "discord:write"]


def test_consent_page_escapes_the_client_name(client):
    response = client.post(
        "/register",
        json={
            "client_name": "<script>alert(1)</script>",
            "redirect_uris": [REDIRECT_URI],
            "token_endpoint_auth_method": "none",
        },
    )
    client_id = response.json()["client_id"]
    response = client.get(
        "/authorize",
        params={
            "response_type": "code",
            "client_id": client_id,
            "redirect_uri": REDIRECT_URI,
            "code_challenge": "x" * 43,
            "code_challenge_method": "S256",
        },
    )
    page = client.get(response.headers["location"])
    assert "<script>" not in page.text and "&lt;script&gt;" in page.text
    assert client.get("/consent", params={"txn": "unknown"}).status_code == 400


def test_read_tool_classification():
    assert is_read_tool("list_guilds") and is_read_tool("inspect_role_permissions")
    assert not is_read_tool("send_message_to_channel") and not is_read_tool("unknown")
    assert not is_read_tool("call_tools_bulk", {"tool_calls": ["junk"]})
