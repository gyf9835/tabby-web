"""Local tests for the tabby MCP server app.

All logic runs against synthetic configs — no network, no real servers.
"""

import base64
import json
import os

import pytest
import yaml
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from django.test import Client, override_settings

from tabby.app.mcp_server import profiles as profiles_mod
from tabby.app.mcp_server import vault as vault_mod
from tabby.app.mcp_server.models import McpClient

# ---------------------------------------------------------------- fixtures

PROFILES = [
    {
        "id": "11111111-1111-1111-1111-111111111111",
        "type": "ssh",
        "name": "home-lxc",
        "group": "home",
        "host": "192.0.2.10",
        "port": 22,
        "user": "gyf",
        "auth": {"type": "password", "id": "aaaaaaaa-1111-1111-1111-111111111111"},
    },
    {
        "id": "22222222-2222-2222-2222-222222222222",
        "type": "ssh",
        "name": "vps-hk",
        "group": "vps",
        "host": "192.0.2.20",
        "port": 2222,
        "user": "root",
        "auth": {"type": "key", "id": "bbbbbbbb-2222-2222-2222-222222222222"},
    },
    {
        "id": "33333333-3333-3333-3333-333333333333",
        "type": "ssh",
        "name": "no-auth-box",
        "group": "home",
        "host": "192.0.2.30",
        "port": 22,
        "user": "ops",
        "auth": None,
    },
    {
        "id": "44444444-4444-4444-4444-444444444444",
        "type": "local",  # non-ssh, must be ignored
        "name": "local-shell",
    },
]

SECRETS = [
    {"type": "password", "key": {"id": "aaaaaaaa-1111-1111-1111-111111111111"}, "value": "p@ss"},
    {"type": "key", "key": {"id": "bbbbbbbb-2222-2222-2222-222222222222"}, "value": "-----BEGIN PRIVATE KEY-----\nabc\n-----END PRIVATE KEY-----\n"},
]


def _encrypt(payload: dict, password: str) -> str:
    stored = {"version": 1, "contents": "", "keySalt": "", "iv": ""}
    salt = os.urandom(8)
    iv = os.urandom(16)
    key = vault_mod.derive_key(password.encode(), salt)
    pt = json.dumps(payload)
    padder = PKCS7(128).padder()
    padded = padder.update(pt.encode()) + padder.finalize()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    stored["contents"] = base64.b64encode(enc.update(padded) + enc.finalize()).decode()
    stored["keySalt"] = base64.b64encode(salt).decode()
    stored["iv"] = base64.b64encode(iv).decode()
    return yaml.dump({"encrypted": True, "vault": stored, "configSync": {"configID": 1}})


def _encrypted_config_yaml(password: str = "hunter2") -> str:
    return _encrypt({"config": {"profiles": PROFILES}, "secrets": SECRETS}, password)


def _plaintext_config_yaml() -> str:
    return yaml.dump({"profiles": PROFILES, "vault": {"secrets": SECRETS}})


@pytest.fixture(autouse=True)
def _reset_profile_cache():
    profiles_mod._cache.update({"key": None, "at": 0.0, "value": None})
    yield
    profiles_mod._cache.update({"key": None, "at": 0.0, "value": None})


@pytest.fixture
def user(django_user_model):
    return django_user_model.objects.create(username="admin")


def _add_config(user, content: str):
    from tabby.app.models import Config

    return Config.objects.create(user=user, name="test", content=content)


# ---------------------------------------------------------------- vault


def test_vault_roundtrip():
    stored = yaml.safe_load(_encrypted_config_yaml("pw1"))["vault"]
    out = vault_mod.decrypt_stored_vault(stored, "pw1")
    assert out["config"]["profiles"][0]["name"] == "home-lxc"


def test_vault_wrong_password_raises():
    stored = yaml.safe_load(_encrypted_config_yaml("pw1"))["vault"]
    with pytest.raises(Exception):
        vault_mod.decrypt_stored_vault(stored, "wrong")


def test_is_encrypted_config():
    assert vault_mod.is_encrypted_config(yaml.safe_load(_encrypted_config_yaml("x")))
    assert not vault_mod.is_encrypted_config({"profiles": []})


# ---------------------------------------------------------------- profiles


@pytest.mark.django_db
def test_load_workspace_encrypted(user):
    _add_config(user, _encrypted_config_yaml())
    with override_settings(MCP_VAULT_PASSWORD="hunter2"):
        ws = profiles_mod.load_workspace(user)
    assert ws["encrypted"] is True
    names = [p["name"] for p in ws["profiles"]]
    assert names == ["home-lxc", "vps-hk", "no-auth-box"]
    assert ws["secrets"]["aaaaaaaa-1111-1111-1111-111111111111"]["value"] == "p@ss"


@pytest.mark.django_db
def test_load_workspace_encrypted_no_password(user):
    _add_config(user, _encrypted_config_yaml())
    with override_settings(MCP_VAULT_PASSWORD=None):
        with pytest.raises(profiles_mod.WorkspaceError, match="MCP_VAULT_PASSWORD"):
            profiles_mod.load_workspace(user)


@pytest.mark.django_db
def test_load_workspace_wrong_password(user):
    _add_config(user, _encrypted_config_yaml())
    with override_settings(MCP_VAULT_PASSWORD="nope"):
        with pytest.raises(profiles_mod.WorkspaceError, match="decryption failed"):
            profiles_mod.load_workspace(user)


@pytest.mark.django_db
def test_load_workspace_plaintext(user):
    _add_config(user, _plaintext_config_yaml())
    ws = profiles_mod.load_workspace(user)
    assert ws["encrypted"] is False
    assert len(ws["profiles"]) == 3


@pytest.mark.django_db
def test_load_workspace_no_config(user):
    with pytest.raises(profiles_mod.WorkspaceError, match="no synced config"):
        profiles_mod.load_workspace(user)


@pytest.mark.django_db
def test_resolve_profile_variants(user):
    _add_config(user, _encrypted_config_yaml())
    with override_settings(MCP_VAULT_PASSWORD="hunter2"):
        assert profiles_mod.resolve_profile(user, "home-lxc")["id"] == "11111111-1111-1111-1111-111111111111"
        assert profiles_mod.resolve_profile(user, "VPS-HK")["group"] == "vps"  # case-insensitive
        assert profiles_mod.resolve_profile(user, "33333333-3333-3333-3333-333333333333")["name"] == "no-auth-box"
        with pytest.raises(profiles_mod.WorkspaceError, match="not found"):
            profiles_mod.resolve_profile(user, "missing")
        with pytest.raises(profiles_mod.WorkspaceError, match="not found"):
            profiles_mod.resolve_profile(user, "")


@pytest.mark.django_db
def test_profile_auth_kinds(user):
    _add_config(user, _encrypted_config_yaml())
    with override_settings(MCP_VAULT_PASSWORD="hunter2"):
        p1 = profiles_mod.resolve_profile(user, "home-lxc")
        assert profiles_mod.profile_auth(user, p1) == {"kind": "password", "password": "p@ss"}
        p2 = profiles_mod.resolve_profile(user, "vps-hk")
        auth2 = profiles_mod.profile_auth(user, p2)
        assert auth2["kind"] == "key" and "BEGIN PRIVATE KEY" in auth2["key"]
        p3 = profiles_mod.resolve_profile(user, "no-auth-box")
        assert profiles_mod.profile_auth(user, p3) == {"kind": "none"}


# ---------------------------------------------------------------- mcp client model


@pytest.mark.django_db
def test_mcp_client_token_autogen():
    c = McpClient.objects.create(name="zcode")
    assert len(c.token) == 64  # token_hex(32)
    c2 = McpClient.objects.create(name="claude", allowed_groups=["home"])
    assert c2.allowed_groups == ["home"]
    assert McpClient.objects.count() == 2


# ---------------------------------------------------------------- MCP endpoint helpers


def _rpc(method, params=None, id=1):
    body = {"jsonrpc": "2.0", "method": method}
    if params is not None:
        body["params"] = params
    if id is not None:
        body["id"] = id
    return body


def _post(client, body, token=None):
    kwargs = {"content_type": "application/json"}
    if token:
        kwargs["HTTP_AUTHORIZATION"] = f"Bearer {token}"
    return client.post("/mcp", json.dumps(body), **kwargs)


@pytest.mark.django_db
def test_endpoint_requires_auth(user):
    _add_config(user, _encrypted_config_yaml())
    r = _post(Client(), _rpc("tools/list"))
    assert r.status_code == 401
    r = _post(Client(), _rpc("tools/list"), token="bogus")
    assert r.status_code == 401
    assert r.json()["error"]["code"] == -32001


@pytest.mark.django_db
def test_endpoint_get_405(user):
    assert Client().get("/mcp").status_code == 405


@pytest.mark.django_db
def test_endpoint_notification_202(user):
    _add_config(user, _encrypted_config_yaml())
    c = McpClient.objects.create(name="t2")
    r = _post(Client(), {"jsonrpc": "2.0", "method": "notifications/initialized"}, token=c.token)
    assert r.status_code == 202


@pytest.mark.django_db
def test_initialize_and_tools_list(user):
    _add_config(user, _encrypted_config_yaml())
    c = McpClient.objects.create(name="tester")
    r = _post(Client(), _rpc("initialize", {"protocolVersion": "2024-11-05"}), token=c.token)
    assert r.status_code == 200
    result = r.json()["result"]
    assert result["protocolVersion"] == "2024-11-05"
    assert result["serverInfo"]["name"] == "tabby-web-mcp"
    assert "tools" in result["capabilities"]

    r = _post(Client(), _rpc("tools/list"), token=c.token)
    tools = r.json()["result"]["tools"]
    assert {t["name"] for t in tools} == {"list_servers", "ssh_exec", "sftp_read", "sftp_write"}
    for t in tools:
        assert "inputSchema" in t


@pytest.mark.django_db
def test_list_servers_unrestricted(user):
    _add_config(user, _plaintext_config_yaml())
    c = McpClient.objects.create(name="all")  # allowed_groups None
    r = _post(Client(), _rpc("tools/call", {"name": "list_servers", "arguments": {}}), token=c.token)
    data = json.loads(r.json()["result"]["content"][0]["text"])
    assert data["total"] == 3
    assert {s["group"] for s in data["servers"]} == {"home", "vps"}
    auth_by_name = {s["name"]: s["auth"] for s in data["servers"]}
    assert auth_by_name == {"home-lxc": "password", "vps-hk": "key", "no-auth-box": "none"}


@pytest.mark.django_db
def test_list_servers_group_filtered(user):
    _add_config(user, _plaintext_config_yaml())
    c = McpClient.objects.create(name="home-only", allowed_groups=["home"])
    r = _post(Client(), _rpc("tools/call", {"name": "list_servers", "arguments": {}}), token=c.token)
    data = json.loads(r.json()["result"]["content"][0]["text"])
    assert data["total"] == 2
    assert all(s["group"] == "home" for s in data["servers"])
    assert "vps-hk" not in {s["name"] for s in data["servers"]}


@pytest.mark.django_db
def test_ssh_exec_denied_for_other_group(user):
    _add_config(user, _plaintext_config_yaml())
    c = McpClient.objects.create(name="home-only", allowed_groups=["home"])
    r = _post(
        Client(),
        _rpc("tools/call", {"name": "ssh_exec", "arguments": {"server": "vps-hk", "command": "id"}}),
        token=c.token,
    )
    result = r.json()["result"]
    assert result["isError"] is True
    assert "allowed groups" in result["content"][0]["text"]


@pytest.mark.django_db
def test_ssh_exec_gateway_unconfigured_is_clean_error(user):
    _add_config(user, _plaintext_config_yaml())
    c = McpClient.objects.create(name="all")
    with override_settings(MCP_GATEWAY_URL="", MCP_CONNECT_MODE="gateway"):
        r = _post(
            Client(),
            _rpc("tools/call", {"name": "ssh_exec", "arguments": {"server": "home-lxc", "command": "echo hi"}}),
            token=c.token,
        )
    result = r.json()["result"]
    assert result["isError"] is True
    assert "MCP_GATEWAY_URL" in result["content"][0]["text"]


@pytest.mark.django_db
def test_ssh_exec_unknown_server(user):
    _add_config(user, _plaintext_config_yaml())
    c = McpClient.objects.create(name="all")
    r = _post(
        Client(),
        _rpc("tools/call", {"name": "ssh_exec", "arguments": {"server": "nope", "command": "x"}}),
        token=c.token,
    )
    result = r.json()["result"]
    assert result["isError"] is True
    assert "not found" in result["content"][0]["text"]
    assert "home-lxc" in result["content"][0]["text"]  # lists available


@pytest.mark.django_db
def test_sync_token_has_full_access(user):
    cfg = _add_config(user, _plaintext_config_yaml())
    r = _post(Client(), _rpc("tools/call", {"name": "list_servers", "arguments": {}}), token=user.config_sync_token)
    data = json.loads(r.json()["result"]["content"][0]["text"])
    assert data["total"] == 3


@pytest.mark.django_db
def test_unknown_method(user):
    _add_config(user, _plaintext_config_yaml())
    c = McpClient.objects.create(name="t")
    r = _post(Client(), _rpc("bogus/method"), token=c.token)
    assert r.json()["error"]["code"] == -32601


@pytest.mark.django_db
def test_workspace_error_surfaces_as_tool_error(user):
    _add_config(user, _encrypted_config_yaml())  # encrypted, no password set
    c = McpClient.objects.create(name="all")
    r = _post(Client(), _rpc("tools/call", {"name": "list_servers", "arguments": {}}), token=c.token)
    result = r.json()["result"]
    assert result["isError"] is True
    assert "MCP_VAULT_PASSWORD" in result["content"][0]["text"]
