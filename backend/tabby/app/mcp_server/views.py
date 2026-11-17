"""MCP (Model Context Protocol) endpoint for tabby-web.

Stateless streamable-HTTP implementation (JSON responses only, no SSE):
exposes the user's synced Tabby SSH profiles as MCP tools.

Auth:
  - Authorization: Bearer <McpClient.token>   (per-client, group-scoped)
  - Authorization: Bearer <user.config_sync_token>  (full access, admin)

Clients see different server sets via McpClient.allowed_groups (Tabby profile
groups); this pairs with mcpjungle registering the same URL once per token.
"""

import base64
import json
import logging

from django.http import HttpResponse, JsonResponse
from django.views.decorators.csrf import csrf_exempt

from . import profiles as profiles_mod
from . import sshops
from .models import McpClient

logger = logging.getLogger(__name__)

PROTOCOL_VERSION = "2024-11-05"
SERVER_INFO = {"name": "tabby-web-mcp", "version": "1.0.0"}

MAX_TIMEOUT_S = 240


class RpcError(Exception):
    def __init__(self, message, code=-32000):
        super().__init__(message)
        self.code = code


def _authenticate(request):
    """Returns (user, client_or_None, allowed_groups_or_None) or raises RpcError."""
    header = request.META.get("HTTP_AUTHORIZATION", "")
    parts = header.split()
    if len(parts) != 2 or parts[0].lower() != "bearer":
        raise RpcError("Authorization: Bearer <token> required", code=-32001)
    token = parts[1]

    from tabby.app.models import User

    client = McpClient.objects.filter(token=token, enabled=True).first()
    if client:
        u = getattr(request, "user", None)
        user = u if getattr(u, "is_authenticated", False) else None
        return user, client, client.allowed_groups

    user = User.objects.filter(config_sync_token=token, is_active=True).first()
    if user:
        return user, None, None  # sync token = full access
    raise RpcError("invalid MCP client token", code=-32001)


def _user_for_client(user, client):
    """McpClient tokens are not user sessions; resolve the owning user via
    the (single) config that has profiles."""
    if user and getattr(user, "pk", None):
        return user
    from tabby.app.models import User

    return User.objects.filter(is_active=True).order_by("id").first()


def _check_group(user, client, profile):
    if client is None or client.allowed_groups is None:
        return
    group = profile.get("group") or ""
    if group not in client.allowed_groups:
        raise RpcError(
            f"server '{profile.get('name')}' (group '{group or '(none)'}) is not "
            "in this client's allowed groups"
        )


def _tools_definition():
    return [
        {
            "name": "list_servers",
            "description": (
                "List SSH servers managed via Tabby (synced from the Tabby "
                "config server), grouped by Tabby profile group."
            ),
            "inputSchema": {"type": "object", "properties": {}, "additionalProperties": False},
        },
        {
            "name": "ssh_exec",
            "description": (
                "Run a shell command on one of the Tabby-managed SSH servers "
                "and return stdout/stderr/exit code. Connections go through "
                "the Tabby connection gateway relay (direct fallback supported)."
            ),
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server": {"type": "string", "description": "server name (or id) from list_servers"},
                    "command": {"type": "string", "description": "shell command to run"},
                    "timeout_s": {"type": "integer", "description": "timeout in seconds (default 30, max 240)"},
                },
                "required": ["server", "command"],
                "additionalProperties": False,
            },
        },
        {
            "name": "sftp_read",
            "description": "Read a file from a Tabby-managed SSH server (text, or base64 if binary; max 4 MB).",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server": {"type": "string"},
                    "path": {"type": "string"},
                },
                "required": ["server", "path"],
                "additionalProperties": False,
            },
        },
        {
            "name": "sftp_write",
            "description": "Write a file on a Tabby-managed SSH server (max 4 MB). Send text as content_text or binary as content_base64.",
            "inputSchema": {
                "type": "object",
                "properties": {
                    "server": {"type": "string"},
                    "path": {"type": "string"},
                    "content_text": {"type": "string"},
                    "content_base64": {"type": "string"},
                },
                "required": ["server", "path"],
                "additionalProperties": False,
            },
        },
    ]


def _tool_result(text: str, is_error: bool = False) -> dict:
    out = {"content": [{"type": "text", "text": text}]}
    if is_error:
        out["isError"] = True
    return out


def _call_tool(user, client, name: str, args: dict) -> dict:
    if name == "list_servers":
        try:
            return _tool_result(
                json.dumps(sshops.list_servers(user, client.allowed_groups if client else None), ensure_ascii=False)
            )
        except profiles_mod.WorkspaceError as e:
            return _tool_result(str(e), is_error=True)

    try:
        ws = profiles_mod.load_workspace(user)
    except profiles_mod.WorkspaceError as e:
        return _tool_result(str(e), is_error=True)

    if name not in ("ssh_exec", "sftp_read", "sftp_write"):
        return _tool_result(f"unknown tool: {name}", is_error=True)

    try:
        profile = profiles_mod.resolve_profile(user, str(args.get("server", "")))
    except profiles_mod.WorkspaceError as e:
        return _tool_result(str(e), is_error=True)

    try:
        _check_group(user, client, profile)
    except RpcError as e:
        return _tool_result(str(e), is_error=True)

    auth = profiles_mod.profile_auth(user, profile)

    if name == "ssh_exec":
        command = str(args.get("command", ""))
        if not command:
            return _tool_result("command is required", is_error=True)
        timeout_s = int(args.get("timeout_s") or 30)
        timeout_s = max(1, min(timeout_s, MAX_TIMEOUT_S))
        try:
            result = sshops.ssh_exec(user, profile, auth, command, timeout_s)
        except sshops.SshError as e:
            return _tool_result(f"ssh_exec failed: {e}", is_error=True)
        return _tool_result(json.dumps(result, ensure_ascii=False))

    if name == "sftp_read":
        try:
            result = sshops.ssh_read_file(user, profile, auth, str(args.get("path", "")))
        except sshops.SshError as e:
            return _tool_result(f"sftp_read failed: {e}", is_error=True)
        return _tool_result(json.dumps(result, ensure_ascii=False))

    # sftp_write
    path = str(args.get("path", ""))
    if args.get("content_base64"):
        try:
            data = base64.b64decode(str(args.get("content_base64")), validate=True)
        except Exception as e:  # noqa: BLE001
            return _tool_result(f"invalid base64: {e}", is_error=True)
    else:
        data = str(args.get("content_text", "")).encode("utf-8")
    try:
        result = sshops.ssh_write_file(user, profile, auth, path, data)
    except sshops.SshError as e:
        return _tool_result(f"sftp_write failed: {e}", is_error=True)
    return _tool_result(json.dumps(result, ensure_ascii=False))


def _dispatch(user, client, method: str, params: dict):
    if method == "initialize":
        return {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {"listChanged": False}},
            "serverInfo": SERVER_INFO,
        }
    if method == "ping":
        return {}
    if method == "tools/list":
        return {"tools": _tools_definition()}
    if method == "tools/call":
        name = str(params.get("name", ""))
        args = params.get("arguments") or {}
        return _call_tool(user, client, name, args)
    raise RpcError(f"method not found: {method}", code=-32601)


@csrf_exempt
def mcp_endpoint(request):
    if request.method != "POST":
        return HttpResponse(status=405)

    try:
        user, client, _groups = _authenticate(request)
    except RpcError as e:
        return JsonResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": e.code, "message": str(e)}},
            status=401,
        )

    try:
        payload = json.loads(request.body.decode("utf-8"))
    except Exception:  # noqa: BLE001
        return JsonResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32700, "message": "parse error"}}
        )

    if not isinstance(payload, dict) or payload.get("jsonrpc") != "2.0":
        return JsonResponse(
            {"jsonrpc": "2.0", "id": None, "error": {"code": -32600, "message": "invalid request"}}
        )

    req_id = payload.get("id")
    method = payload.get("method", "")
    params = payload.get("params") or {}

    if req_id is None:  # notification
        return HttpResponse(status=202)

    owner = _user_for_client(user, client)
    if owner is None:
        return JsonResponse(
            {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32000, "message": "no active user with a synced config"}}
        )

    try:
        result = _dispatch(owner, client, method, params)
    except RpcError as e:
        return JsonResponse({"jsonrpc": "2.0", "id": req_id, "error": {"code": e.code, "message": str(e)}})
    except Exception as e:  # noqa: BLE001
        logger.exception("mcp tools/call crashed")
        return JsonResponse(
            {"jsonrpc": "2.0", "id": req_id, "error": {"code": -32603, "message": f"internal error: {e}"}}
        )

    return JsonResponse({"jsonrpc": "2.0", "id": req_id, "result": result})
