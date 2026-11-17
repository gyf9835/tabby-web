"""SSH operations executed with OpenSSH on the host.

Connections go through the tabby-connection-gateway WebSocket relay via
ProxyCommand (SSH handshake stays end-to-end); direct mode is available as
fallback. Password auth uses sshpass (SSHPASS env), key auth uses a temp key
file; both never leak secrets into the process argv.
"""

import base64
import glob
import os
import shlex
import subprocess
import tempfile
import time

from django.conf import settings

from . import profiles as profiles_mod

MAX_OUTPUT = 4 * 1024 * 1024
MAX_FILE = 4 * 1024 * 1024


class SshError(Exception):
    pass


def _venv_python() -> str:
    return sys_executable()


def sys_executable() -> str:
    import sys

    return sys.executable


def _relay_path() -> str:
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "relay.py")


def _gateway_url() -> str:
    return settings.MCP_GATEWAY_URL or ""


def _gateway_token() -> str:
    return settings.MCP_GATEWAY_TOKEN or ""


def connect_modes() -> list:
    mode = (settings.MCP_CONNECT_MODE or "gateway").lower()
    if mode == "gateway":
        return ["gateway"]
    if mode == "direct":
        return ["direct"]
    return ["gateway", "direct"]  # auto


def _proxy_cmd(host: str, port: int) -> str:
    return " ".join(
        [
            shlex.quote(_venv_python()),
            shlex.quote(_relay_path()),
            shlex.quote(_gateway_url()),
            shlex.quote(_gateway_token()),
            shlex.quote(host),
            shlex.quote(str(port)),
        ]
    )


def _base_ssh_opts() -> list:
    return [
        "-o",
        "StrictHostKeyChecking=no",
        "-o",
        "UserKnownHostsFile=/dev/null",
        "-o",
        "ConnectTimeout=15",
        "-o",
        "ServerAliveInterval=15",
        "-o",
        "ServerAliveCountMax=3",
        "-o",
        "LogLevel=ERROR",
    ]


def _auth_args_and_env(auth: dict, env: dict):
    """Returns (prefix_args, ssh_opts). prefix_args wrap the ssh binary."""
    kind = auth.get("kind")
    if kind == "password":
        env["SSHPASS"] = auth["password"]
        return ["sshpass", "-e"], [
            "-o",
            "PreferredAuthentications=password,keyboard-interactive",
            "-o",
            "PubkeyAuthentication=no",
        ]
    if kind == "key":
        fd, path = tempfile.mkstemp(prefix="mcpkey-", suffix=".pem")
        # newline="" keeps the key byte-exact (Windows text mode would break it)
        with os.fdopen(fd, "w", newline="") as f:
            f.write(auth["key"])
        os.chmod(path, 0o600)
        env["_MCP_KEYFILE"] = path
        return [], [
            "-i",
            path,
            "-o",
            "IdentitiesOnly=yes",
            "-o",
            "BatchMode=yes",
        ]
    return [], ["-o", "BatchMode=yes"]


def _cleanup_env(env: dict):
    kf = env.pop("_MCP_KEYFILE", None)
    if kf:
        try:
            os.unlink(kf)
        except OSError:
            pass


def _ssh_argv(user, profile, auth, via, remote_cmd=None):
    host = profile.get("host")
    port = int(profile.get("port") or 22)
    login = f"{profile.get('user')}@{host}" if profile.get("user") else str(host)

    env = dict(os.environ)
    auth_prefix, auth_opts = _auth_args_and_env(auth, env)
    args = auth_prefix + ["ssh"] + _base_ssh_opts() + auth_opts
    if via == "gateway":
        if not _gateway_url():
            raise SshError("MCP_GATEWAY_URL is not configured")
        args += ["-o", f"ProxyCommand={_proxy_cmd(host, port)}"]
    args += ["-p", str(port)]
    args += ["--", login]
    if remote_cmd:
        args.append(remote_cmd)
    return args, env


def _run(args, env, timeout, stdin_data=None):
    if stdin_data is None:
        # give ssh's stdin an immediate EOF so it never blocks on forwarding
        stdin_data = b""
    try:
        proc = subprocess.run(
            args,
            input=stdin_data,
            capture_output=True,
            timeout=timeout,
            env=env,
        )
        return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired as e:
        out = (e.stdout or b"")[:MAX_OUTPUT]
        err = (e.stderr or b"")[:MAX_OUTPUT]
        raise SshError(
            f"command timed out after {timeout}s. stdout: "
            f"{out.decode(errors='replace')!r} stderr: {err.decode(errors='replace')!r}"
        )


def _looks_like_relay_failure(stderr: str) -> bool:
    return "tabby-relay" in stderr or "connection-failed" in stderr


def ssh_exec(user, profile, auth, command: str, timeout_s: int = 30) -> dict:
    started = time.time()
    errors = []
    for via in connect_modes():
        args, env = _ssh_argv(user, profile, auth, via, remote_cmd=command)
        try:
            code, out, err = _run(args, env, timeout_s)
        except SshError as e:
            _cleanup_env(env)
            if via == connect_modes()[-1]:
                raise
            errors.append(f"{via}: {e}")
            continue
        except Exception as e:  # noqa: BLE001
            _cleanup_env(env)
            if via == connect_modes()[-1]:
                raise SshError(f"ssh failed: {e}")
            errors.append(f"{via}: {e}")
            continue
        sout = out.decode(errors="replace")[:MAX_OUTPUT]
        serr = err.decode(errors="replace")[:MAX_OUTPUT]
        if code == 255 and via != connect_modes()[-1] and _looks_like_relay_failure(serr):
            errors.append(f"{via}: {serr.strip()[:300]}")
            _cleanup_env(env)
            continue
        _cleanup_env(env)
        return {
            "exit_code": code,
            "stdout": sout,
            "stderr": serr,
            "via": via,
            "duration_ms": int((time.time() - started) * 1000),
        }
    _cleanup_env(env)
    raise SshError("; ".join(errors) or "all connection modes failed")


def ssh_read_file(user, profile, auth, path: str) -> dict:
    if "\n" in path or len(path) > 1024:
        raise SshError("invalid path")
    started = time.time()
    errors = []
    env = {}
    for via in connect_modes():
        args, env = _ssh_argv(user, profile, auth, via, remote_cmd=f"cat -- {shlex.quote(path)}")
        try:
            code, out, err = _run(args, env, 60)
        except SshError as e:
            _cleanup_env(env)
            if via == connect_modes()[-1]:
                raise
            errors.append(f"{via}: {e}")
            continue
        _cleanup_env(env)
        if code != 0:
            serr = err.decode(errors="replace")[:500]
            if via != connect_modes()[-1] and _looks_like_relay_failure(serr):
                errors.append(f"{via}: {serr}")
                continue
            raise SshError(f"read failed (exit {code}): {serr or 'unknown error'}")
        if len(out) > MAX_FILE:
            return {
                "path": path,
                "truncated": True,
                "note": f"file larger than {MAX_FILE} bytes; read aborted",
                "via": via,
            }
        try:
            content = out.decode("utf-8")
            encoding = "text"
        except UnicodeDecodeError:
            content = base64.b64encode(out).decode("ascii")
            encoding = "base64"
        return {
            "path": path,
            "size": len(out),
            "encoding": encoding,
            "content": content,
            "via": via,
            "duration_ms": int((time.time() - started) * 1000),
        }
    _cleanup_env(env)
    raise SshError("; ".join(errors))


def ssh_write_file(user, profile, auth, path: str, data: bytes) -> dict:
    if "\n" in path or len(path) > 1024:
        raise SshError("invalid path")
    if len(data) > MAX_FILE:
        raise SshError(f"payload too large ({len(data)} bytes, max {MAX_FILE})")
    started = time.time()
    errors = []
    env = {}
    for via in connect_modes():
        remote = f"cat > {shlex.quote(path)}"
        args, env = _ssh_argv(user, profile, auth, via, remote_cmd=remote)
        try:
            code, out, err = _run(args, env, 60, stdin_data=data)
        except SshError as e:
            _cleanup_env(env)
            if via == connect_modes()[-1]:
                raise
            errors.append(f"{via}: {e}")
            continue
        _cleanup_env(env)
        if code != 0:
            serr = err.decode(errors="replace")[:500]
            if via != connect_modes()[-1] and _looks_like_relay_failure(serr):
                errors.append(f"{via}: {serr}")
                continue
            raise SshError(f"write failed (exit {code}): {serr or 'unknown error'}")
        return {
            "path": path,
            "written_bytes": len(data),
            "via": via,
            "duration_ms": int((time.time() - started) * 1000),
            "note": "file recreated via stream; ownership/permissions may reset",
        }
    _cleanup_env(env)
    raise SshError("; ".join(errors))


def list_servers(user, allowed_groups=None) -> dict:
    ws = profiles_mod.load_workspace(user)
    servers = []
    for p in ws["profiles"]:
        group = p.get("group") or ""
        if allowed_groups is not None and group not in allowed_groups:
            continue
        try:
            auth = profiles_mod.profile_auth(user, p)
            kind = auth.get("kind", "none")
        except Exception:  # noqa: BLE001
            kind = "none"
        servers.append(
            {
                "name": p.get("name") or p.get("id"),
                "group": group,
                "host": p.get("host"),
                "port": int(p.get("port") or 22),
                "user": p.get("user"),
                "auth": kind,
            }
        )
    servers.sort(key=lambda s: (s["group"], str(s["name"])))
    return {
        "mode": settings.MCP_CONNECT_MODE,
        "gateway_configured": bool(_gateway_url()),
        "encrypted_config": ws["encrypted"],
        "total": len(servers),
        "servers": servers,
    }
