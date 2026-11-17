"""Local fake SSH server for dev verification ONLY (binds 127.0.0.1:2201).

Accepts publickey auth for user "dev" using dev_test_ssh_key.pub.
Supported commands (enough to exercise the MCP ssh tools):
  echo <text>          -> echoes text
  id / whoami          -> canned identity
  cat -- '<path>'      -> read file from sandbox
  cat > '<path>'       -> write stdin into sandbox file
"""

import os
import socket
import threading
import time
import base64

import paramiko

HERE = os.path.dirname(os.path.abspath(__file__))
KEY_PATH = os.path.join(HERE, "..", "dev_test_ssh_key")
SANDBOX = os.path.join(HERE, "devsandbox")
os.makedirs(SANDBOX, exist_ok=True)

host_key = paramiko.Ed25519Key.from_private_key_file(KEY_PATH)


def load_pub():
    with open(KEY_PATH + ".pub") as f:
        parts = f.read().split()
    return paramiko.Ed25519Key(data=base64.b64decode(parts[1]))


ALLOWED_PUB = load_pub()


def _safe(name: str) -> str:
    return os.path.basename(name.replace("\\", "/").replace('"', "").replace("'", ""))


class Server(paramiko.ServerInterface):
    def get_server_key(self):
        return host_key

    def check_channel_request(self, kind, chanid):
        return paramiko.OPEN_SUCCEEDED

    def check_channel_session_request(self, channelid):
        return paramiko.OPEN_SUCCEEDED

    def check_auth_publickey(self, username, key):
        if username == "dev" and key == ALLOWED_PUB:
            return paramiko.AUTH_SUCCESSFUL
        return paramiko.AUTH_FAILED

    def get_allowed_auths(self, username):
        return "publickey"

    def check_auth_password(self, username, password):
        return paramiko.AUTH_FAILED

    def check_channel_exec_request(self, channel, command):
        print("exec request:", repr(command), flush=True)
        threading.Thread(target=self._exec, args=(channel, command), daemon=True).start()
        return True

    def _exec(self, channel, command):
        if isinstance(command, bytes):
            command = command.decode(errors="replace")
        command = command.strip()
        try:
            out = b""
            if command == "echo" or command.startswith("echo "):
                out = command[5:].encode() + b"\n"
            elif command.startswith("id"):
                out = b"uid=1000(dev) gid=1000(dev) groups=1000(dev)\n"
            elif command.startswith("whoami"):
                out = b"dev\n"
            elif command.startswith("cat > "):
                name = _safe(command[6:].strip())
                data = b""
                try:
                    while True:
                        chunk = channel.recv(4096)
                        if not chunk:
                            break
                        data += chunk
                except EOFError:
                    pass
                with open(os.path.join(SANDBOX, name), "wb") as f:
                    f.write(data)
                out = b""
            elif command.startswith("cat -- "):
                name = _safe(command[7:].strip())
                fp = os.path.join(SANDBOX, name)
                out = open(fp, "rb").read() if os.path.exists(fp) else b"cat: no such file\n"
            elif command.startswith("cat "):
                name = _safe(command[4:].strip())
                fp = os.path.join(SANDBOX, name)
                out = open(fp, "rb").read() if os.path.exists(fp) else b"cat: no such file\n"
            else:
                out = f"fake-sshd: unsupported command: {command}\n".encode()
            if out:
                channel.send(out)
            channel.send_exit_status(0)
        except Exception as e:  # noqa: BLE001
            channel.send(f"fake-sshd error: {e}\n".encode())
            channel.send_exit_status(1)
        finally:
            try:
                channel.close()
            except OSError:
                pass


def serve():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(("127.0.0.1", 2201))
    sock.listen(5)
    print("fake-sshd listening on 127.0.0.1:2201", flush=True)
    while True:
        client, addr = sock.accept()
        t = paramiko.Transport(client)
        t.add_server_key(host_key)
        try:
            t.start_server(server=Server())
        except Exception as e:  # noqa: BLE001
            print("handshake failed:", e, flush=True)
            try:
                client.close()
            except OSError:
                pass
            continue
        threading.Thread(target=_pump, args=(t,), daemon=True).start()


def _pump(transport):
    try:
        while transport.is_active():
            time.sleep(1)
    except Exception:
        pass


if __name__ == "__main__":
    serve()
