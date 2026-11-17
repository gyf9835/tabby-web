"""SSH ProxyCommand bridge for Eugeny/tabby-connection-gateway.

The gateway is a WebSocket -> TCP byte relay; the SSH handshake runs
end-to-end between this process (via OpenSSH) and the target host, through
the relayed stream.

Used as:  ssh -o ProxyCommand="python relay.py <url> <token> <host> <port>"
Protocol (text frames = JSON service messages, binary frames = raw TCP bytes):
  server -> {"_":"hello","version":1,"auth_required":bool}
  client -> {"_":"hello","version":1,"auth_token":...}
  server -> {"_":"ready"}
  client -> {"_":"connect","host":...,"port":...}
  server -> {"_":"connected"}            then raw bytes both ways
  errors -> {"_":"error","code":...,"details":...} then close

stdin is pumped by a plain thread (asyncio pipes are Unix-only; this keeps
the bridge cross-platform).
"""

import asyncio
import json
import sys
import threading

import websockets

CHUNK = 32768


def die(msg: str, code: int = 1):
    print(f"tabby-relay: {msg}", file=sys.stderr)
    sys.exit(code)


def _stdin_pump(queue: asyncio.Queue, loop) -> None:
    stdin = sys.stdin.buffer
    try:
        while True:
            data = stdin.read1(CHUNK)
            if not data:
                break
            loop.call_soon_threadsafe(queue.put_nowait, data)
    except (OSError, ValueError):
        pass
    finally:
        loop.call_soon_threadsafe(queue.put_nowait, None)  # EOF sentinel


async def main() -> int:
    if len(sys.argv) < 5:
        die("usage: relay.py <gateway-url> <auth-token> <host> <port>")
    gw_url, token, host, port = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

    try:
        ws = await websockets.connect(gw_url, max_size=None, open_timeout=15)
    except Exception as e:
        die(f"gateway connect failed: {e}")

    try:
        hello = json.loads(await asyncio.wait_for(ws.recv(), 15))
        if hello.get("_") != "hello":
            die(f"unexpected gateway greeting: {hello}")
        await ws.send(json.dumps({"_": "hello", "version": 1, "auth_token": token}))
        ready = json.loads(await asyncio.wait_for(ws.recv(), 15))
        if ready.get("_") != "ready":
            die(f"gateway not ready: {ready}")
        await ws.send(json.dumps({"_": "connect", "host": host, "port": int(port)}))
        reply = json.loads(await asyncio.wait_for(ws.recv(), 20))
        if reply.get("_") == "error":
            die(f"gateway error: {reply.get('code')} {reply.get('details', '')}")
        if reply.get("_") != "connected":
            die(f"unexpected gateway reply: {reply}")
    except asyncio.TimeoutError:
        die("gateway handshake timeout")
    except json.JSONDecodeError:
        die("malformed gateway message")

    queue: asyncio.Queue = asyncio.Queue()
    loop = asyncio.get_event_loop()
    threading.Thread(target=_stdin_pump, args=(queue, loop), daemon=True).start()

    async def stdin_to_ws():
        while True:
            data = await queue.get()
            if data is None:
                return
            await ws.send(data)

    async def ws_to_stdout():
        while True:
            msg = await ws.recv()
            if isinstance(msg, str):
                try:
                    m = json.loads(msg)
                except json.JSONDecodeError:
                    return
                if m.get("_") == "error":
                    print(
                        f"tabby-relay: gateway error: {m.get('code')} "
                        f"{m.get('details', '')}",
                        file=sys.stderr,
                    )
                return
            if msg is None:
                return
            sys.stdout.buffer.write(msg)
            sys.stdout.buffer.flush()

    try:
        done, pending = await asyncio.wait(
            [
                asyncio.ensure_future(stdin_to_ws()),
                asyncio.ensure_future(ws_to_stdout()),
            ],
            return_when=asyncio.FIRST_COMPLETED,
        )
        for t in pending:
            t.cancel()
        for t in done:
            t.result()
    finally:
        try:
            await ws.close()
        except Exception:  # noqa: BLE001
            pass
    return 0


if __name__ == "__main__":
    try:
        sys.exit(asyncio.run(main()))
    except KeyboardInterrupt:
        sys.exit(130)
    except BrokenPipeError:
        sys.exit(0)
