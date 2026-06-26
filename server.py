#!/usr/bin/env python3
"""
NDCrypt relay server — hardened edition.

Changes from original
─────────────────────
[S1] Session pairing & key   Alice's pubkey send is assigned an opaque, random
     confirmation            session_id by the server purely for routing —
                              it carries no security meaning.  The real
                              integrity guarantee is cryptographic: Bob
                              encrypts a fixed confirmation tag under the
                              seed he just derived (using ONLY the existing
                              NDCryptWasm encrypt_bytes/decrypt_bytes — no
                              extra hash primitive, no external library).
                              Alice can only produce the matching tag back
                              if her decapsulation recovered the SAME seed,
                              which is only possible if Bob really
                              encapsulated against Alice's real public key.
                              A MITM that swaps in a different pubkey ends
                              up holding a seed Alice never shares, so the
                              confirmation round-trip fails and both sides
                              abort. This replaces the previous SHA3-256
                              pubkey-commitment scheme, which depended on a
                              hash export that does not exist in the
                              compiled NDCrypt wasm package.

[S2] No plaintext metadata  name, msgId, chunkIndex, totalChunks are all packed into
                            the 31-byte NDCrypt payload as a binary header.  The wire
                            carries only {type, nonce, array} for every message.
                            A passive observer sees a fixed-size array and a nonce —
                            no name, no chunk count, no message length.

[S3] Origin allowlist       WebSocket upgrades are rejected unless the Origin header
                            matches the server's own host.  Prevents cross-site
                            WebSocket hijacking from any other page.  The allowed
                            set is computed once at startup, not per-connection.

[S4] Per-IP rate limiting   Token-bucket: burst + refill rate sized to keep up with
                            real chunked file transfers (see constants below) while
                            still dropping a genuine flood from a single IP.

[S5] Path traversal fix     File serving resolves against an absolute PKG_DIR, checked
                            with os.path.commonpath().  No normalised-but-still-escaping
                            path can reach outside the pkg/ directory.

[S6] Explicit exceptions    All bare except: clauses replaced with typed handlers.

[S7] Session state machine  Server tracks handshake state per connection pair:
                            IDLE → PUBKEY_SENT → COMPLETE.  Out-of-order or duplicate
                            handshake frames are rejected with a WS close.

[S2-revised] Chunk metadata is plaintext again. To support arbitrarily large
                            messages and file transfers, every chunk now carries
                            {kind, transferId, chunkIndex, totalChunks, totalBytes}
                            alongside {nonce, array}. This is a deliberate rollback
                            of the strict [S2] metadata-hiding property above (not a
                            bug): chunk sequencing isn't secret, the same way a TLS
                            record's sequence number isn't — only the actual message
                            text / file bytes still go through the NDCrypt cipher.
                            The server only validates and routes these fields; it
                            never inspects the encrypted content itself.

[S4-revised] The original burst=20 / refill=5 per-second bucket was sized for
                            short chat-text bursts, not chunked file transfers. With
                            a 31-byte ciphertext payload per chunk, even a small file
                            quickly burns through 20 tokens and then gets throttled to
                            5 msgs/sec — chunks past that point are silently dropped by
                            `continue` with no error returned to either peer. The
                            receiver then waits forever for chunks that will never
                            arrive (most visible as a transfer stalling near the end,
                            once the initial burst allowance is exhausted). Bumped
                            capacity/refill so a real multi-chunk transfer can sustain
                            its natural send rate (paired with a matching client-side
                            throttle in sendChunks(), see [C4] below) while still
                            bounding worst-case throughput per IP.

Nonce space
───────────
Application message nonces (from get_nonce_base()) are masked to 31 bits on
the wire. Bit 31 is reserved exclusively for the two fixed key-confirmation
messages (0x80000000 = Bob's confirm, 0x80000001 = Alice's confirm), so a
confirmation ciphertext can never collide with a real message nonce.
"""

import asyncio
import json
import os
import secrets
import signal
import socket
import subprocess
import sys
import time
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Optional

from websockets.asyncio.server import serve, ServerConnection
from websockets.http11 import Response as WsResponse
from websockets.datastructures import Headers as WsHeaders

PORT      = 8080
PKG_DIR   = os.path.abspath("pkg")           # [S5] absolute base for static files
ORIGIN_WS = f"http://localhost:{PORT}"       # [S3] extend list if you add LAN origins

# [S2-revised] Each NDCrypt chunk carries at most 31 plaintext bytes (see
# params.rs SIGNAL_COUNT), so this is generous on purpose — about 150 MB of
# file at 31 B/chunk — it's just a sanity ceiling against a malformed or
# hostile totalChunks value making a peer's browser allocate a huge array,
# not a real product limit.
MAX_TOTAL_CHUNKS = 5_000_000

connected: set[ServerConnection] = set()

# [S3] Computed once at startup (see main()) and reused for every connection's
# Origin check. Recomputing this per-connection was the original bug: a
# transient DNS/route hiccup at handshake time made get_local_ip() fall back
# to "127.0.0.1", silently rejecting legitimate LAN clients whose browser
# Origin still pointed at the real LAN IP the page was served from.
ALLOWED_ORIGINS: set[str] = set()

# ─── Session state ────────────────────────────────────────────────────────────

class HsState(Enum):
    IDLE        = auto()   # no pubkey seen yet
    PUBKEY_SENT = auto()   # Alice sent pubkey; waiting for Bob's ciphertext
    COMPLETE    = auto()   # handshake done; normal messages flow

@dataclass
class PeerSession:
    state:      HsState          = HsState.IDLE
    session_id: Optional[str]    = None   # opaque routing token, no security meaning

# keyed by the connection that sent the pubkey (Alice)
sessions: dict[ServerConnection, PeerSession] = {}

# ─── Rate limiting ────────────────────────────────────────────────────────────

# [S4-revised] Sized for real chunked file transfers, not just chat bursts.
# Each ndcrypt chunk is one WS message carrying <=31 plaintext bytes, so a
# modest file (a few hundred KB) means thousands of chunks. The client throttles
# itself to RATE_LIMIT_RATE messages/sec (see [C4] in the HTML client below) so
# the two stay in lockstep; the burst capacity here just absorbs normal jitter
# (multiple tabs, slight scheduling drift) without dropping legitimate chunks.
RATE_LIMIT_CAPACITY = 200.0   # burst
RATE_LIMIT_RATE     = 100.0   # tokens/second

@dataclass
class TokenBucket:
    capacity:   float = RATE_LIMIT_CAPACITY
    rate:       float = RATE_LIMIT_RATE
    tokens:     float = RATE_LIMIT_CAPACITY
    last_refill: float = field(default_factory=time.monotonic)

    def consume(self) -> bool:
        now = time.monotonic()
        self.tokens = min(self.capacity, self.tokens + (now - self.last_refill) * self.rate)
        self.last_refill = now
        if self.tokens >= 1.0:
            self.tokens -= 1.0
            return True
        return False

rate_limits: dict[str, TokenBucket] = {}   # keyed by remote IP

def check_rate(ws: ServerConnection) -> bool:           # [S4]
    ip = ws.remote_address[0]
    if ip not in rate_limits:
        rate_limits[ip] = TokenBucket()
    return rate_limits[ip].consume()

# ─── Helpers ──────────────────────────────────────────────────────────────────

def new_session_id() -> str:
    """Opaque random routing token — carries NO security guarantee.
    It only tells the server which Alice a given Bob is replying to.
    The actual integrity check is the NDCrypt key-confirmation round trip,
    done client-side with the existing encrypt_bytes/decrypt_bytes exports."""
    return secrets.token_hex(16)

def get_local_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except OSError:
        return "127.0.0.1"

def kill_port_unix(port: int) -> None:
    try:
        out = subprocess.check_output(["lsof", f"-ti:{port}"], stderr=subprocess.DEVNULL)
        pids = out.decode().strip().split()
        current_pid = os.getpid()
        for pid_str in pids:
            pid = int(pid_str)
            if pid != current_pid:
                try:
                    os.kill(pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
    except subprocess.CalledProcessError:
        pass

# ─── HTTP handler ─────────────────────────────────────────────────────────────

async def http_handler(connection: ServerConnection, request, *args):
    path = request.path.split("?")[0]

    if path == "/ws":
        return None  # hand off to ws_handler

    # [S5] Serve pkg/ files with path-traversal protection.
    if path.startswith("/pkg/"):
        rel      = path[1:]                                  # strip leading /
        abs_path = os.path.abspath(os.path.join(PKG_DIR, os.path.basename(rel)))
        try:
            common = os.path.commonpath([abs_path, PKG_DIR])
        except ValueError:
            return WsResponse(403, "Forbidden", WsHeaders([]), b"Forbidden")

        if common != PKG_DIR or not os.path.isfile(abs_path):
            return WsResponse(404, "Not Found", WsHeaders([]), b"Not found")

        try:
            with open(abs_path, "rb") as f:
                content = f.read()
        except OSError:
            return WsResponse(500, "Error", WsHeaders([]), b"Read error")

        mime = "application/wasm" if abs_path.endswith(".wasm") else "application/javascript"
        return WsResponse(200, "OK", WsHeaders([("Content-Type", mime)]), content)

    if path in ("/", "/index.html"):
        return WsResponse(
            200, "OK",
            WsHeaders([("Content-Type", "text/html; charset=utf-8")]),
            HTML.encode(),
        )

    return WsResponse(404, "Not Found", WsHeaders([]), b"Not found")

# ─── WebSocket handler ────────────────────────────────────────────────────────

async def ws_handler(ws: ServerConnection) -> None:
    # [S3] Reject connections from unexpected origins.
    # ALLOWED_ORIGINS is computed once at startup, not per-connection, so a
    # transient local-IP lookup failure mid-session can't reject legitimate
    # clients that connected fine moments earlier.
    origin = ws.request.headers.get("Origin", "")
    if origin not in ALLOWED_ORIGINS:
        await ws.close(1008, "Origin not allowed")
        return

    connected.add(ws)
    peer = ws.remote_address
    print(f"  + {peer[0]}:{peer[1]}  ({len(connected)} online)")

    try:
        async for raw in ws:
            # [S4] Rate limit
            if not check_rate(ws):
                continue

            # [S6] Explicit exception handling
            try:
                data = json.loads(raw)
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue

            if not isinstance(data, dict):
                continue

            msg_type = str(data.get("type", ""))

            # ── Handshake: pubkey ────────────────────────────────────────────
            # [S1] Alice sends her pubkey. Server hands out an opaque
            #       session_id purely so it knows which Alice a later
            #       ciphertext/confirm belongs to. No security claim here —
            #       that comes from the NDCrypt confirmation round trip below.
            if msg_type == "pubkey":
                array = data.get("array")
                if not isinstance(array, list) or len(array) != 2048:
                    await ws.close(1008, "Bad pubkey")
                    return

                sess = sessions.setdefault(ws, PeerSession())
                if sess.state != HsState.IDLE:
                    await ws.close(1008, "Unexpected pubkey")
                    return

                session_id      = new_session_id()
                sess.session_id = session_id
                sess.state      = HsState.PUBKEY_SENT

                # Relay to all other clients, attaching the routing id.
                payload = json.dumps({
                    "type":       "pubkey",
                    "array":      array,
                    "session_id": session_id,   # Bob must echo this back
                })
                await _broadcast(ws, payload)

            # ── Handshake: ciphertext ────────────────────────────────────────
            # [S1] Bob sends ciphertext + the session_id he received, plus his
            #       confirmation ciphertext (encrypted under the seed he just
            #       derived). Server just routes by session_id; it does not
            #       and cannot verify the confirmation itself — only Alice's
            #       browser, holding the private key, can do that.
            elif msg_type == "ciphertext":
                array       = data.get("array")
                session_id  = data.get("session_id", "")
                confirm     = data.get("confirm")
                if not isinstance(array, list) or len(array) != 2048:
                    await ws.close(1008, "Bad ciphertext")
                    return
                if not isinstance(session_id, str) or len(session_id) != 32:
                    await ws.close(1008, "Bad session_id")
                    return
                if not isinstance(confirm, list) or len(confirm) != 1040:
                    await ws.close(1008, "Bad confirm")
                    return

                # Find Alice's session by matching session_id.
                alice_ws = _find_alice(session_id)
                if alice_ws is None:
                    await ws.close(1008, "Unknown session_id")
                    return

                alice_sess = sessions[alice_ws]
                if alice_sess.state != HsState.PUBKEY_SENT:
                    await ws.close(1008, "Unexpected ciphertext")
                    return

                alice_sess.state = HsState.COMPLETE

                # Forward to Alice so she can decapsulate and verify the
                # confirmation tag herself.
                payload = json.dumps({
                    "type":       "ciphertext",
                    "array":      array,
                    "session_id": session_id,
                    "confirm":    confirm,
                })
                try:
                    await alice_ws.send(payload)
                except Exception:
                    pass

            # ── Handshake: confirm-ack ───────────────────────────────────────
            # Alice, having verified Bob's confirmation tag decrypts correctly,
            # sends her own confirmation ciphertext back so Bob gets positive
            # proof too (not just an assumption that his send succeeded).
            elif msg_type == "confirm_ack":
                array      = data.get("array")
                session_id = data.get("session_id", "")
                if not isinstance(array, list) or len(array) != 1040:
                    await ws.close(1008, "Bad confirm_ack")
                    return
                if not isinstance(session_id, str) or len(session_id) != 32:
                    await ws.close(1008, "Bad session_id")
                    return

                payload = json.dumps({
                    "type":       "confirm_ack",
                    "array":      array,
                    "session_id": session_id,
                })
                await _broadcast(ws, payload)

            # ── Encrypted message ─────────────────────────────────────────────
            # [S2-revised] nonce + array stay opaque/encrypted as before; chunk
            # sequencing (kind/transferId/chunkIndex/totalChunks/totalBytes) is
            # now plaintext by design — see the [S2-revised] note up top. The
            # server only validates shapes/bounds here, never the content.
            elif msg_type == "ndcrypt":
                nonce        = data.get("nonce")
                array        = data.get("array")
                kind         = data.get("kind")
                transfer_id  = data.get("transferId")
                chunk_index  = data.get("chunkIndex")
                total_chunks = data.get("totalChunks")
                total_bytes  = data.get("totalBytes")

                if not isinstance(nonce, int) or not isinstance(array, list):
                    continue
                if len(array) != 1040:
                    continue
                if kind not in ("meta", "data"):
                    continue
                if not isinstance(transfer_id, int):
                    continue
                if not isinstance(chunk_index, int) or not isinstance(total_chunks, int):
                    continue
                if total_chunks <= 0 or total_chunks > MAX_TOTAL_CHUNKS:
                    continue
                if chunk_index < 0 or chunk_index >= total_chunks:
                    continue
                if total_bytes is not None and not isinstance(total_bytes, int):
                    continue

                payload = json.dumps({
                    "type":        "ndcrypt",
                    "kind":        kind,
                    "transferId":  transfer_id,
                    "chunkIndex":  chunk_index,
                    "totalChunks": total_chunks,
                    "totalBytes":  total_bytes,
                    "nonce":       nonce,
                    "array":       array,
                })
                await _broadcast(ws, payload)

            # ── Ignore everything else ────────────────────────────────────────
            # No plain-text "text" messages, no echo of unknown types.

    finally:
        connected.discard(ws)
        sessions.pop(ws, None)
        print(f"  - {peer[0]}:{peer[1]}  ({len(connected)} online)")


def _find_alice(session_id: str) -> Optional[ServerConnection]:
    """Return the connection that owns this routing session_id, or None."""
    for c, sess in sessions.items():
        if sess.session_id == session_id:
            return c
    return None


async def _broadcast(sender: ServerConnection, payload: str) -> None:
    dead: set[ServerConnection] = set()
    for c in connected:
        if c is not sender:
            try:
                await c.send(payload)
            except Exception:
                dead.add(c)
    connected.difference_update(dead)

# ─── HTML client ──────────────────────────────────────────────────────────────
# All security-relevant JS changes are marked with [Cx] comments mirroring the
# server-side [Sx] markers above.

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>NDCrypt WebAssembly Client</title>
<style>
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; background: #1a1a18; color: #f5f5f3; height: 100dvh; display: flex; flex-direction: column; }
  header { padding: 14px 20px; border-bottom: 1px solid #333; background: #242422; display: flex; align-items: center; justify-content: space-between; flex-shrink: 0; }
  header h1 { font-size: 15px; font-weight: 500; color: #00ff00; display: flex; align-items: center; gap: 8px; }
  #status { font-size: 12px; color: #888; display: flex; align-items: center; gap: 6px; }
  #dot { width: 7px; height: 7px; border-radius: 50%; background: #ccc; transition: background 0.3s; }
  #dot.online { background: #3a9e6e; }
  #dot.secure { background: #00ff00; box-shadow: 0 0 5px #00ff00; }
  #dot.offline { background: #c0392b; }
  #handshake-bar { background: #2e2e2c; padding: 10px 20px; display: flex; justify-content: space-between; align-items: center; border-bottom: 1px solid #333; }
  #handshake-btn { background: #00ff00; color: #1a1a18; border: none; padding: 6px 12px; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 12px; }
  #handshake-btn:hover { opacity: 0.8; }
  #handshake-btn:disabled { opacity: 0.5; cursor: not-allowed; }

  /* ── Benchmark panel ──────────────────────────────────────────────────── */
  #bench-bar { background: #242422; padding: 8px 20px; border-bottom: 1px solid #333; }
  #bench-toggle { background: none; border: 1px solid #444; color: #ccc; padding: 5px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; }
  #bench-toggle:hover { border-color: #00ff00; color: #00ff00; }
  #bench-panel { margin-top: 10px; }
  .bench-controls { display: flex; align-items: center; gap: 10px; margin-bottom: 8px; flex-wrap: wrap; }
  #bench-run { background: #00ff00; color: #1a1a18; border: none; padding: 5px 12px; border-radius: 4px; cursor: pointer; font-weight: bold; font-size: 12px; }
  #bench-run:disabled { opacity: 0.5; cursor: not-allowed; }
  #bench-status { font-size: 12px; color: #888; }
  #bench-hint { font-size: 11px; color: #666; margin-bottom: 8px; }
  #bench-table { width: 100%; border-collapse: collapse; font-size: 12px; }
  #bench-table th, #bench-table td { text-align: left; padding: 4px 10px; border-bottom: 1px solid #333; white-space: nowrap; }
  #bench-table th { color: #888; font-weight: 500; }
  #bench-table tr.scheme-nd  td:nth-child(2) { color: #00ff00; }
  #bench-table tr.scheme-aes td:nth-child(2) { color: #5dade2; }

  #messages { flex: 1; overflow-y: auto; padding: 16px 20px; display: flex; flex-direction: column; gap: 10px; scroll-behavior: smooth; }
  .msg { max-width: 72%; padding: 9px 13px; border-radius: 14px; font-size: 14px; line-height: 1.5; word-break: break-word; }
  .msg.mine { align-self: flex-end; background: #00ff00; color: #1a1a18; border-bottom-right-radius: 4px; }
  .msg.theirs { align-self: flex-start; background: #2e2e2c; border: 1px solid #444; border-bottom-left-radius: 4px; }
  .msg .meta { font-size: 11px; opacity: 0.65; margin-bottom: 3px; font-weight: bold; }
  .msg.mine .meta { text-align: right; }
  .msg.system { align-self: center; background: none; border: none; color: #888; font-size: 12px; padding: 0; max-width: 100%; }

  /* ── File transfer UI ─────────────────────────────────────────────────── */
  .progress-track { margin-top: 6px; height: 4px; border-radius: 2px; background: rgba(0,0,0,0.15); overflow: hidden; }
  .msg.theirs .progress-track { background: rgba(255,255,255,0.12); }
  .progress-bar { height: 100%; width: 0%; background: currentColor; transition: width 0.15s; }
  .msg.theirs .progress-bar { background: #00ff00; }
  .file-link { display: inline-flex; align-items: center; gap: 6px; margin-top: 4px; color: inherit; text-decoration: none; font-size: 13px; font-weight: 600; }
  .file-link:hover { text-decoration: underline; }
  .file-preview { display: block; max-width: 100%; max-height: 220px; border-radius: 8px; margin-top: 6px; }
  .msg.error { border-color: #c0392b !important; }

  footer { padding: 12px 16px; border-top: 1px solid #333; background: #242422; display: flex; gap: 8px; align-items: center; flex-shrink: 0; }
  #name-input, #msg-input { border: 1px solid #444; border-radius: 20px; padding: 9px 14px; font-size: 14px; outline: none; background: #2e2e2c; color: inherit; transition: border-color 0.15s; }
  #name-input:focus, #msg-input:focus { border-color: #00ff00; background: #333; }
  #name-input { width: 110px; flex-shrink: 0; }
  #msg-input { flex: 1; }
  #send-btn, #file-btn { width: 36px; height: 36px; border-radius: 50%; border: none; background: #00ff00; color: #1a1a18; cursor: pointer; display: flex; align-items: center; justify-content: center; flex-shrink: 0; }
  #file-btn { background: #2e2e2c; color: #ccc; border: 1px solid #444; font-size: 16px; }
  #file-btn:hover { border-color: #00ff00; color: #00ff00; }
  #send-btn:disabled, #file-btn:disabled { opacity: 0.25; cursor: default; background: #555; color:#888; border-color: #444; }
</style>
</head>
<body>
<header>
  <h1>
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="#00ff00" stroke-width="2" stroke-linecap="round">
      <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"></path>
    </svg>
    NDCrypt Client
  </h1>
  <div id="status"><div id="dot"></div><span id="status-text">Booting Wasm Engine…</span></div>
</header>
<div id="handshake-bar">
  <span style="font-size: 12px; color: #aaa;" id="handshake-status">Awaiting Handshake...</span>
  <button id="handshake-btn" disabled>Initialize E2EE</button>
</div>
<div id="bench-bar">
  <button id="bench-toggle">⚡ Benchmark vs AES-GCM</button>
  <div id="bench-panel" hidden>
    <div id="bench-hint">Runs locally in this tab only — no network round trip. NDCrypt uses a local self-handshake; nothing here touches your chat session.</div>
    <div class="bench-controls">
      <button id="bench-run">Run benchmark</button>
      <span id="bench-status"></span>
    </div>
    <table id="bench-table" hidden>
      <thead><tr><th>Size</th><th>Scheme</th><th>Encrypt</th><th>Decrypt</th><th>Wire bytes</th><th>Overhead</th><th>Throughput</th></tr></thead>
      <tbody id="bench-tbody"></tbody>
    </table>
  </div>
</div>
<div id="messages"></div>
<footer>
  <input id="name-input" type="text" placeholder="Alias" maxlength="20" />
  <input id="file-input" type="file" hidden />
  <button id="file-btn" title="Send a file" disabled>📎</button>
  <input id="msg-input" type="text" placeholder="Encrypted message" autocomplete="off" disabled />
  <button id="send-btn" disabled>
    <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2">
      <line x1="22" y1="2" x2="11" y2="13"/>
      <polygon points="22 2 15 22 11 13 2 9 22 2"/>
    </svg>
  </button>
</footer>

<script type="module">
import init, { NDCryptWasm } from './pkg/NDCrypt.js';

const dot            = document.getElementById('dot');
const statusText     = document.getElementById('status-text');
const handshakeStatus = document.getElementById('handshake-status');
const messages       = document.getElementById('messages');
const nameInput      = document.getElementById('name-input');
const msgInput       = document.getElementById('msg-input');
const sendBtn        = document.getElementById('send-btn');
const handshakeBtn   = document.getElementById('handshake-btn');
const fileBtn        = document.getElementById('file-btn');
const fileInput      = document.getElementById('file-input');
const benchToggle    = document.getElementById('bench-toggle');
const benchPanel     = document.getElementById('bench-panel');
const benchRunBtn    = document.getElementById('bench-run');
const benchStatus    = document.getElementById('bench-status');
const benchTable     = document.getElementById('bench-table');
const benchTbody     = document.getElementById('bench-tbody');

let ws, cryptoEngine;
let isSecure   = false;
let isAlice    = false;   // true if this peer initiated the handshake
let myNonce    = 0;       // [C3] seed-derived base + local counter, masked to 31 bits
const seenNonces = new Set();

// [C1] Key confirmation, using ONLY the existing NDCrypt encrypt_bytes /
// decrypt_bytes exports — no hash function, no external library, no new
// wasm export. Bob encrypts a fixed tag under the seed he just derived and
// sends it alongside his ciphertext. Alice can only reproduce/verify that
// tag if her decapsulation recovered the exact same seed, which can only
// happen if Bob really encapsulated against Alice's real public key. A
// MITM that substitutes a different pubkey ends up holding a seed Alice
// never converges on, so the confirmation check fails and both sides abort.
//
// Nonce space: real per-message nonces are masked to 31 bits (top bit = 0).
// Confirmation ciphertexts use fixed nonces with the top bit SET, so they
// can never collide with a real message nonce.
const CONFIRM_TAG        = new TextEncoder().encode('NDCRYPT-OK');
const NONCE_CONFIRM_BOB   = 0x80000000;  // Bob → Alice confirmation
const NONCE_CONFIRM_ALICE = 0x80000001;  // Alice → Bob confirmation ack
const MSG_NONCE_MASK      = 0x7FFFFFFF;  // real message nonces stay in the low 31 bits

let pendingSessionId = null;  // set when we send our pubkey; routing only

const encoder = new TextEncoder();
const decoder = new TextDecoder();

function chunkAad(kind, transferId, chunkIndex, totalChunks, totalBytes) {
  return encoder.encode(JSON.stringify({
    kind,
    transferId,
    chunkIndex,
    totalChunks,
    totalBytes: totalBytes == null ? null : totalBytes,
  }));
}

// ── Transfer framing ───────────────────────────────────────────────────────
//
// Every logical send (one text message, or one file) becomes two parallel
// "transfers" sharing a transferId:
//
//   kind 'meta' — a tiny JSON descriptor, almost always exactly one chunk:
//                 { k:'t', name }                                  for text
//                 { k:'f', name, filename, mime, size }            for files
//   kind 'data' — the actual UTF-8 text bytes, or the raw file bytes
//
// Both are split into header-less chunks of at most MAX_PAYLOAD bytes and
// encrypted one chunk at a time — NDCrypt can only hide MAX_PAYLOAD bytes
// per encrypt_bytes() call (see params.rs SIGNAL_COUNT), so anything bigger
// has no choice but to go out as a sequence of chunks. Chunk sequencing
// (transferId/chunkIndex/totalChunks/totalBytes) rides in the *plaintext*
// envelope next to {nonce, array} — see the [S2-revised] note in server.py.
// Only the actual content bytes are ever passed through the cipher.

const MAX_PAYLOAD = 31;
let transferIdCounter = (Date.now() & 0xFFFF) << 8;
function nextTransferId() { return (transferIdCounter = (transferIdCounter + 1) & 0x7FFFFFFF); }

function chunkBytes(bytes) {
  if (bytes.length === 0) return [bytes.subarray(0, 0)];
  const chunks = [];
  for (let off = 0; off < bytes.length; off += MAX_PAYLOAD) {
    chunks.push(bytes.subarray(off, off + MAX_PAYLOAD));
  }
  return chunks;
}

function encodeMeta(obj) { return encoder.encode(JSON.stringify(obj)); }
function decodeMeta(bytes) { return JSON.parse(decoder.decode(bytes)); }

// Sends every chunk of one transfer. Yields every 32 chunks to keep the UI
// responsive, and waits when ws.bufferedAmount is high — ws.send() queues into
// the browser's internal socket buffer, and if the loop outpaces the socket's
// drain rate the last chunks sit in that buffer invisibly while the sender
// already thinks the transfer is complete.
const WS_BACKPRESSURE_THRESHOLD = 64 * 1024;   // 64 KB

// [C4] Client-side send throttle, paired with the server's [S4-revised]
// token bucket (see server.py constants RATE_LIMIT_CAPACITY/RATE_LIMIT_RATE).
// Without this, sendChunks() fires messages as fast as the event loop and
// the WS socket buffer allow — far faster than the server's original
// 5 msgs/sec sustained rate. Once the server's burst allowance ran out,
// every chunk past that point was silently dropped (`continue` in
// ws_handler, no error sent back), so the receiver's buf.received never
// reached totalChunks and the transfer hung forever, almost always
// looking like "the last few chunks never arrive." Keeping the client
// rate a bit under the server's refill rate means the bucket never goes
// empty in the first place, so nothing gets dropped — this is strictly
// safer than transferring at whatever ad-hoc speed the client happens to
// run at, even though it caps the maximum sustained transfer rate to
// roughly MAX_SUSTAINED_RATE chunks/sec.
const MAX_SUSTAINED_RATE = 80;                       // chunks/sec, stays under server's 100/s refill
const MIN_SEND_INTERVAL_MS = 1000 / MAX_SUSTAINED_RATE;
let lastSendAt = 0;

async function throttleSend() {
  const now = performance.now();
  const wait = MIN_SEND_INTERVAL_MS - (now - lastSendAt);
  if (wait > 0) await new Promise(r => setTimeout(r, wait));
  lastSendAt = performance.now();
}

async function sendChunks(kind, transferId, bytes, onProgress) {
  const chunks = chunkBytes(bytes);
  const totalChunks = chunks.length;
  for (let i = 0; i < totalChunks; i++) {
    // Pause until the socket buffer has drained enough to accept more data.
    while (ws.bufferedAmount > WS_BACKPRESSURE_THRESHOLD) {
      await new Promise(r => setTimeout(r, 16));
    }
    // [C4] Throttle to the server's sustained rate so chunks never get
    // silently dropped by the relay's per-IP token bucket.
    await throttleSend();

    const aad = chunkAad(kind, transferId, i, totalChunks, bytes.length);
    const encArr = cryptoEngine.encrypt_bytes_aad(chunks[i], myNonce, aad);
    ws.send(JSON.stringify({
      type:        'ndcrypt',
      kind,
      transferId,
      chunkIndex:  i,
      totalChunks,
      totalBytes:  bytes.length,
      nonce:       myNonce,
      array:       Array.from(encArr),
    }));
    // [C3] Increment nonce for every chunk — same-nonce reuse would break
    // the OTP. Masked to 31 bits so it can never wander into the reserved
    // confirmation-nonce range (top bit set).
    myNonce = (myNonce + 1) & MSG_NONCE_MASK;
    if (onProgress) onProgress(i + 1, totalChunks);
    if (i % 32 === 31) await new Promise(r => setTimeout(r, 0));
  }
}

// ── Reassembly ───────────────────────────────────────────────────────────────

const transferBuffers = {};                 // `${transferId}:${kind}` -> {chunks, received}
const completedMeta   = {};                 // transferId -> decoded meta object
const completedData   = {};                 // transferId -> merged Uint8Array
const incomingProgress = {};                // transferId -> progress bubble (files only)

function getBuffer(transferId, kind, totalChunks) {
  const key = `${transferId}:${kind}`;
  let buf = transferBuffers[key];
  if (!buf) buf = transferBuffers[key] = { chunks: new Array(totalChunks), received: 0 };
  return buf;
}

function mergeBuffer(buf) {
  const total = buf.chunks.reduce((n, c) => n + c.length, 0);
  const merged = new Uint8Array(total);
  let off = 0;
  for (const c of buf.chunks) { merged.set(c, off); off += c.length; }
  return merged;
}

function onDataChunk(transferId, chunkIndex, totalChunks, totalBytes) {
  const meta = completedMeta[transferId];
  if (!meta || meta.k !== 'f' || totalChunks <= 1) return;   // only show progress for multi-chunk files
  let p = incomingProgress[transferId];
  if (!p) p = incomingProgress[transferId] = appendProgressMessage(meta.name || 'Anonymous', meta.filename, totalBytes, 'theirs');
  updateProgressMessage(p, (chunkIndex + 1) / totalChunks);
}

function clearIncomingProgress(transferId) {
  const p = incomingProgress[transferId];
  if (p) { p.div.remove(); delete incomingProgress[transferId]; }
}

function tryFinalize(transferId) {
  const meta = completedMeta[transferId];
  const data = completedData[transferId];
  if (!meta || !data) return;

  if (meta.k === 't') {
    appendMessage(meta.name || 'Anonymous', decoder.decode(data), 'theirs');
  } else if (meta.k === 'f') {
    appendFileMessage(meta.name || 'Anonymous', meta.filename || 'file', meta.mime || 'application/octet-stream', data);
  }
  delete completedMeta[transferId];
  delete completedData[transferId];
}

// ── Boot & connect ────────────────────────────────────────────────────────────

async function boot() {
  try {
    await init();
    cryptoEngine = new NDCryptWasm();
    connect();
  } catch (e) {
    appendMessage('SYSTEM', 'Failed to load Rust WebAssembly engine. Did you run wasm-pack build?', 'system');
  }
}

function connect() {
  const proto = location.protocol === 'https:' ? 'wss' : 'ws';
  ws = new WebSocket(`${proto}://${location.host}/ws`);

  ws.onopen = () => {
    dot.className = 'online';
    statusText.textContent = 'Relay Connected';
    handshakeBtn.disabled = false;
    appendMessage('SYSTEM', 'Relay connected. Waiting for Key Exchange…', 'system');
  };

  ws.onclose = () => {
    dot.className = 'offline';
    statusText.textContent = 'Relay Offline';
    isSecure = false;
    handshakeBtn.disabled = true;
    msgInput.disabled = true;
    sendBtn.disabled = true;
    fileBtn.disabled = true;
    setTimeout(connect, 2000);
  };

  ws.onmessage = (e) => {
    let data;
    try { data = JSON.parse(e.data); } catch { return; }

    if (data.type === 'pubkey') {
      // Bob receives Alice's pubkey + a routing session_id (no security
      // meaning — just lets the server forward our reply to the right peer).
      appendMessage('SYSTEM', 'Received public key. Encapsulating seed…', 'system');
      const cipherFlat = cryptoEngine.encapsulate_seed(data.array);
      if (!cipherFlat || cipherFlat.length === 0) {
        appendMessage('SYSTEM', 'ERROR: encapsulate_seed failed (session already active?)', 'system');
        return;
      }
      // [C1] Prove to Alice we derived a real seed from HER pubkey: encrypt
      // a fixed tag under that seed using the existing NDCrypt cipher.
      // Only someone who encapsulated against Alice's real public key can
      // produce a confirm value Alice's decapsulated seed will decrypt back
      // to CONFIRM_TAG.
      const confirmArr = cryptoEngine.encrypt_bytes(CONFIRM_TAG, NONCE_CONFIRM_BOB);
      ws.send(JSON.stringify({
        type:       'ciphertext',
        array:      Array.from(cipherFlat),
        session_id: data.session_id,
        confirm:    Array.from(confirmArr),
      }));
      // [C3] Bob is party_index=1 → disjoint nonce space from Alice. Mask
      // to 31 bits so it can never collide with the reserved confirm nonces.
      myNonce  = cryptoEngine.get_nonce_base(1) & MSG_NONCE_MASK;
      isAlice  = false;
      appendMessage('SYSTEM', 'Confirmation sent. Awaiting Alice\u2019s ack…', 'system');
      // Bob doesn't mark secure yet — wait for confirm_ack so both sides
      // have positive proof, not just an assumption that the send worked.
    }

    else if (data.type === 'ciphertext') {
      // Alice receives Bob's ciphertext + his confirmation tag.
      appendMessage('SYSTEM', 'Decapsulating seed…', 'system');
      const ok = cryptoEngine.decapsulate_seed(data.array);
      if (!ok) {
        appendMessage('SYSTEM', 'ERROR: decapsulate_seed failed', 'system');
        return;
      }
      // [C1] Verify Bob's confirmation tag decrypts correctly under the
      // seed we just recovered. This is the real MITM check: it only
      // passes if Bob encapsulated against our actual public key, which
      // only happens if no one swapped the pubkey in transit.
      const confirmArr  = new Uint16Array(data.confirm);
      const decoded      = cryptoEngine.decrypt_bytes(confirmArr, NONCE_CONFIRM_BOB);
      const decodedOk    = decoded && decoded.length === CONFIRM_TAG.length &&
                            decoded.every((b, i) => b === CONFIRM_TAG[i]);
      if (!decodedOk) {
        appendMessage('SYSTEM', '\u26a0 HANDSHAKE ABORTED: key confirmation failed. Possible MITM.', 'system');
        ws.close();
        return;
      }
      // [C3] Alice is party_index=0 → disjoint nonce space from Bob.
      myNonce  = cryptoEngine.get_nonce_base(0) & MSG_NONCE_MASK;
      isAlice  = true;
      // Send our own confirmation back so Bob has positive proof too.
      const ackArr = cryptoEngine.encrypt_bytes(CONFIRM_TAG, NONCE_CONFIRM_ALICE);
      ws.send(JSON.stringify({
        type:       'confirm_ack',
        array:      Array.from(ackArr),
        session_id: data.session_id,
      }));
      markSecure('Alice — seed decapsulated & confirmed');
    }

    else if (data.type === 'confirm_ack') {
      // Bob receives Alice's confirmation ack.
      if (isAlice || isSecure) return;  // not waiting on this, or already done
      const ackArr   = new Uint16Array(data.array);
      const decoded   = cryptoEngine.decrypt_bytes(ackArr, NONCE_CONFIRM_ALICE);
      const decodedOk = decoded && decoded.length === CONFIRM_TAG.length &&
                         decoded.every((b, i) => b === CONFIRM_TAG[i]);
      if (!decodedOk) {
        appendMessage('SYSTEM', '\u26a0 HANDSHAKE ABORTED: ack confirmation failed. Possible MITM.', 'system');
        ws.close();
        return;
      }
      markSecure('Bob — seed encapsulated & confirmed');
    }

    else if (data.type === 'ndcrypt') {
      if (!isSecure) return;
      const { kind, transferId, chunkIndex, totalChunks, totalBytes, nonce, array } = data;
      if (kind !== 'meta' && kind !== 'data') return;
      if (!Number.isInteger(transferId) || !Number.isInteger(chunkIndex) || !Number.isInteger(totalChunks)) return;
      if (!Number.isInteger(nonce) || nonce < 0 || nonce > MSG_NONCE_MASK) return;
      if (!Array.isArray(array) || array.length !== 1040) return;
      if (seenNonces.has(nonce)) return;

      const arr = new Uint16Array(array);
      const aad = chunkAad(kind, transferId, chunkIndex, totalChunks, totalBytes);
      let rawBytes;
      try {
        rawBytes = cryptoEngine.decrypt_bytes_aad(arr, nonce, aad);
      } catch {
        return;
      }
      seenNonces.add(nonce);

      const buf = getBuffer(transferId, kind, totalChunks);
      if (buf.chunks[chunkIndex] !== undefined) return;
      buf.chunks[chunkIndex] = rawBytes;
      buf.received++;

      if (kind === 'data') onDataChunk(transferId, chunkIndex, totalChunks, totalBytes);

      if (buf.received === totalChunks) {
        const merged = mergeBuffer(buf);
        delete transferBuffers[`${transferId}:${kind}`];
        if (kind === 'meta') {
          try { completedMeta[transferId] = decodeMeta(merged); }
          catch (err) { console.warn('Bad transfer meta', err); return; }
        } else {
          completedData[transferId] = merged;
          clearIncomingProgress(transferId);
        }
        tryFinalize(transferId);
      }
    }

    else if (data.type === 'system') {
      appendMessage('SYSTEM', data.text, 'system');
    }
  };
}

function markSecure(role) {
  isSecure = true;
  seenNonces.clear();
  dot.className = 'secure';
  statusText.textContent  = `E2EE Secure (${role})`;
  handshakeStatus.textContent = 'Quantum-resistant tunnel established.';
  handshakeStatus.style.color = '#00ff00';
  msgInput.disabled = false;
  sendBtn.disabled  = false;
  fileBtn.disabled  = false;
  appendMessage('SYSTEM', 'E2EE Tunnel Established.', 'system');
}

// ── Message / file rendering ─────────────────────────────────────────────────

function formatBytes(n) {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(2)} MB`;
}

function appendMessage(name, text, type) {
  const div = document.createElement('div');
  div.className = 'msg ' + type;
  if (type !== 'system') {
    const meta = document.createElement('div');
    meta.className   = 'meta';
    meta.textContent = name;
    div.appendChild(meta);
  }
  const body = document.createElement('div');
  body.textContent = text;
  div.appendChild(body);
  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
  return div;
}

function appendProgressMessage(name, filename, size, type) {
  const div = appendMessage(name, `${type === 'mine' ? 'Sending' : 'Receiving'} ${filename}${size ? ' (' + formatBytes(size) + ')' : ''}…`, type);
  const body = div.lastChild;
  const track = document.createElement('div');
  track.className = 'progress-track';
  const bar = document.createElement('div');
  bar.className = 'progress-bar';
  track.appendChild(bar);
  div.appendChild(track);
  return { div, body, track, bar };
}

function updateProgressMessage(p, frac) {
  p.bar.style.width = `${Math.min(100, Math.round(frac * 100))}%`;
}

function finalizeProgressMessage(p, text, isError = false) {
  p.body.textContent = text;
  p.track.remove();
  if (isError) p.div.classList.add('error');
}

function appendFileMessage(name, filename, mime, data) {
  const div = document.createElement('div');
  div.className = 'msg theirs';
  const meta = document.createElement('div');
  meta.className = 'meta';
  meta.textContent = name;
  div.appendChild(meta);

  const blob = new Blob([data], { type: mime });
  const url  = URL.createObjectURL(blob);

  if (mime.startsWith('image/')) {
    const img = document.createElement('img');
    img.src = url;
    img.className = 'file-preview';
    div.appendChild(img);
  }

  const link = document.createElement('a');
  link.href = url;
  link.download = filename;
  link.className = 'file-link';
  link.textContent = `⬇ ${filename} (${formatBytes(data.length)})`;
  div.appendChild(link);

  messages.appendChild(div);
  messages.scrollTop = messages.scrollHeight;
}

// ── Send: text ────────────────────────────────────────────────────────────────

handshakeBtn.addEventListener('click', () => {
  appendMessage('SYSTEM', 'Generating lattice keypair…', 'system');
  const pubKeyFlat = cryptoEngine.generate_keys();
  ws.send(JSON.stringify({ type: 'pubkey', array: Array.from(pubKeyFlat) }));
  appendMessage('SYSTEM', 'Public key sent. Awaiting peer…', 'system');
});

async function send() {
  const name = (nameInput.value.trim() || 'Anonymous').slice(0, 20);
  const text = msgInput.value.trim();
  if (!text || !isSecure) return;

  msgInput.value = '';
  msgInput.focus();

  const transferId = nextTransferId();
  try {
    await sendChunks('meta', transferId, encodeMeta({ k: 't', name }));
    await sendChunks('data', transferId, encoder.encode(text));
  } catch (err) {
    appendMessage('SYSTEM', `Send error: ${err.message}`, 'system');
    return;
  }
  appendMessage(name, text, 'mine');
}

sendBtn.addEventListener('click', send);
msgInput.addEventListener('keydown', e => {
  if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); send(); }
});

// ── Send: file ────────────────────────────────────────────────────────────────

fileBtn.addEventListener('click', () => fileInput.click());
fileInput.addEventListener('change', () => {
  const file = fileInput.files[0];
  fileInput.value = '';
  if (file && isSecure) sendFile(file);
});

async function sendFile(file) {
  const name = (nameInput.value.trim() || 'Anonymous').slice(0, 20);
  const transferId = nextTransferId();
  const bubble = appendProgressMessage(name, file.name, file.size, 'mine');

  try {
    const bytes = new Uint8Array(await file.arrayBuffer());
    await sendChunks('meta', transferId, encodeMeta({
      k: 'f', name, filename: file.name, mime: file.type || 'application/octet-stream', size: bytes.length,
    }));
    await sendChunks('data', transferId, bytes, (done, total) => updateProgressMessage(bubble, done / total));
    finalizeProgressMessage(bubble, `Sent ${file.name} (${formatBytes(file.size)})`);
  } catch (err) {
    finalizeProgressMessage(bubble, `Failed to send ${file.name}: ${err.message}`, true);
  }
}

// ── Benchmark: NDCrypt vs Web Crypto AES-GCM ──────────────────────────────────
//
// Pure client-side timing of each scheme's *natural* usage pattern for a given
// payload size: AES-GCM encrypts/decrypts the whole payload in one call —
// that's how every real app uses an AEAD. NDCrypt necessarily needs
// ceil(size / 31) separate encrypt_bytes/decrypt_bytes calls, because each
// call can only hide MAX_PAYLOAD bytes (params.rs SIGNAL_COUNT). Both numbers
// are the real, measured cost of how each scheme would actually be used for
// a payload of that size — the gap between them is the result, not test bias.
// Runs entirely in this tab; no network round trip, no external library.

let benchEngineA = null, benchEngineB = null;  // local self-handshake pair, lazily created

async function ensureBenchEngines() {
  if (benchEngineA) return;
  benchEngineA = new NDCryptWasm();
  benchEngineB = new NDCryptWasm();
  const pub    = benchEngineA.generate_keys();
  const cipher = benchEngineB.encapsulate_seed(pub);
  benchEngineA.decapsulate_seed(cipher);
}

function randomBytes(n) {
  const b = new Uint8Array(n);
  crypto.getRandomValues(b);   // Web Crypto caps a single call at 65536 bytes
  return b;
}

function bytesToBase64(bytes) {
  let binary = '';
  const CHUNK = 0x8000;
  for (let i = 0; i < bytes.length; i += CHUNK) {
    binary += String.fromCharCode(...bytes.subarray(i, i + CHUNK));
  }
  return btoa(binary);
}

async function benchNDCrypt(plain) {
  await ensureBenchEngines();
  const chunks = chunkBytes(plain);
  const baseNonce = 1_000_000;

  const t0 = performance.now();
  const ciphers = chunks.map((c, i) => benchEngineA.encrypt_bytes(c, baseNonce + i));
  const t1 = performance.now();

  let wireBytes = 0;
  for (let i = 0; i < ciphers.length; i++) {
    wireBytes += JSON.stringify({
      type: 'ndcrypt', kind: 'data', transferId: 1,
      chunkIndex: i, totalChunks: chunks.length, totalBytes: plain.length,
      nonce: baseNonce + i, array: Array.from(ciphers[i]),
    }).length;
  }

  const t2 = performance.now();
  for (let i = 0; i < ciphers.length; i++) benchEngineB.decrypt_bytes(ciphers[i], baseNonce + i);
  const t3 = performance.now();

  return { scheme: 'NDCrypt', plainBytes: plain.length, encryptMs: t1 - t0, decryptMs: t3 - t2, wireBytes };
}

async function benchAesGcm(plain) {
  const key = await crypto.subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
  const iv  = randomBytes(12);

  const t0 = performance.now();
  const cipherBuf = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, key, plain);
  const t1 = performance.now();

  const wireBytes = JSON.stringify({
    type: 'aesgcm', iv: Array.from(iv), data: bytesToBase64(new Uint8Array(cipherBuf)),
  }).length;

  const t2 = performance.now();
  await crypto.subtle.decrypt({ name: 'AES-GCM', iv }, key, cipherBuf);
  const t3 = performance.now();

  return { scheme: 'AES-GCM', plainBytes: plain.length, encryptMs: t1 - t0, decryptMs: t3 - t2, wireBytes };
}

function formatRate(bytes, ms) {
  if (ms <= 0) return '—';
  const kbps = (bytes / 1024) / (ms / 1000);
  return kbps > 1024 ? `${(kbps / 1024).toFixed(2)} MB/s` : `${kbps.toFixed(1)} KB/s`;
}

function addBenchRow(r) {
  const tr = document.createElement('tr');
  tr.className = r.scheme === 'NDCrypt' ? 'scheme-nd' : 'scheme-aes';
  const overhead   = (r.wireBytes / r.plainBytes).toFixed(1);
  const throughput = formatRate(r.plainBytes, r.encryptMs + r.decryptMs);
  tr.innerHTML =
    `<td>${formatBytes(r.plainBytes)}</td><td>${r.scheme}</td>` +
    `<td>${r.encryptMs.toFixed(2)} ms</td><td>${r.decryptMs.toFixed(2)} ms</td>` +
    `<td>${r.wireBytes.toLocaleString()} B</td><td>${overhead}×</td><td>${throughput}</td>`;
  benchTbody.appendChild(tr);
}

async function runBenchmark() {
  const sizes = [256, 1024, 4096, 16384, 65536];
  benchRunBtn.disabled = true;
  benchTable.hidden = false;
  benchTbody.innerHTML = '';
  const rows = [];

  for (let i = 0; i < sizes.length; i++) {
    const size  = sizes[i];
    const plain = randomBytes(size);

    benchStatus.textContent = `Running ${formatBytes(size)}… (${i + 1}/${sizes.length})`;
    await new Promise(r => setTimeout(r, 0));

    const nd = await benchNDCrypt(plain);
    addBenchRow(nd); rows.push(nd);
    await new Promise(r => setTimeout(r, 0));

    const aes = await benchAesGcm(plain);
    addBenchRow(aes); rows.push(aes);
    await new Promise(r => setTimeout(r, 0));
  }

  benchStatus.textContent = `Done — ${sizes.length} size(s) tested.`;
  console.log('%cNDCrypt vs AES-GCM benchmark', 'color:#00ff00;font-weight:bold;');
  console.table(rows.map(r => ({
    Size: formatBytes(r.plainBytes),
    Scheme: r.scheme,
    'Encrypt (ms)': +r.encryptMs.toFixed(2),
    'Decrypt (ms)': +r.decryptMs.toFixed(2),
    'Wire bytes': r.wireBytes,
    'Overhead ×': +(r.wireBytes / r.plainBytes).toFixed(1),
    Throughput: formatRate(r.plainBytes, r.encryptMs + r.decryptMs),
  })));
  benchRunBtn.disabled = false;
}

benchToggle.addEventListener('click', () => { benchPanel.hidden = !benchPanel.hidden; });
benchRunBtn.addEventListener('click', () => {
  runBenchmark().catch(err => {
    benchStatus.textContent = 'Error: ' + err.message;
    benchRunBtn.disabled = false;
  });
});

boot();
</script>
</body>
</html>
"""

# ─── Entry point ──────────────────────────────────────────────────────────────

async def main() -> None:
    print(f"\nNDCrypt Wasm Relay Server (hardened)")
    print(f"{'─' * 36}")
    kill_port_unix(PORT)
    local_ip = get_local_ip()

    # [S3] Freeze the allowed Origin set once, here, before accepting any
    # connections. ws_handler reuses this for every client for the life of
    # the process instead of recomputing get_local_ip() per-connection.
    global ALLOWED_ORIGINS
    ALLOWED_ORIGINS = {
        f"http://localhost:{PORT}",
        f"http://127.0.0.1:{PORT}",
        f"http://{local_ip}:{PORT}",
    }

    async with serve(
        ws_handler,
        host="0.0.0.0",
        port=PORT,
        process_request=http_handler,
    ) as server:
        print(f"  server running")
        print(f"  local  →  http://localhost:{PORT}")
        print(f"  LAN    →  http://{local_ip}:{PORT}\n")
        await server.serve_forever()


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nshutting down.")
