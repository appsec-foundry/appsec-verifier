"""The SSRF callback listener (VER-012, VER-018).

An SSRF finding is confirmed only by a request that arrives here carrying the
finding's marker: the agent makes the target fetch `url_for(marker)`, and the
listener, not the model, observes the hit. The Verifier itself never contacts
the listener (the scope guard refuses it as a target).

The listener binds only to a loopback address from the scope's `callback.host`
and `callback.port`. A target on another machine reaches it through a
TLS-terminating proxy or tunnel the operator runs; `callback.base_url` then
names that proxy and must be https. A plain-http `base_url` is accepted only
when its host is loopback too, so probe traffic never leaves the machine
unencrypted (VER-018).

It answers every request with an empty 204 and reads no request body. It keeps
only the time, method and source address of a request whose target contains a
marker (`vrf` and 16 hex digits), never its headers, body or full path, and
caps how many it keeps, so an unrelated or hostile client cannot grow it.
"""

from __future__ import annotations

import re
import socket
import threading
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

from ..scope.guard import is_loopback as _loopback

_MARKER = re.compile(r"vrf[0-9a-f]{16}")
_MAX_MARKERS = 256
_MAX_HITS = 20
_SOCKET_TIMEOUT = 5


class CallbackUnavailable(Exception):
    """The scope's callback cannot be served safely; SSRF findings stay unconfirmed."""


class _ServerV6(ThreadingHTTPServer):
    address_family = socket.AF_INET6


class CallbackListener:
    def __init__(self, callback: dict | None):
        callback = callback or {}
        host, port, base_url = callback.get("host"), callback.get("port"), callback.get("base_url")
        if not host or not port or not base_url:
            raise CallbackUnavailable("the scope's callback needs host, port and base_url")
        if not _loopback(host):
            raise CallbackUnavailable(f"the listener binds only to loopback, not {host!r}; reach it from another "
                                      "machine through a TLS-terminating proxy named in callback.base_url")
        try:
            parts = urlsplit(base_url)
            scheme, base_host = parts.scheme.lower(), parts.hostname
        except ValueError as exc:
            raise CallbackUnavailable("callback.base_url is not a URL") from exc
        if scheme not in ("http", "https") or not base_host:
            raise CallbackUnavailable("callback.base_url must be an http(s) URL with a host")
        if scheme == "http" and not _loopback(base_host):
            raise CallbackUnavailable("callback.base_url must be https unless its host is loopback, so probe "
                                      "traffic does not leave the machine unencrypted")
        self.host, self.port, self.base_url = str(host).strip("[]"), int(port), base_url.rstrip("/")
        self._hits: dict[str, list[dict]] = {}
        self._changed = threading.Condition()
        self._server: ThreadingHTTPServer | None = None

    def start(self) -> None:
        """Bind and serve in a background thread. Raises OSError when the port cannot be bound."""
        listener = self

        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.0"          # one request per connection
            timeout = _SOCKET_TIMEOUT

            def _answer(self):
                listener._record(self.path, self.command, self.client_address[0])
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()

            do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = _answer

            def log_message(self, *args):          # no request lines on the console
                pass

        server_cls = _ServerV6 if ":" in self.host else ThreadingHTTPServer
        self._server = server_cls((self.host, self.port), Handler)
        self._server.daemon_threads = True
        threading.Thread(target=self._server.serve_forever, name="callback-listener", daemon=True).start()

    def close(self) -> None:
        if self._server is not None:
            self._server.shutdown()
            self._server.server_close()
            self._server = None

    def url_for(self, marker: str) -> str:
        return f"{self.base_url}/{marker}"

    def _record(self, target: str, method: str, source: str) -> None:
        match = _MARKER.search(target or "")
        if match is None:
            return
        with self._changed:
            hits = self._hits.get(match.group())
            if hits is None:
                if len(self._hits) >= _MAX_MARKERS:
                    return
                hits = self._hits[match.group()] = []
            if len(hits) < _MAX_HITS:
                hits.append({"at": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                             "method": str(method)[:16], "source": str(source)[:64]})
                self._changed.notify_all()

    def hits(self, marker: str) -> list[dict]:
        with self._changed:
            return [dict(h) for h in self._hits.get(marker, [])]

    def wait_for(self, marker: str, timeout: float) -> bool:
        """Whether a request with `marker` has arrived, waiting up to `timeout` seconds for one."""
        with self._changed:
            return self._changed.wait_for(lambda: bool(self._hits.get(marker)), timeout=timeout)
