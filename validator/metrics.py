"""
Lightweight metrics & health server for the exploit subnet.

Exposes a simple HTTP endpoint that serves JSON metrics and a ``/health``
readiness probe.  No external dependencies (uses the stdlib
``http.server``).

Usage (standalone):
    python -m validator.metrics --port 9946

Programmatic:
    from validator.metrics import MetricsServer
    srv = MetricsServer(port=9946)
    srv.start()            # runs in a background daemon thread
    srv.inc("validations_total")
    srv.observe("validation_latency_ms", 142)
    srv.stop()

Endpoints:
    GET /health   →  {"status": "ok"}
    GET /metrics  →  {"validations_total": 5, ...}
"""

from __future__ import annotations

import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Optional


class _MetricsStore:
    """Thread-safe in-memory metrics store."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._counters: dict[str, int] = {}
        self._gauges: dict[str, float] = {}
        self._histograms: dict[str, list[float]] = {}
        self._start_time = time.monotonic()

    # ── Counters ──────────────────────────────────────────────────────

    def inc(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0) + amount

    def get_counter(self, name: str) -> int:
        with self._lock:
            return self._counters.get(name, 0)

    # ── Gauges ────────────────────────────────────────────────────────

    def set_gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = value

    def get_gauge(self, name: str) -> float:
        with self._lock:
            return self._gauges.get(name, 0.0)

    # ── Histograms (rolling last 1000 observations) ──────────────────

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            buf = self._histograms.setdefault(name, [])
            buf.append(value)
            if len(buf) > 1000:
                del buf[: len(buf) - 1000]

    # ── Snapshot ──────────────────────────────────────────────────────

    def snapshot(self) -> dict:
        with self._lock:
            snap: dict = {}
            snap.update(self._counters)
            snap.update(self._gauges)
            for name, buf in self._histograms.items():
                if buf:
                    sorted_buf = sorted(buf)
                    n = len(sorted_buf)
                    snap[f"{name}_count"] = n
                    snap[f"{name}_mean"] = round(sum(sorted_buf) / n, 2)
                    snap[f"{name}_p50"] = sorted_buf[(n - 1) // 2]
                    snap[f"{name}_p99"] = sorted_buf[min(n - 1, int(n * 0.99))]
            snap["uptime_seconds"] = round(time.monotonic() - self._start_time, 1)
            return snap


# Module-level singleton so any part of the app can record metrics.
_global_store = _MetricsStore()


def inc(name: str, amount: int = 1) -> None:
    """Increment a counter on the global metrics store."""
    _global_store.inc(name, amount)


def set_gauge(name: str, value: float) -> None:
    """Set a gauge on the global metrics store."""
    _global_store.set_gauge(name, value)


def observe(name: str, value: float) -> None:
    """Record an observation on the global metrics store."""
    _global_store.observe(name, value)


def snapshot() -> dict:
    """Return a snapshot of all metrics."""
    return _global_store.snapshot()


# ── HTTP Handler ──────────────────────────────────────────────────────────────

class _Handler(BaseHTTPRequestHandler):
    """Tiny HTTP handler for /health and /metrics."""

    def do_GET(self) -> None:  # noqa: N802
        if self.path == "/health":
            self._json_response(200, {"status": "ok"})
        elif self.path == "/metrics":
            self._json_response(200, _global_store.snapshot())
        else:
            self._json_response(404, {"error": "not found"})

    def _json_response(self, code: int, body: dict) -> None:
        payload = json.dumps(body, indent=2).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    # Silence request logging
    def log_message(self, format: str, *args: object) -> None:  # noqa: A002
        pass


# ── Server ────────────────────────────────────────────────────────────────────

class MetricsServer:
    """Background HTTP server exposing /health and /metrics."""

    def __init__(self, host: str = "127.0.0.1", port: int = 9946) -> None:
        self.host = host
        self.port = port
        self._httpd: Optional[HTTPServer] = None
        self._thread: Optional[threading.Thread] = None

    def start(self) -> None:
        """Start the server in a daemon thread."""
        self._httpd = HTTPServer((self.host, self.port), _Handler)
        self._thread = threading.Thread(target=self._httpd.serve_forever, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        if self._httpd:
            self._httpd.shutdown()
            self._httpd = None

    # Convenience wrappers delegating to the global store
    inc = staticmethod(inc)
    set_gauge = staticmethod(set_gauge)
    observe = staticmethod(observe)
    snapshot = staticmethod(snapshot)


# ── CLI entry point ───────────────────────────────────────────────────────────

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(description="Exploit-subnet metrics server")
    parser.add_argument("--port", type=int, default=9946, help="HTTP port (default 9946)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Bind address")
    args = parser.parse_args()

    srv = MetricsServer(host=args.host, port=args.port)
    srv.start()
    print(f"Metrics server listening on {args.host}:{args.port}")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        srv.stop()


if __name__ == "__main__":
    main()
