"""Serve the handoff site and evaluate synthetic gateway scenarios on demand.

Local demo only. The API invokes the Python simulator, not a real browser actuator.
"""
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit
import json
import os

from .scenario import generate
from .assurance import run_sweep

ROOT = Path(__file__).resolve().parents[1]


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_GET(self):
        url = urlsplit(self.path)
        if url.path == "/api/assurance":
            # Deterministic local synthetic test sweep; no outward network requests.
            body = json.dumps(run_sweep(), ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        if url.path == "/api/scenario":
            params = parse_qs(url.query)
            identifier = params.get("id", [""])[0]
            data = generate()
            case = next((case for case in data["scenarios"] if case["id"] == identifier), None)
            if case is None:
                self.send_error(404, "Unknown synthetic scenario")
                return
            body = json.dumps({"kind": data["kind"], "scenario": case}, ensure_ascii=False).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json; charset=utf-8")
            self.send_header("Cache-Control", "no-store")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        super().do_GET()


if __name__ == "__main__":
    port = int(os.environ.get("NEO_DEMO_PORT", "8765"))
    server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
    print(f"Synthetic gateway demo: http://127.0.0.1:{port}/site/ (Ctrl-C to stop)", flush=True)
    server.serve_forever()
