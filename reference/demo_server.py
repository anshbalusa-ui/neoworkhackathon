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
from .confirmation_scenario import generate_confirmation
from .probe import evaluate_probe

ROOT = Path(__file__).resolve().parents[1]


class Handler(SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=str(ROOT), **kwargs)

    def do_POST(self):
        # This is a loopback-only, synthetic attack sandbox. No outgoing network.
        if urlsplit(self.path).path != "/api/probe":
            self.send_error(404, "Unknown demo API")
            return
        try:
            content_type = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
            raw_length = self.headers.get("Content-Length", "")
            size = int(raw_length)
            if content_type != "application/json" or not 0 < size <= 1600:
                raise ValueError("Invalid request type or size")
            request = json.loads(self.rfile.read(size))
            if not isinstance(request, dict) or set(request) != {
                "page_instruction", "operation", "destination", "value"
            }:
                raise ValueError("Unknown probe keys")
            result = evaluate_probe(**request)
        except (TypeError, ValueError, UnicodeDecodeError, json.JSONDecodeError):
            self.send_error(400, "Invalid synthetic probe")
            return
        data = json.dumps(result, ensure_ascii=False).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

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
        if url.path == "/api/confirmation":
            identifier = parse_qs(url.query).get("id", [""])[0]
            scenarios = generate_confirmation()
            case = next((item for item in scenarios["cases"] if item["id"] == identifier), None)
            if case is None:
                self.send_error(404, "Unknown synthetic confirmation scenario")
                return
            body = json.dumps({"kind": scenarios["kind"], "case": case},
                              ensure_ascii=False).encode()
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
