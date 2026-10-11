"""Dependency-free static site validation and inline JavaScript syntax check."""
from __future__ import annotations

from collections import Counter
from html.parser import HTMLParser
from pathlib import Path
import re
import shutil
import subprocess
import tempfile


ROOT = Path(__file__).resolve().parents[1]
HTML = ROOT / "site" / "index.html"


class Structure(HTMLParser):
    def __init__(self):
        super().__init__()
        self.ids = []
        self.anchors = []
        self.external_scripts = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if "id" in attrs:
            self.ids.append(attrs["id"])
        if tag == "a" and attrs.get("href", "").startswith("#"):
            self.anchors.append(attrs["href"][1:])
        if tag == "script" and "src" in attrs:
            self.external_scripts.append(attrs["src"])


def validate():
    html = HTML.read_text(encoding="utf-8")
    parsed = Structure()
    parsed.feed(html)
    counts = Counter(parsed.ids)
    duplicates = [ident for ident, count in counts.items() if count > 1]
    missing = [ident for ident in parsed.anchors if ident not in counts]
    assert not duplicates, f"Duplicate HTML IDs: {duplicates}"
    assert not missing, f"Broken internal anchors: {missing}"
    assert not parsed.external_scripts, "The handoff must not load third-party scripts"
    needed = (
        "architecture", "scenario", "probe", "assurance", "confirmation", "policy", "threats",
        "handoff", "attack-select", "run-attack", "run-assurance",
        "assurance-facts", "assurance-matrix", "assurance-status",
        "confirm-select", "run-confirm", "confirm-status", "confirmation-result",
        "probe-form", "probe-text", "probe-operation", "probe-destination",
        "probe-value", "probe-submit", "probe-outcome", "probe-status",
    )
    assert all(name in counts for name in needed), "Missing a critical demo interaction"
    scripts = re.findall(r"<script(?:\s[^>]*)?>(.*?)</script>", html, re.S | re.I)
    assert len(scripts) == 1, "Expected one self-contained inline demo script"
    assert not re.search(r"\b(?:eval|Function)\s*\(|\.innerHTML\s*=", scripts[0]), (
        "Untrusted scenario text must use safe DOM text APIs"
    )
    node = shutil.which("node")
    assert node, "Node.js is required for the demo JavaScript syntax check"
    with tempfile.TemporaryDirectory() as directory:
        script = Path(directory) / "neo-demo.js"
        script.write_text(scripts[0], encoding="utf-8")
        check = subprocess.run([node, "--check", str(script)],
                               capture_output=True, text=True)
        assert check.returncode == 0, f"Invalid demo JavaScript:\n{check.stderr}"
    print(f"PASS: site structure, {len(parsed.anchors)} links, "
          f"{len(parsed.ids)} distinct IDs, inline JS syntax and safe text APIs")


if __name__ == "__main__":
    validate()
