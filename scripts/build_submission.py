"""Reproducibly package the three required deliverables at the archive root."""
from pathlib import Path
from zipfile import ZipFile, ZIP_DEFLATED

ROOT = Path(__file__).resolve().parents[1]
FILES = ("neo-action-security-architecture.md", "neo-action-threat-model.md", "neo-action-confirmation-policy.md")
OUTPUT = ROOT / "neo-action-security-architecture.zip"

if __name__ == "__main__":
    for name in FILES:
        if not (ROOT / name).is_file() or not (ROOT / name).read_text(encoding="utf-8").strip():
            raise SystemExit("Missing or empty: " + name)
    with ZipFile(OUTPUT, "w", compression=ZIP_DEFLATED, compresslevel=9) as z:
        for name in FILES:
            z.write(ROOT / name, arcname=name)
    with ZipFile(OUTPUT) as z:
        if sorted(z.namelist()) != sorted(FILES) or z.testzip():
            raise SystemExit("ZIP verification failed")
        for name in FILES:
            if z.read(name) != (ROOT / name).read_bytes():
                raise SystemExit("ZIP byte mismatch: " + name)
    print("PASS: exact three-file submission", OUTPUT)
