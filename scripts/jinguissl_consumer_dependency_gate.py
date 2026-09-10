"""Bounded consumer proof: direct Contract dependency, no direct Core source import."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
for name in ("webauthn-crypto-smoke", "webdav-digest-smoke", "quic-crypto-smoke", "tls-client-smoke"):
    sample = root / "examples" / name
    text = (sample / "cjpm.toml").read_text()
    sections = re.findall(r"(?ms)^\[dependencies\]\s*\n(.*?)(?=^\[|\Z)", text)
    assert len(sections) == 1, name
    names = re.findall(r"(?m)^\s*([\w.-]+)\s*=", sections[0])
    assert names == ["jinguissl"], (name, names)
    assert "jinguissl_core" not in text, name
    for source in (sample / "src").rglob("*.cj"):
        assert not re.search(r"\bimport\s+jinguissl_core\b", source.read_text()), source
print("four standalone consumers: direct jinguissl only; transitive Core lock allowed")
