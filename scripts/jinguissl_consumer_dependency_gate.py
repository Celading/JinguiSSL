"""Bounded consumer proof: direct Contract dependency, no direct Core source import."""
from pathlib import Path
import re

root = Path(__file__).resolve().parents[1]
pin_pattern = r'jinguissl_core\s*=\s*\{\s*git\s*=\s*"([^"]+)"\s*,\s*commitId\s*=\s*"([0-9a-f]{40})"\s*\}'
def core_pin(path):
    text = path.read_text()
    matches = [("git", *match) for match in re.findall(pin_pattern, text)]
    versions = re.findall(r'jinguissl_core\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"', text)
    versions += re.findall(r'jinguissl_core\s*=\s*\{\s*version\s*=\s*"([0-9]+\.[0-9]+\.[0-9]+)"\s*\}', text)
    matches += [("registry", version) for version in versions]
    assert len(matches) == 1, f"missing or ambiguous Core pin: {path}"
    return matches[0]

expected_pin = core_pin(root / "cjpm.toml")
assert core_pin(root / "cjpm.lock") == expected_pin, "root Core lock drift"
examples = sorted((root / "examples").glob("*/cjpm.toml"))
assert examples, "no independent consumer manifests"
for manifest in examples:
    assert core_pin(manifest.with_name("cjpm.lock")) == expected_pin, f"consumer Core lock drift: {manifest.parent.name}"
print(f"{len(examples)} consumer locks match the hosted root Core pin")

for name in ("webauthn-crypto-smoke", "webdav-digest-smoke", "quic-crypto-smoke", "tls-client-smoke", "dtls-consumer", "tlcp-consumer"):
    sample = root / "examples" / name
    text = (sample / "cjpm.toml").read_text()
    sections = re.findall(r"(?ms)^\[dependencies\]\s*\n(.*?)(?=^\[|\Z)", text)
    assert len(sections) == 1, name
    names = re.findall(r"(?m)^\s*([\w.-]+)\s*=", sections[0])
    assert names == ["jinguissl"], (name, names)
    assert "jinguissl_core" not in text, name
    for source in (sample / "src").rglob("*.cj"):
        assert not re.search(r"\bimport\s+jinguissl_core\b", source.read_text()), source
print("six standalone consumers: direct jinguissl only; transitive Core lock allowed")
