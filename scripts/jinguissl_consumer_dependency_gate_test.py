"""Regression tests for exact hosted consumer locks and direct dependency boundaries."""
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


class ConsumerDependencyGateTest(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.TemporaryDirectory(prefix="jinguissl-consumer-gate-")
        self.addCleanup(self.folder.cleanup)
        self.root = Path(self.folder.name)
        (self.root / "scripts").mkdir()
        self.script = self.root / "scripts/jinguissl_consumer_dependency_gate.py"
        shutil.copyfile(Path(__file__).with_name(self.script.name), self.script)
        self.pin = 'jinguissl_core = {git = "https://gitcode.com/CjKu/JinguiCore.git", commitId = "' + "a" * 40 + '"}\n'
        (self.root / "cjpm.toml").write_text("[dependencies]\n" + self.pin)
        (self.root / "cjpm.lock").write_text("version = 0\n[requires]\n" + self.pin)
        for name in ("webauthn-crypto-smoke", "webdav-digest-smoke", "quic-crypto-smoke", "tls-client-smoke", "dtls-consumer"):
            sample = self.root / "examples" / name
            (sample / "src").mkdir(parents=True)
            (sample / "cjpm.toml").write_text('[dependencies]\njinguissl = { path = "../.." }\n')
            (sample / "cjpm.lock").write_text("version = 0\n[requires]\n" + self.pin)
            (sample / "src/main.cj").write_text("import jinguissl.contract.*\n")

    def run_gate(self):
        return subprocess.run([sys.executable, str(self.script)], capture_output=True, text=True)

    def test_matching_hosted_graph_passes(self):
        result = self.run_gate()
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_stale_consumer_lock_rejected(self):
        path = self.root / "examples/dtls-consumer/cjpm.lock"
        path.write_text(path.read_text().replace("a" * 40, "b" * 40))
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("consumer Core lock drift: dtls-consumer", result.stderr)

    def test_stale_root_lock_rejected(self):
        path = self.root / "cjpm.lock"
        path.write_text(path.read_text().replace("a" * 40, "b" * 40))
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("root Core lock drift", result.stderr)

    def test_unpinned_core_rejected(self):
        (self.root / "cjpm.toml").write_text('[dependencies]\njinguissl_core = { path = "../core" }\n')
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("missing or ambiguous Core pin", result.stderr)

    def test_direct_core_import_rejected(self):
        (self.root / "examples/dtls-consumer/src/main.cj").write_text("import jinguissl_core.crypto.dtls.*\n")
        result = self.run_gate()
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("dtls-consumer/src/main.cj", result.stderr)


if __name__ == "__main__":
    unittest.main()
