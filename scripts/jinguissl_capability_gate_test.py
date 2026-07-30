#!/usr/bin/env python3
"""Regression tests for the JinguiSSL capability publication gate."""

from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path

from jinguissl_capability_gate import public_surface_fingerprint, validate_public_delta


def run_git(root: Path, *args: str) -> None:
    subprocess.run(["git", *args], cwd=root, check=True, capture_output=True, text=True)


class CapabilityGateTest(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "src").mkdir()
        (self.root / "docs").mkdir()
        (self.root / "src/demo.cj").write_text(
            "package demo\n\npublic func answer(): Int64 {\n    42\n}\n",
            encoding="utf-8",
        )
        (self.root / "README.md").write_text("# Demo\n", encoding="utf-8")
        (self.root / "docs/manual.md").write_text("# Manual\n", encoding="utf-8")
        (self.root / "docs/capabilities.json").write_text("{}\n", encoding="utf-8")
        (self.root / "docs/capability-matrix.md").write_text(
            "# Matrix\n", encoding="utf-8"
        )
        run_git(self.root, "init")
        run_git(self.root, "config", "user.email", "gate-test@example.invalid")
        run_git(self.root, "config", "user.name", "Capability Gate Test")
        run_git(self.root, "add", ".")
        run_git(self.root, "commit", "-m", "base")
        self.manifest = {
            "readme": "README.md",
            "matrix": "docs/capability-matrix.md",
            "excludeSourceGlobs": [],
            "capabilities": [
                {
                    "id": "demo",
                    "sourceGlobs": ["src/*.cj"],
                    "manualPages": ["docs/manual.md"],
                }
            ],
        }

    def tearDown(self) -> None:
        self.temp.cleanup()

    def test_public_change_requires_manifest_matrix_readme_and_manual(self) -> None:
        (self.root / "src/demo.cj").write_text(
            "package demo\n\npublic func answer(value: Int64): Int64 {\n    value\n}\n",
            encoding="utf-8",
        )
        errors = validate_public_delta(self.root, self.manifest, "HEAD")
        self.assertEqual(len(errors), 4)
        self.assertTrue(any("docs/capabilities.json" in item for item in errors))
        self.assertTrue(any("docs/capability-matrix.md" in item for item in errors))
        self.assertTrue(any("README.md" in item for item in errors))
        self.assertTrue(any("manual page" in item for item in errors))

        for relative in (
            "README.md",
            "docs/manual.md",
            "docs/capabilities.json",
            "docs/capability-matrix.md",
        ):
            path = self.root / relative
            path.write_text(path.read_text(encoding="utf-8") + "\n", encoding="utf-8")
        self.assertEqual(validate_public_delta(self.root, self.manifest, "HEAD"), [])

    def test_body_only_change_does_not_require_publication_docs(self) -> None:
        (self.root / "src/demo.cj").write_text(
            "package demo\n\npublic func answer(): Int64 {\n    43\n}\n",
            encoding="utf-8",
        )
        self.assertEqual(validate_public_delta(self.root, self.manifest, "HEAD"), [])

    def test_multiline_signature_and_enum_cases_are_public_surface(self) -> None:
        before = """public enum Mode {
    | One
}

public class Request {
    public init(
        value: Int64
    ) {
    }
}
"""
        after = """public enum Mode {
    | One
    | Two
}

public class Request {
    public init(
        value: String
    ) {
    }
}
"""
        self.assertNotEqual(
            public_surface_fingerprint(before), public_surface_fingerprint(after)
        )


if __name__ == "__main__":
    unittest.main()
