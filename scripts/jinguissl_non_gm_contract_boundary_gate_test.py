#!/usr/bin/env python3

import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name("jinguissl_non_gm_contract_boundary_gate.py")
SPEC = importlib.util.spec_from_file_location("non_gm_boundary_gate", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class NonGmContractBoundaryGateTest(unittest.TestCase):
    def matches(self, source: str):
        return [
            MODULE.FORBIDDEN.search(declaration)
            for _, declaration in MODULE.public_declarations(source)
            if MODULE.FORBIDDEN.search(declaration)
        ]

    def test_contract_and_byte_types_are_allowed(self):
        source = """
public class ContractRsaEnvelope {
    internal let core: RsaPrivateKey
    public let key: ContractRsaPrivateKey
    public let encoded: Array<Byte>
}
"""
        self.assertEqual(self.matches(source), [])

    def test_multiline_core_type_is_rejected(self):
        source = """
public func badBoundary(
    value: X509Certificate
): Array<Byte> {
    []
}
"""
        matches = self.matches(source)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].group(0), "X509Certificate")

    def test_live_alias_type_is_rejected(self):
        source = """
public let runtime: livecontract.ContractSshServerRuntime
"""
        matches = self.matches(source)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].group(0), "livecontract.ContractSshServerRuntime")

    def test_internal_foreign_types_do_not_leak(self):
        source = """
internal func bridge(value: EcPrivateKey): Unit {}
private func parse(value: CryptoException): Unit {}
public func stableBoundary(value: ContractEcKeyPair): Array<Byte> { [] }
"""
        self.assertEqual(self.matches(source), [])


if __name__ == "__main__":
    unittest.main()
