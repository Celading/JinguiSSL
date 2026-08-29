#!/usr/bin/env python3

import importlib.util
from pathlib import Path
import unittest


SCRIPT = Path(__file__).with_name("jinguissl_gm_contract_boundary_gate.py")
SPEC = importlib.util.spec_from_file_location("gm_boundary_gate", SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
assert SPEC.loader is not None
SPEC.loader.exec_module(MODULE)


class GmContractBoundaryGateTest(unittest.TestCase):
    def matches(self, source: str):
        return [
            MODULE.FORBIDDEN.search(declaration)
            for _, declaration in MODULE.public_declarations(source)
            if MODULE.FORBIDDEN.search(declaration)
        ]

    def test_contract_types_are_allowed(self):
        source = """
public class ContractTlcpSecrets {
    internal let core: TlcpHandshakeSecrets
    public let cipherSuite: ContractTlcpCipherSuite
}
"""
        self.assertEqual(self.matches(source), [])

    def test_multiline_public_core_type_is_rejected(self):
        source = """
public func badBoundary(
    value: TlcpHandshakeSecrets
): Array<Byte> {
    []
}
"""
        matches = self.matches(source)
        self.assertEqual(len(matches), 1)
        self.assertEqual(matches[0].group(0), "TlcpHandshakeSecrets")

    def test_private_and_internal_core_types_are_not_public_leaks(self):
        source = """
private func privateHelper(value: Sm2PrivateKey): Unit {}
internal func packageHelper(value: X509Certificate): Unit {}
public func stableBoundary(value: ContractSm2KeyPair): Array<Byte> { [] }
"""
        self.assertEqual(self.matches(source), [])


if __name__ == "__main__":
    unittest.main()
