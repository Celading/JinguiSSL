#!/usr/bin/env python3
"""Fail if C204 preferred Contract declarations expose Core/live-owned types."""

from pathlib import Path
import re
import sys


FILES = [
    "src/contract/contract_aes_primitives.cj",
    "src/contract/contract_asymmetric.cj",
    "src/contract/contract_random.cj",
    "src/contract/contract_ssh_facade.cj",
    "src/contract/contract_traditional_kem.cj",
    "src/contract/contract_x509_general.cj",
    "src/contract/ssh_startup_bundle.cj",
]

FORBIDDEN = re.compile(
    r"(?:\blivecontract\.[A-Za-z_]\w*|"
    r"\b(?:BigNum|CryptoException|CryptoErrorCode|CoreHashAlgorithm|HashAlgorithm|"
    r"AesGcmResult|NamedCurve|EcPrivateKey|EcPublicKey|RsaPrivateKey|RsaPublicKey|"
    r"X509Certificate|SshKexInitMessage|SshVersionBanner)\b)"
)


def public_declarations(text: str):
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        line = lines[index]
        match = re.match(r"^\s*public\s+(func|class|enum|let|prop|init)\b", line)
        if not match:
            index += 1
            continue
        start = index + 1
        declaration = [line]
        kind = match.group(1)
        while (
            kind not in {"let", "prop"}
            and "{" not in declaration[-1]
            and "=" not in declaration[-1]
            and index + 1 < len(lines)
        ):
            index += 1
            declaration.append(lines[index])
        yield start, "\n".join(declaration)
        index += 1


def main() -> int:
    root = Path(__file__).resolve().parent.parent
    errors = []
    for relative in FILES:
        path = root / relative
        if not path.is_file():
            errors.append(f"{relative}: required C204 Contract surface is missing")
            continue
        for line, declaration in public_declarations(path.read_text(encoding="utf-8")):
            match = FORBIDDEN.search(declaration)
            if match:
                errors.append(
                    f"{relative}:{line}: public declaration exposes foreign type {match.group(0)}"
                )
    if errors:
        print(f"Non-GM Contract boundary gate failed: {len(errors)} error(s)", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"Non-GM Contract boundary gate passed: {len(FILES)} surface file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
