#!/usr/bin/env python3
"""Fail if C203 GM public declarations expose Core-owned types."""

from pathlib import Path
import re
import sys


FILES = [
    "src/contract/contract_gm_primitives.cj",
    "src/contract/contract_sm9.cj",
    "src/contract/contract_gm_x509.cj",
    "src/contract/contract_rfc8998.cj",
    "src/contract/contract_tlcp.cj",
]

FORBIDDEN = re.compile(
    r"\b(?:BigNum|CryptoException|CryptoErrorCode|HashAlgorithm|"
    r"Sm2(?:PrivateKey|PublicKey|KeyExchangeResult)|Sm9[A-Z]\w*|"
    r"X509\w+|Tls(?:13\w+|ContentType|PlainRecord)|Tlcp\w+|Dtlcp\w+)\b"
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
            errors.append(f"{relative}: required C203 GM surface is missing")
            continue
        for line, declaration in public_declarations(path.read_text(encoding="utf-8")):
            match = FORBIDDEN.search(declaration)
            if match:
                errors.append(
                    f"{relative}:{line}: public declaration exposes Core type {match.group(0)}"
                )
    if errors:
        print(f"GM Contract boundary gate failed: {len(errors)} error(s)", file=sys.stderr)
        for error in errors:
            print(f"- {error}", file=sys.stderr)
        return 1
    print(f"GM Contract boundary gate passed: {len(FILES)} surface file(s)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
