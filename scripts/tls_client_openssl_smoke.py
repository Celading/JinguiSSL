"""Independent OpenSSL peer for the Contract-only TLS consumer, no external network.

Run from repo root after building examples/tls-client-smoke. Python ssl uses its
reported OpenSSL backend; application crypto remains entirely Cangjie.
"""
import pathlib
import os
import platform
import socket
import ssl
import subprocess
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/tls-client-smoke"
BINARY = EXAMPLE / "target/release/bin/main"


def runtime_environment():
    env = os.environ.copy()
    sdk = pathlib.Path(env["CANGJIE_HOME"])
    host = "darwin" if platform.system() == "Darwin" else "linux"
    arch = "aarch64" if platform.machine() in ("arm64", "aarch64") else "x86_64"
    runtime = sdk / "runtime/lib" / f"{host}_{arch}_cjnative"
    if not runtime.is_dir():
        raise RuntimeError(f"configured SDK runtime missing: {runtime}")
    variable = "DYLD_LIBRARY_PATH" if host == "darwin" else "LD_LIBRARY_PATH"
    env[variable] = os.pathsep.join([str(runtime), str(sdk / "tools/lib"), env.get(variable, "")])
    return env


def run(suite):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.num_tickets = 2  # valid tickets are decoded/discarded without enabling resumption
    context.set_alpn_protocols(["mqtt"])
    context.load_cert_chain(ROOT / "testdata/x509/engine_leaf.pem", ROOT / "testdata/x509/policy_leaf_key_pkcs8.pem")
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(15)
    errors = []

    def serve():
        try:
            raw, _ = listener.accept()
            raw.settimeout(15)
            with context.wrap_socket(raw, server_side=True) as peer:
                assert peer.selected_alpn_protocol() == "mqtt"
                assert peer.recv(4) == b"ping"
                peer.sendall(b"pong")
                print(f"peer suite={suite}: {peer.version()} {peer.cipher()[0]}")
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        result = subprocess.run([str(BINARY), str(listener.getsockname()[1]), str(suite)],
                                cwd=EXAMPLE, env=runtime_environment(), capture_output=True, text=True, timeout=30)
        thread.join(16)
        print(result.stdout, end="")
        if result.returncode:
            raise RuntimeError(result.stderr + result.stdout)
        if errors:
            raise errors[0]
        assert not thread.is_alive()
    finally:
        listener.close()


if __name__ == "__main__":
    print(ssl.OPENSSL_VERSION)
    for value in (0x1301, 0x1302, 0x1303):
        run(value)
