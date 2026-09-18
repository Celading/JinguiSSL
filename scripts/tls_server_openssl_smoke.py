"""Independent TLS client with certificate/hostname verification, no external network."""
import pathlib
import socket
import ssl
import subprocess
from tls_client_openssl_smoke import runtime_environment

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/tls-server-smoke"


def run(alpn):
    context = ssl.create_default_context(cafile=str(ROOT / "testdata/x509/engine_root.pem"))
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    if alpn:
        context.set_alpn_protocols(["mqtt"])
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(15)
        process = subprocess.Popen([str(EXAMPLE / "target/release/bin/main"), str(listener.getsockname()[1]),
                                    "alpn" if alpn else "none"], cwd=EXAMPLE,
                                   env=runtime_environment(), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            raw, _ = listener.accept()
            raw.settimeout(15)
            with context.wrap_socket(raw, server_hostname="www.example.com") as client:
                assert client.version() == "TLSv1.3"
                assert client.selected_alpn_protocol() == ("mqtt" if alpn else None)
                client.sendall(b"ping")
                assert client.recv(4) == b"pong"
                assert client.recv(1) == b"", "missing clean close"
                print("verified OpenSSL client:", client.cipher(), "alpn=", alpn)
            stdout, stderr = process.communicate(timeout=15)
            assert process.returncode == 0, stdout + stderr
            print(stdout.strip())
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate()


if __name__ == "__main__":
    print(ssl.OPENSSL_VERSION)
    run(True)
    run(False)
