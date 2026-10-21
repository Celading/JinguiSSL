"""Independent loopback OpenSSL peer for the wire-derived TLS 1.3 entrypoint."""
import os
import pathlib
import socket
import ssl
import subprocess
import threading

ROOT = pathlib.Path(__file__).resolve().parents[1]
EXAMPLE = ROOT / "examples/tls-wire-client-smoke"


def run(compatibility):
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = context.maximum_version = ssl.TLSVersion.TLSv1_3
    context.num_tickets = 0
    if not compatibility:
        context.options &= ~ssl.OP_ENABLE_MIDDLEBOX_COMPAT
    context.set_alpn_protocols(["http/1.1"])

    def confirm_server_name(peer, name, initial_context):
        if name != "www.example.com":
            return ssl.ALERT_DESCRIPTION_UNRECOGNIZED_NAME
        return None

    context.set_servername_callback(confirm_server_name)
    context.load_cert_chain(ROOT / "testdata/x509/engine_leaf.pem",
                            ROOT / "testdata/x509/policy_leaf_key_pkcs8.pem")
    errors = []
    with socket.socket() as listener:
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        listener.settimeout(15)

        def serve():
            try:
                raw, _ = listener.accept()
                raw.settimeout(15)
                with context.wrap_socket(raw, server_side=True) as peer:
                    assert peer.selected_alpn_protocol() == "http/1.1"
                    assert peer.recv(4) == b"ping"
                    peer.sendall(b"pong")
            except BaseException as error:
                errors.append(error)

        thread = threading.Thread(target=serve, daemon=True)
        thread.start()
        result = subprocess.run([str(EXAMPLE / "target/release/bin/main"), str(listener.getsockname()[1])],
                                cwd=EXAMPLE, capture_output=True, text=True, timeout=30)
        thread.join(16)
        print(f"compatibility={compatibility}: {result.stdout.strip()}")
        if result.returncode:
            raise RuntimeError(result.stderr + result.stdout)
        if errors:
            raise errors[0]
        assert not thread.is_alive()


if __name__ == "__main__":
    print(ssl.OPENSSL_VERSION)
    run(True)
    run(False)
