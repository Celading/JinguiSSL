"""aioquic==1.3.0 raw TLS engine oracle; not a QUIC packet/network interop claim.

The loopback length prefix is solely a test carrier. Actual TLS bytes have no
record headers. The fixed-version reference verifies client Finished and checks
both directional handshake/application traffic secrets without printing secrets.
"""
import hashlib
import pathlib
import socket
import struct
import subprocess
import threading

import aioquic
from aioquic.buffer import Buffer
from aioquic.tls import Context, CipherSuite, Direction, Epoch, State, load_pem_private_key, load_pem_x509_certificates
from tls_client_openssl_smoke import ROOT, runtime_environment

EXAMPLE = ROOT / "examples/quic-crypto-smoke"


def read_exact(sock, size):
    out = bytearray()
    while len(out) < size:
        chunk = sock.recv(size - len(out))
        if not chunk:
            raise EOFError("test carrier closed")
        out.extend(chunk)
    return bytes(out)


def read_frame(sock):
    size, = struct.unpack("!I", read_exact(sock, 4))
    assert size <= 262144
    return read_exact(sock, size)


def write_frame(sock, data):
    sock.sendall(struct.pack("!I", len(data)) + data)


def run(suite):
    peer = Context(is_client=False, alpn_protocols=["igquic-echo"], cipher_suites=[CipherSuite(suite)])
    peer.certificate = load_pem_x509_certificates((ROOT / "testdata/x509/engine_leaf.pem").read_bytes())[0]
    peer.certificate_private_key = load_pem_private_key((ROOT / "testdata/x509/policy_leaf_key_pkcs8.pem").read_bytes())
    peer.handshake_extensions = [(0x39, b"\x03\x00")]
    keys = {}
    peer.update_traffic_key_cb = lambda direction, epoch, cipher, secret: keys.__setitem__((direction, epoch), secret)
    output = {epoch: Buffer(capacity=262144) for epoch in Epoch}
    listener = socket.socket()
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    listener.settimeout(15)
    errors = []

    def serve():
        try:
            sock, _ = listener.accept()
            with sock:
                sock.settimeout(15)
                peer.handle_message(read_frame(sock), output)
                assert (0x39, b"\x01\x00") in peer.received_extensions
                assert peer.alpn_negotiated == "igquic-echo"
                write_frame(sock, output[Epoch.INITIAL].data)
                write_frame(sock, output[Epoch.HANDSHAKE].data)
                peer.handle_message(read_frame(sock), {epoch: Buffer(capacity=262144) for epoch in Epoch})
                assert peer.state == State.SERVER_POST_HANDSHAKE
                for epoch in (Epoch.HANDSHAKE, Epoch.ONE_RTT):
                    for direction in (Direction.DECRYPT, Direction.ENCRYPT):
                        assert read_frame(sock) == hashlib.sha256(keys[direction, epoch]).digest()
                write_frame(sock, b"\x01")
        except BaseException as exc:
            errors.append(exc)

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        result = subprocess.run([str(EXAMPLE / "target/release/bin/main"), str(listener.getsockname()[1]), str(suite)],
                                cwd=EXAMPLE, env=runtime_environment(), capture_output=True, text=True, timeout=30)
        thread.join(16)
        print(f"suite={suite}: {result.stdout}", end="")
        if errors:
            raise errors[0]
        if result.returncode:
            raise RuntimeError(result.stderr + result.stdout)
        assert not thread.is_alive()
    finally:
        listener.close()


if __name__ == "__main__":
    assert aioquic.__version__ == "1.3.0", aioquic.__version__
    print(f"aioquic {aioquic.__version__}: raw handshake reference")
    for value in (0x1301, 0x1302, 0x1303):
        run(value)
