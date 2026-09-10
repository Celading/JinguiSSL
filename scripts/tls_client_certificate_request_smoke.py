"""Real OpenSSL s_server: optional empty-client-cert succeeds; required cert fails.

Reference executable only; application TLS/crypto remains Cangjie. No external
network or fixture modifications. OPENSSL overrides the reference executable.
"""
import os
import shutil
import socket
import subprocess
import threading
from tls_client_openssl_smoke import ROOT, EXAMPLE, BINARY, runtime_environment


def run(openssl, suite, required):
    with socket.socket() as reserve:
        reserve.bind(("127.0.0.1", 0))
        port = reserve.getsockname()[1]
    command = [openssl, "s_server", "-accept", f"127.0.0.1:{port}", "-tls1_3",
               "-cert", str(ROOT / "testdata/x509/engine_leaf.pem"),
               "-key", str(ROOT / "testdata/x509/policy_leaf_key_pkcs8.pem"),
               "-CAfile", str(ROOT / "testdata/x509/engine_root.pem"),
               "-Verify" if required else "-verify", "1", "-alpn", "mqtt",
               "-www", "-naccept", "1", "-msg"]
    peer = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    lines = []
    ready = threading.Event()

    def drain(stream):
        for line in stream:
            lines.append(line)
            if "ACCEPT" in line:
                ready.set()

    readers = [threading.Thread(target=drain, args=(stream,), daemon=True)
               for stream in (peer.stdout, peer.stderr)]
    for reader in readers:
        reader.start()
    try:
        if not ready.wait(8):
            raise RuntimeError("OpenSSL listener did not become ready: " + "".join(lines))
        client = subprocess.run([str(BINARY), str(port), str(suite), "http-probe"],
                                cwd=EXAMPLE, env=runtime_environment(),
                                capture_output=True, text=True, timeout=30)
        peer.wait(timeout=10)
        for reader in readers:
            reader.join(2)
        trace = "".join(lines)
        assert "CertificateRequest" in trace, trace
        # OpenSSL's independent message decoder must see the eight-byte empty
        # Certificate handshake (four-byte header plus four-byte empty body).
        assert "length 0008], Certificate" in trace, client.stdout + client.stderr + trace
        if required:
            assert client.returncode != 0, client.stdout
            assert "peer did not return a certificate" in trace, trace
            print(f"suite={suite}: mandatory certificate rejected, client failed")
        else:
            assert client.returncode == 0, client.stderr + client.stdout + trace
            assert "authenticated HTTP probe OK" in client.stdout, client.stdout
            assert "Finished" in trace, trace
            print(f"suite={suite}: optional CertificateRequest, empty Certificate, Finished and application data OK")
    finally:
        if peer.poll() is None:
            peer.terminate()
            try:
                peer.wait(timeout=3)
            except subprocess.TimeoutExpired:
                peer.kill()
                peer.wait()


if __name__ == "__main__":
    executable = os.environ.get("OPENSSL") or shutil.which("openssl")
    if not executable:
        raise RuntimeError("OpenSSL reference executable is required; test not skipped")
    print(subprocess.check_output([executable, "version"], text=True).strip())
    for value in (0x1301, 0x1302, 0x1303):
        run(executable, value, False)
        run(executable, value, True)
