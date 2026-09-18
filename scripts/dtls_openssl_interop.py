#!/usr/bin/env python3
"""Independent DTLS 1.2 reference test; OpenSSL is never a library backend.

Build examples/dtls-consumer first. This runner generates ephemeral identities and
uses loopback UDP. It checks both roles, SRTP profiles 7/1, mutual private-key
proof, Finished, application records and byte-exact RFC 5764 exporter output.
"""
import argparse
import hashlib
import os
import platform
from pathlib import Path
import queue
import re
import select
import shutil
import socket
import subprocess
import tempfile
import threading
import time


def lines(process):
    result = queue.Queue()
    def read():
        for line in iter(process.stdout.readline, b""):
            result.put(line.decode(errors="replace").rstrip())
        result.put(None)
    threading.Thread(target=read, daemon=True).start()
    return result


def run_case(binary, openssl, folder, role, profile):
    processes = []
    peer_lines, reference_lines, app_data = [], [], []
    udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp.bind(("127.0.0.1", 0))
    udp.setblocking(False)
    def launch(args):
        env = os.environ.copy()
        if args[0] == str(binary):
            sdk = Path(env["CANGJIE_HOME"])
            host = "darwin" if platform.system() == "Darwin" else "linux"
            arch = "aarch64" if platform.machine() in ("arm64", "aarch64") else "x86_64"
            runtime = sdk / "runtime/lib" / f"{host}_{arch}_cjnative"
            if not runtime.is_dir(): raise RuntimeError(f"SDK runtime missing: {runtime}")
            variable = "DYLD_LIBRARY_PATH" if host == "darwin" else "LD_LIBRARY_PATH"
            env[variable] = os.pathsep.join([str(runtime), str(sdk / "tools/lib"), env.get(variable, "")])
        p = subprocess.Popen(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                             stderr=subprocess.STDOUT, env=env)
        processes.append(p)
        return p, lines(p)
    def command(p, value):
        p.stdin.write((value + "\n").encode()); p.stdin.flush()
    try:
        profile_name = {7: "SRTP_AEAD_AES_128_GCM", 1: "SRTP_AES128_CM_SHA1_80"}[profile]
        export_len = {7: 56, 1: 60}[profile]
        common = ["-dtls1_2", "-cipher", "ECDHE-ECDSA-AES128-GCM-SHA256",
                  "-groups", "X25519:P-256", "-sigalgs", "ecdsa_secp256r1_sha256", "-no_ticket",
                  "-use_srtp", profile_name, "-keymatexport", "EXTRACTOR-dtls_srtp",
                  "-keymatexportlen", str(export_len), "-cert", str(folder / "ref.pem"),
                  "-key", str(folder / "ref.key"), "-CAfile", str(folder / "own.pem"),
                  "-verify_return_error", "-ign_eof", "-mtu", "1200"]
        if role == "client":
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as port_probe:
                port_probe.bind(("127.0.0.1", 0)); ref_port = port_probe.getsockname()[1]
            remote = ("127.0.0.1", ref_port)
            ref, ref_q = launch([openssl, "s_server", "-accept", f"127.0.0.1:{ref_port}",
                                 "-Verify", "1", "-naccept", "1"] + common)
        else:
            remote = None
            ref, ref_q = launch([openssl, "s_client", "-connect", f"127.0.0.1:{udp.getsockname()[1]}"] + common)
        fingerprint = hashlib.sha256((folder / "ref.der").read_bytes()).hexdigest()
        peer, peer_q = launch([str(binary), role, str(folder / "own.key"),
                              str(folder / "own.der"), fingerprint, str(profile)])
        start = time.monotonic()
        def read_peer():
            nonlocal remote
            while True:
                value = peer_q.get(timeout=10)
                if value is None:
                    raise AssertionError("Cangjie peer exited: " + "\n".join(peer_lines[-20:]))
                peer_lines.append(value)
                if value.startswith("OUT "):
                    assert remote is not None
                    udp.sendto(bytes.fromhex(value[4:]), remote)
                if value.startswith("DATA "): app_data.append(bytes.fromhex(value[5:]))
                if value.startswith("READY "): return value == "READY true"
        authenticated = read_peer()
        last_tick = 0
        def pump():
            nonlocal remote, authenticated, last_tick
            now = int((time.monotonic() - start) * 1000)
            if select.select([udp], [], [], 0.02)[0]:
                packet, sender = udp.recvfrom(65535)
                if remote is None: remote = sender
                assert remote == sender
                command(peer, f"RX {now} {packet.hex()}")
                authenticated = read_peer()
            elif now - last_tick >= 200:
                command(peer, f"TICK {now}"); authenticated = read_peer(); last_tick = now
            while not ref_q.empty():
                line = ref_q.get_nowait()
                if line is not None: reference_lines.append(line)
            if peer.poll() is not None or ref.poll() is not None:
                raise AssertionError("peer exited before completion")
        while time.monotonic() - start < 15 and not authenticated: pump()
        assert authenticated, "handshake timeout"
        command(peer, "EXPORT"); read_peer()
        own_keys = next(line[5:] for line in peer_lines if line.startswith("KEYS "))
        command(peer, "APP " + b"jinguissl-to-openssl\n".hex()); read_peer()
        command(ref, "openssl-to-jinguissl")
        while time.monotonic() - start < 20:
            pump()
            output = "\n".join(reference_lines)
            match = re.search(r"Keying material:\s*([0-9A-Fa-f]+)", output)
            if match and b"openssl-to-jinguissl\n" in app_data and "jinguissl-to-openssl" in output:
                assert match.group(1).lower() == own_keys, "SRTP exporter mismatch"
                assert "ECDHE-ECDSA-AES128-GCM-SHA256" in output, "wrong negotiated suite"
                print(f"PASS role={role} profile={profile} mutual-auth application exporter={export_len}B", flush=True)
                return
        raise AssertionError("application/exporter timeout")
    except Exception:
        # Never print transient exported secrets or private keys on failure.
        print("Reference tail:", "\n".join(x for x in reference_lines[-35:]
              if "Keying material:" not in x and "Master-Key:" not in x), flush=True)
        print("Peer tail:", "\n".join(x for x in peer_lines[-10:]
              if not x.startswith(("KEYS ", "OUT "))), flush=True)
        raise
    finally:
        udp.close()
        for p in processes:
            if p.poll() is None: p.terminate()
        for p in processes:
            try: p.wait(timeout=3)
            except subprocess.TimeoutExpired: p.kill(); p.wait()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--binary", type=Path, default=Path(__file__).resolve().parents[1] /
                        "examples/dtls-consumer/target/release/bin/main")
    parser.add_argument("--openssl", default=shutil.which("openssl"))
    args = parser.parse_args()
    print(subprocess.check_output([args.openssl, "version"], text=True).strip(), flush=True)
    with tempfile.TemporaryDirectory(prefix="jinguissl-dtls-reference-") as name:
        folder = Path(name)
        for identity in ["own", "ref"]:
            subprocess.run([args.openssl, "req", "-new", "-x509", "-newkey", "ec",
                "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes", "-days", "2", "-subj", f"/CN={identity}",
                "-keyout", str(folder / f"{identity}.key"), "-out", str(folder / f"{identity}.pem")],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            subprocess.run([args.openssl, "x509", "-in", str(folder / f"{identity}.pem"),
                "-outform", "DER", "-out", str(folder / f"{identity}.der")], check=True)
        for role in ["client", "server"]:
            for profile in [7, 1]: run_case(args.binary.resolve(), args.openssl, folder, role, profile)


if __name__ == "__main__": main()
