#!/usr/bin/env python3
"""Validate and atomically stage a leaf/key pair, then reload only this proxy."""
from __future__ import annotations

import argparse
import fcntl
import hashlib
import os
from pathlib import Path
import subprocess
import tempfile
import time


def run(argv: list[str], data: bytes | None = None) -> bytes:
    result = subprocess.run(argv, input=data, capture_output=True, timeout=10)
    if result.returncode:
        raise RuntimeError(f"{Path(argv[0]).name} validation or reload failed")
    return result.stdout


def atomic_write(path: Path, data: bytes) -> None:
    fd, name = tempfile.mkstemp(dir=path.parent, prefix=".certificate-")
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(name, path)
    finally:
        if os.path.exists(name):
            os.unlink(name)


def switch_pair(target: Path, link_target: str) -> None:
    temporary = target / f".current-{os.getpid()}"
    try:
        temporary.symlink_to(link_target)
        os.replace(temporary, target / "current")
        directory_fd = os.open(target, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def stage_pair(target: Path, cert: bytes, key: bytes, digest: bytes) -> str:
    versions = target / "versions"
    versions.mkdir(mode=0o700, exist_ok=True)
    version = Path(tempfile.mkdtemp(dir=versions, prefix=digest.decode()[:16] + "-"))
    atomic_write(version / "10.10.99.99.crt", cert)
    atomic_write(version / "10.10.99.99.key", key)
    for directory in (version, versions):
        directory_fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    return str(version.relative_to(target))


def current_pair_matches(target: Path, cert: bytes, key: bytes) -> bool:
    current = target / "current"
    if not current.is_symlink():
        return False
    try:
        # A state receipt alone is insufficient after interrupted work or damage.
        return (current / "10.10.99.99.crt").read_bytes() == cert and (current / "10.10.99.99.key").read_bytes() == key
    except OSError:
        return False


def validated_pair(source: Path, root_ca: Path) -> tuple[bytes, bytes, str]:
    cert_file = source / "10.10.99.99.crt"
    key_file = source / "10.10.99.99.key"
    cert, key = cert_file.read_bytes(), key_file.read_bytes()
    time.sleep(0.5)
    if cert_file.read_bytes() != cert or key_file.read_bytes() != key:
        raise RuntimeError("certificate files are still changing")
    with tempfile.TemporaryDirectory(prefix="cdt-leaf-") as tmp:
        cert_path, key_path = Path(tmp) / "leaf.crt", Path(tmp) / "leaf.key"
        atomic_write(cert_path, cert)
        atomic_write(key_path, key)
        public_cert = run(["openssl", "x509", "-in", str(cert_path), "-pubkey", "-noout"])
        cert_key = run(["openssl", "pkey", "-pubin", "-outform", "DER"], public_cert)
        private_key = run(["openssl", "pkey", "-in", str(key_path), "-pubout", "-outform", "DER"])
        if cert_key != private_key:
            raise RuntimeError("certificate and key do not match")
        run(["openssl", "x509", "-in", str(cert_path), "-noout", "-checkip", "10.10.99.99"])
        run(["openssl", "x509", "-in", str(cert_path), "-noout", "-checkend", "300"])
        run(["openssl", "verify", "-CAfile", str(root_ca), "-untrusted", str(cert_path), str(cert_path)])
        fingerprint = run(["openssl", "x509", "-in", str(cert_path), "-noout", "-fingerprint", "-sha256"]).decode().strip()
    return cert, key, fingerprint


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source-dir", type=Path, default=Path("/opt/knowledge-hub/caddy-data/caddy/certificates/local/10.10.99.99"))
    parser.add_argument("--target-dir", type=Path, default=Path("/opt/cdt-lan-navigation/tls"))
    parser.add_argument("--state-dir", type=Path, default=Path("/var/lib/cdt-lan-navigation"))
    parser.add_argument("--root-ca", type=Path, default=Path("/opt/knowledge-hub/caddy-data/caddy/pki/authorities/local/root.crt"))
    parser.add_argument("--container", default="cdt-lan-navigation")
    parser.add_argument("--address", default="127.0.0.1:2020")
    parser.add_argument("--prepare", action="store_true")
    args = parser.parse_args()
    args.target_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.state_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (args.state_dir / "reload.lock").open("a") as lock:
        os.chmod(lock.name, 0o600)
        fcntl.flock(lock, fcntl.LOCK_EX)
        for attempt in range(3):
            try:
                cert, key, fingerprint = validated_pair(args.source_dir, args.root_ca)
                digest = hashlib.sha256(cert + b"\0" + key).hexdigest().encode()
                state = args.state_dir / "loaded-pair"
                pair_matches = current_pair_matches(args.target_dir, cert, key)
                if not args.prepare and pair_matches and state.is_file() and state.read_bytes() == digest:
                    return
                current = args.target_dir / "current"
                previous = os.readlink(current) if current.is_symlink() else None
                if not pair_matches:
                    switch_pair(args.target_dir, stage_pair(args.target_dir, cert, key, digest))
                try:
                    if not args.prepare:
                        run(["docker", "exec", args.container, "caddy", "reload", "--force", "--address", args.address, "--config", "/etc/caddy/Caddyfile", "--adapter", "caddyfile"])
                except (OSError, RuntimeError, subprocess.TimeoutExpired):
                    if previous is not None and not pair_matches:
                        switch_pair(args.target_dir, previous)
                    raise
                if not args.prepare:
                    # The live proxy has accepted this pair. A receipt failure
                    # must not revert the disk pair behind the running proxy.
                    atomic_write(state, digest)
                print(("prepared " if args.prepare else "reloaded ") + fingerprint)
                return
            except (OSError, RuntimeError, subprocess.TimeoutExpired) as error:
                if attempt == 2:
                    raise SystemExit(f"CDT certificate refresh failed: {error}")
                time.sleep(2)


if __name__ == "__main__":
    main()
