#!/usr/bin/env python3
# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

"""Generate or refresh certificate-management test certificates from a manifest.

Supported key_algorithm values in the manifest:

  RSA        RSA-2048, RSA-3072, RSA-4096
  EC         EC-P256, EC-P384, EC-P521
  EdDSA      Ed25519, Ed448
  PQC        ML-DSA-44, ML-DSA-65, ML-DSA-87  (NIST FIPS 204, OpenSSL >= 3.5)

The key_algorithm field drives both the -newkey arguments and whether an
explicit message-digest flag (-sha256) is passed to openssl req.  Ed25519,
Ed448, and ML-DSA variants carry their own inherent digest and must not
receive -sha256.

Manifest schema (v2)
--------------------
Paths are derived from the entry ``name`` field and the top-level ``defaults``
block — they are not stored redundantly in each entry.  Convention:

  certificate  ->  <cert_dir>/<name>.pem            (default cert_dir = ".")
  private key  ->  <key_dir>/<name>.key.pem          (default key_dir = "private")
  slot KV      ->  <cert_dir>/<name>_slot.kv

The ``generated`` block within each entry is written by this script after a
successful generation run and must not be edited by hand.
"""

from __future__ import annotations

import argparse
import datetime as datetime_module
import json
import pathlib
import subprocess
from typing import Any

# ---------------------------------------------------------------------------
# Algorithm tables
# ---------------------------------------------------------------------------

_EC_CURVES: dict[str, str] = {
    "EC-P256": "P-256",
    "EC-P384": "P-384",
    "EC-P521": "P-521",
}
_EDDSA_ALGS: frozenset[str] = frozenset({"ED25519", "ED448"})
_MLDSA_LEVELS: frozenset[str] = frozenset({"ML-DSA-44", "ML-DSA-65", "ML-DSA-87"})


def newkey_args(key_algorithm: str) -> list[str]:
    """Return the -newkey flag sequence for *openssl req -x509*.

    The returned list is ready to extend() into the openssl argument list
    during key generation (not used for the ``update`` path which reuses an
    existing key with -key).
    """
    alg = key_algorithm.upper()

    if alg.startswith("RSA-"):
        bits = alg[4:]
        if not bits.isdigit():
            raise SystemExit(f"Invalid RSA key size in key_algorithm: {key_algorithm!r}")
        return ["-newkey", f"rsa:{bits}"]

    if alg in _EC_CURVES:
        curve = _EC_CURVES[alg]
        return ["-newkey", "ec", "-pkeyopt", f"ec_paramgen_curve:{curve}"]

    if alg in _EDDSA_ALGS:
        return ["-newkey", alg.lower()]  # ed25519 / ed448

    if alg in _MLDSA_LEVELS:
        return ["-newkey", alg.lower()]  # ml-dsa-44 / ml-dsa-65 / ml-dsa-87

    raise SystemExit(
        f"Unknown key_algorithm: {key_algorithm!r}. "
        f"Supported: RSA-<bits>, EC-P256/P384/P521, Ed25519, Ed448, "
        f"ML-DSA-44/65/87."
    )


def uses_separate_digest(key_algorithm: str) -> bool:
    """True for RSA and EC where an explicit hash algorithm can be selected.

    Ed25519, Ed448, and ML-DSA carry their own inherent digest; passing
    -sha256 to openssl req for these algorithms is incorrect and may produce
    an error on strict OpenSSL builds.
    """
    alg = key_algorithm.upper()
    return alg.startswith("RSA-") or alg in _EC_CURVES


# ---------------------------------------------------------------------------
# Path derivation
# ---------------------------------------------------------------------------


def cert_path(root: pathlib.Path, defaults: dict[str, Any], entry: dict[str, Any]) -> pathlib.Path:
    cert_dir = entry.get("cert_dir", defaults.get("cert_dir", "."))
    return root / cert_dir / f"{entry['name']}.pem"


def key_path(root: pathlib.Path, defaults: dict[str, Any], entry: dict[str, Any]) -> pathlib.Path:
    key_dir = entry.get("key_dir", defaults.get("key_dir", "private"))
    return root / key_dir / f"{entry['name']}.key.pem"


def slot_kv_path(root: pathlib.Path, defaults: dict[str, Any], entry: dict[str, Any]) -> pathlib.Path:
    cert_dir = entry.get("cert_dir", defaults.get("cert_dir", "."))
    return root / cert_dir / f"{entry['name']}_slot.kv"


def entry_validity_days(defaults: dict[str, Any], entry: dict[str, Any]) -> int:
    return int(entry.get("validity_days", defaults.get("validity_days", 3650)))


# ---------------------------------------------------------------------------
# OpenSSL helpers
# ---------------------------------------------------------------------------


def run_openssl(openssl: str, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([openssl, *arguments], check=True, capture_output=True, text=True)


def annotate_pem(openssl: str, certificate_path: pathlib.Path) -> None:
    """Prepend human-readable certificate info to a PEM file.

    Runs ``openssl x509 -text`` which outputs the decoded fields followed by
    the PEM block.  The result is written back to the same file so the cert
    remains machine-parseable while also being human-readable at a glance.
    Most PEM parsers (OpenSSL, Python cryptography, etc.) skip the text header
    and process only the base64 armored block.
    """
    result = run_openssl(openssl, ["x509", "-in", str(certificate_path), "-text"])
    certificate_path.write_text(result.stdout, encoding="utf-8")


def parse_snapshot(openssl: str, certificate_path: pathlib.Path) -> dict[str, str]:
    result = run_openssl(
        openssl,
        [
            "x509",
            "-in",
            str(certificate_path),
            "-noout",
            "-subject",
            "-startdate",
            "-enddate",
            "-fingerprint",
            "-sha256",
        ],
    )
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value.strip()

    def parse_date(value: str) -> str:
        parsed = datetime_module.datetime.strptime(value, "%b %d %H:%M:%S %Y GMT")
        return parsed.replace(tzinfo=datetime_module.timezone.utc).isoformat().replace("+00:00", "Z")

    fingerprint: str = values["sha256 Fingerprint"].replace(":", "").upper()
    return {
        "not_before": parse_date(values["notBefore"]),
        "not_after": parse_date(values["notAfter"]),
        "sha256_fingerprint": fingerprint,
    }


# ---------------------------------------------------------------------------
# Manifest I/O
# ---------------------------------------------------------------------------


def load_manifest(path: pathlib.Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as manifest_file:
        return json.load(manifest_file)  # type: ignore[no-any-return]


def save_manifest(path: pathlib.Path, manifest: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as manifest_file:
        json.dump(manifest, manifest_file, indent=2)
        manifest_file.write("\n")


def find_certificate(manifest: dict[str, Any], name: str) -> dict[str, Any]:
    for certificate in manifest["certificates"]:
        if certificate["name"] == name:
            return certificate  # type: ignore[no-any-return]
    names = ", ".join(entry["name"] for entry in manifest["certificates"])
    raise SystemExit(f"Unknown certificate '{name}'. Available names: {names}")


# ---------------------------------------------------------------------------
# Slot KV descriptor
# ---------------------------------------------------------------------------


def _find_workspace_root(start: pathlib.Path) -> pathlib.Path | None:
    """Walk upward from *start* looking for a Bazel workspace marker file."""
    path = start.resolve()
    for _ in range(12):
        for marker in ("MODULE.bazel", "WORKSPACE.bazel", "WORKSPACE", ".git"):
            if (path / marker).exists():
                return path
        parent = path.parent
        if parent == path:
            break
        path = parent
    return None


def write_slot_kv(
    root: pathlib.Path,
    defaults: dict[str, Any],
    entry: dict[str, Any],
) -> pathlib.Path:
    """Write a KV slot descriptor alongside the generated certificate.

    The cert_path inside the descriptor uses a workspace-relative path so that
    tests can reference the descriptor directly from the Bazel runfiles root
    without copying or modifying it at runtime.

    Workspace root discovery is done via marker-file search (MODULE.bazel,
    WORKSPACE.bazel, WORKSPACE, .git) so the path is computed correctly
    regardless of whether Python is invoked via a WSL executable, a Windows
    native interpreter, or a Unix shell from any working directory.
    """
    kv_path = slot_kv_path(root, defaults, entry)
    pem_path = cert_path(root, defaults, entry)

    workspace_root = _find_workspace_root(root)
    if workspace_root is not None:
        try:
            cert_path_str = pem_path.resolve().relative_to(workspace_root).as_posix()
        except ValueError:
            cert_path_str = pem_path.name
    else:
        # Last-resort fallback: use the filename only; the test must locate it
        # relative to its own runfiles root.
        cert_path_str = pem_path.name

    kv_path.write_text(
        f"[certificate]\ncert_path = {cert_path_str}\ncert_format = pem\n",
        encoding="utf-8",
    )
    return kv_path


# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------


def generate_certificate(
    openssl: str,
    root: pathlib.Path,
    defaults: dict[str, Any],
    entry: dict[str, Any],
    update: bool,
) -> tuple[pathlib.Path, pathlib.Path]:
    certificate_path = cert_path(root, defaults, entry)
    private_key_path = key_path(root, defaults, entry)
    certificate_path.parent.mkdir(parents=True, exist_ok=True)
    private_key_path.parent.mkdir(parents=True, exist_ok=True)

    if update and not private_key_path.exists():
        raise SystemExit(
            f"Cannot update '{entry['name']}': private key is missing at {private_key_path}"
        )

    key_alg: str = entry["key_algorithm"]
    subject: str = entry["subject"]
    days: int = entry_validity_days(defaults, entry)

    digest_flags = ["-sha256"] if uses_separate_digest(key_alg) else []
    arguments = [
        "req",
        "-x509",
        "-new",
        *digest_flags,
        "-nodes",
        "-days",
        str(days),
        "-subj",
        subject,
        "-out",
        str(certificate_path),
        "-addext",
        "basicConstraints=critical,CA:TRUE",
        "-addext",
        "subjectKeyIdentifier=hash",
        "-addext",
        "authorityKeyIdentifier=keyid",
    ]
    if update:
        arguments.extend(["-key", str(private_key_path)])
    else:
        arguments.extend([*newkey_args(key_alg), "-keyout", str(private_key_path)])

    run_openssl(openssl, arguments)
    annotate_pem(openssl, certificate_path)
    entry["generated"] = parse_snapshot(openssl, certificate_path)
    kv = write_slot_kv(root, defaults, entry)
    return certificate_path, kv


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=["generate", "update"])
    parser.add_argument("name", help="Manifest certificate name")
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("certificate_manifest.json"),
    )
    parser.add_argument("--openssl", default="openssl", help="OpenSSL executable")
    args = parser.parse_args()

    manifest_path = args.manifest.resolve()
    manifest = load_manifest(manifest_path)
    defaults: dict[str, Any] = manifest.get("defaults", {})
    entry = find_certificate(manifest, args.name)
    certificate_path, kv_path = generate_certificate(
        args.openssl,
        manifest_path.parent,
        defaults,
        entry,
        update=args.action == "update",
    )
    save_manifest(manifest_path, manifest)
    print(f"Wrote {certificate_path}")
    print(f"Wrote {kv_path}")
    print(json.dumps(entry["generated"], indent=2))


if __name__ == "__main__":
    main()
