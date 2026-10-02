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

Manifest schema (v2)
--------------------
Each subfolder of the test-vector tree has its own ``manifest.json``.  The
script is invoked with ``--manifest <folder>/manifest.json``; all paths inside
the manifest are resolved relative to that file's directory.

  certificate (PEM)   ->  <cert_dir>/<name>.pem
  certificate (DER)   ->  <cert_dir>/<name>.der           (if "der" in cert_formats)
  certificate (chain) ->  <cert_dir>/<name>.chain.pem     (if chain_file = true)
  private key         ->  <key_dir>/<name>.key.pem
  slot KV             ->  <cert_dir>/<name>_slot.kv
  CRL (PEM)           ->  <cert_dir>/<name>.crl.pem
  CRL (DER)           ->  <cert_dir>/<name>.crl.der
  OCSP request        ->  <cert_dir>/<name>.ocsp.req.der
  OCSP response       ->  <cert_dir>/<name>.ocsp.resp.der

Manifest entry fields
---------------------
  name            string   Unique identifier within the manifest
  subject         string   OpenSSL -subj value  ("/CN=.../O=...")
  key_algorithm   string   RSA-2048 / EC-P256 / Ed25519 / ML-DSA-44 …
  purpose         string   (optional) human-readable description
  validity_days   int      (optional) overrides defaults.validity_days
  cert_dir        string   (optional) overrides defaults.cert_dir
  key_dir         string   (optional) overrides defaults.key_dir
  signed_by       string   (optional) name of issuer CA entry → issued cert path
  is_ca           bool     (optional) basicConstraints CA flag.
                           Defaults true for self-signed, false when signed_by is set.
  cert_formats    list     (optional) ["pem"] | ["der"] | ["pem","der"].
                           Overridden per-invocation by --cert-format.
  chain_file      bool     (optional) write <name>.chain.pem (leaf + ancestors)
  ext_file        string   (optional) path to a file containing a [v3_ext] OpenSSL
                           extension section.  Use for non-standard extensions
                           (SANs, OCSPSigning EKU, specific key usage, etc.).
                           The file must contain only the [v3_ext] stanza —
                           boilerplate [req] wrapper is added by the script.
                           Most certs do NOT need an ext_file.
  crl             object   (optional) CRL generation hints
    revoked       list     (optional) cert names whose serials appear in the CRL
  ocsp            object   (optional) OCSP generation hints
    signer        string   Name of the OCSP-signing cert entry (must carry
                           extendedKeyUsage = OCSPSigning in its ext_file)
    status        string   "good" | "revoked" (default "good")
    validity_days int      Response validity window in days (default 7)

Certificate signing (signed_by)
--------------------------------
Without ``signed_by``: self-signed via ``openssl req -x509``.
With ``signed_by``:    CSR via ``openssl req -new``, then signed via
                       ``openssl x509 -req -CA ... -CAkey ...``.
Issuer PEM and private key must be on disk before signing the leaf.

Extension customisation (ext_file)
------------------------------------
Provide a file containing only the ``[v3_ext]`` OpenSSL stanza:

  [v3_ext]
  basicConstraints = critical,CA:FALSE
  subjectKeyIdentifier = hash
  authorityKeyIdentifier = keyid
  extendedKeyUsage = OCSPSigning
  noCheck = ignored

Reference it from the manifest entry as ``"ext_file": "ocsp_signer.ext.conf"``.
The script injects the boilerplate [req] wrapper automatically so the file stays
minimal.  Omit ext_file for standard CA or leaf certs — the defaults are
sufficient for most test-vector purposes.

Actions
--------
  generate <name>   Generate a new key + certificate.
  update   <name>   Re-sign the certificate reusing the existing private key.
  crl      <name>   Generate a CRL signed by <name>; revokes crl.revoked entries.
  ocsp-req <name>   Generate a DER OCSP request for <name> against its issuer.
  ocsp-resp<name>   Generate a pre-computed DER OCSP response for <name>.

Example end-to-end (pki_chain folder):

  python generate_certificates.py generate root_ca        --manifest pki_chain/manifest.json
  python generate_certificates.py generate ocsp_signer    --manifest pki_chain/manifest.json
  python generate_certificates.py generate intermediate_ca --manifest pki_chain/manifest.json
  python generate_certificates.py generate leaf           --manifest pki_chain/manifest.json
  python generate_certificates.py crl root_ca             --manifest pki_chain/manifest.json
  python generate_certificates.py ocsp-req  leaf          --manifest pki_chain/manifest.json
  python generate_certificates.py ocsp-resp leaf          --manifest pki_chain/manifest.json
"""

from __future__ import annotations

import argparse
import datetime as datetime_module
import json
import pathlib
import subprocess
import tempfile
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
    alg = key_algorithm.upper()
    if alg.startswith("RSA-"):
        bits = alg[4:]
        if not bits.isdigit():
            raise SystemExit(f"Invalid RSA key size: {key_algorithm!r}")
        return ["-newkey", f"rsa:{bits}"]
    if alg in _EC_CURVES:
        return ["-newkey", "ec", "-pkeyopt", f"ec_paramgen_curve:{_EC_CURVES[alg]}"]
    if alg in _EDDSA_ALGS:
        return ["-newkey", alg.lower()]
    if alg in _MLDSA_LEVELS:
        return ["-newkey", alg.lower()]
    raise SystemExit(
        f"Unknown key_algorithm: {key_algorithm!r}. "
        "Supported: RSA-<bits>, EC-P256/P384/P521, Ed25519, Ed448, ML-DSA-44/65/87."
    )


def uses_separate_digest(key_algorithm: str) -> bool:
    alg = key_algorithm.upper()
    return alg.startswith("RSA-") or alg in _EC_CURVES


# ---------------------------------------------------------------------------
# Path derivation
# ---------------------------------------------------------------------------


def cert_path(root: pathlib.Path, defaults: dict[str, Any], entry: dict[str, Any]) -> pathlib.Path:
    cert_dir = entry.get("cert_dir", defaults.get("cert_dir", "."))
    return root / cert_dir / f"{entry['name']}.pem"


def cert_der_path(root: pathlib.Path, defaults: dict[str, Any], entry: dict[str, Any]) -> pathlib.Path:
    cert_dir = entry.get("cert_dir", defaults.get("cert_dir", "."))
    return root / cert_dir / f"{entry['name']}.der"


def cert_chain_path(root: pathlib.Path, defaults: dict[str, Any], entry: dict[str, Any]) -> pathlib.Path:
    cert_dir = entry.get("cert_dir", defaults.get("cert_dir", "."))
    return root / cert_dir / f"{entry['name']}.chain.pem"


def key_path(root: pathlib.Path, defaults: dict[str, Any], entry: dict[str, Any]) -> pathlib.Path:
    key_dir = entry.get("key_dir", defaults.get("key_dir", "private"))
    return root / key_dir / f"{entry['name']}.key.pem"


def slot_kv_path(root: pathlib.Path, defaults: dict[str, Any], entry: dict[str, Any]) -> pathlib.Path:
    cert_dir = entry.get("cert_dir", defaults.get("cert_dir", "."))
    return root / cert_dir / f"{entry['name']}_slot.kv"


def crl_pem_path(root: pathlib.Path, defaults: dict[str, Any], entry: dict[str, Any]) -> pathlib.Path:
    cert_dir = entry.get("cert_dir", defaults.get("cert_dir", "."))
    return root / cert_dir / f"{entry['name']}.crl.pem"


def crl_der_path(root: pathlib.Path, defaults: dict[str, Any], entry: dict[str, Any]) -> pathlib.Path:
    cert_dir = entry.get("cert_dir", defaults.get("cert_dir", "."))
    return root / cert_dir / f"{entry['name']}.crl.der"


def ocsp_req_path(root: pathlib.Path, defaults: dict[str, Any], entry: dict[str, Any]) -> pathlib.Path:
    cert_dir = entry.get("cert_dir", defaults.get("cert_dir", "."))
    return root / cert_dir / f"{entry['name']}.ocsp.req.der"


def ocsp_resp_path(root: pathlib.Path, defaults: dict[str, Any], entry: dict[str, Any]) -> pathlib.Path:
    cert_dir = entry.get("cert_dir", defaults.get("cert_dir", "."))
    return root / cert_dir / f"{entry['name']}.ocsp.resp.der"


def entry_validity_days(defaults: dict[str, Any], entry: dict[str, Any]) -> int:
    return int(entry.get("validity_days", defaults.get("validity_days", 3650)))


def resolve_cert_formats(
    defaults: dict[str, Any],
    entry: dict[str, Any],
    cli_override: str | None,
) -> list[str]:
    if cli_override is not None:
        return ["pem", "der"] if cli_override == "both" else [cli_override]
    raw: list[str] = entry.get("cert_formats", defaults.get("cert_formats", ["pem"]))
    seen: set[str] = set()
    result: list[str] = []
    for fmt in raw:
        fmt = fmt.lower()
        if fmt not in seen:
            seen.add(fmt)
            result.append(fmt)
    return result


# ---------------------------------------------------------------------------
# OpenSSL helpers
# ---------------------------------------------------------------------------


def run_openssl(openssl: str, arguments: list[str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run([openssl, *arguments], check=True, capture_output=True, text=True)


def annotate_pem(openssl: str, certificate_path: pathlib.Path) -> None:
    """Prepend human-readable x509 text to a PEM certificate file."""
    result = run_openssl(openssl, ["x509", "-in", str(certificate_path), "-text"])
    certificate_path.write_text(result.stdout, encoding="utf-8")


def annotate_crl_pem(openssl: str, crl_path: pathlib.Path) -> None:
    """Prepend human-readable CRL text to a PEM CRL file."""
    result = run_openssl(openssl, ["crl", "-in", str(crl_path), "-text"])
    crl_path.write_text(result.stdout, encoding="utf-8")


def parse_snapshot(openssl: str, certificate_path: pathlib.Path) -> dict[str, str]:
    result = run_openssl(
        openssl,
        ["x509", "-in", str(certificate_path), "-noout",
         "-subject", "-startdate", "-enddate", "-fingerprint", "-sha256"],
    )
    values: dict[str, str] = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value.strip()

    def parse_date(value: str) -> str:
        parsed = datetime_module.datetime.strptime(value, "%b %d %H:%M:%S %Y GMT")
        return parsed.replace(tzinfo=datetime_module.timezone.utc).isoformat().replace("+00:00", "Z")

    return {
        "not_before": parse_date(values["notBefore"]),
        "not_after": parse_date(values["notAfter"]),
        "sha256_fingerprint": values["sha256 Fingerprint"].replace(":", "").upper(),
    }


# ---------------------------------------------------------------------------
# Manifest I/O
# ---------------------------------------------------------------------------


def load_manifest(path: pathlib.Path) -> dict[str, Any]:
    with path.open(encoding="utf-8") as f:
        return json.load(f)  # type: ignore[no-any-return]


def save_manifest(path: pathlib.Path, manifest: dict[str, Any]) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)
        f.write("\n")


def find_certificate(manifest: dict[str, Any], name: str) -> dict[str, Any]:
    for entry in manifest["certificates"]:
        if entry["name"] == name:
            return entry  # type: ignore[no-any-return]
    names = ", ".join(e["name"] for e in manifest["certificates"])
    raise SystemExit(f"Unknown certificate '{name}'. Available: {names}")


# ---------------------------------------------------------------------------
# Slot KV descriptor
# ---------------------------------------------------------------------------


def _find_workspace_root(start: pathlib.Path) -> pathlib.Path | None:
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
    cert_format: str = "pem",
) -> pathlib.Path:
    kv_path = slot_kv_path(root, defaults, entry)
    target = (
        cert_path(root, defaults, entry)
        if cert_format == "pem"
        else cert_der_path(root, defaults, entry)
    )
    workspace_root = _find_workspace_root(root)
    if workspace_root is not None:
        try:
            cert_path_str = target.resolve().relative_to(workspace_root).as_posix()
        except ValueError:
            cert_path_str = target.name
    else:
        cert_path_str = target.name
    kv_path.write_text(
        f"[certificate]\ncert_path = {cert_path_str}\ncert_format = {cert_format}\n",
        encoding="utf-8",
    )
    return kv_path


# ---------------------------------------------------------------------------
# Extension file helpers
# ---------------------------------------------------------------------------


def _resolve_ext_file(
    root: pathlib.Path,
    entry: dict[str, Any],
) -> pathlib.Path | None:
    """Return the resolved ext_file path for an entry, or None if not set."""
    raw = entry.get("ext_file")
    if not raw:
        return None
    p = root / raw
    if not p.exists():
        raise SystemExit(f"ext_file not found: {p}")
    return p


def _build_ext_conf(
    tmp: pathlib.Path,
    is_ca: bool,
    ext_file: pathlib.Path | None,
) -> pathlib.Path:
    """Write a temp extension conf and return its path.

    If ext_file is provided, its [v3_ext] content is used verbatim (the script
    adds only the [req] wrapper needed by openssl req -x509).
    If absent, a minimal sensible default is generated from is_ca.
    """
    conf_path = tmp / "extensions.conf"
    if ext_file is not None:
        user_content = ext_file.read_text(encoding="utf-8")
        # Ensure the user section is named [v3_ext] (already required by docs)
        conf_path.write_text(user_content, encoding="utf-8")
    else:
        bc = "CA:TRUE" if is_ca else "CA:FALSE"
        conf_path.write_text(
            "[v3_ext]\n"
            f"basicConstraints = critical,{bc}\n"
            "subjectKeyIdentifier = hash\n"
            "authorityKeyIdentifier = keyid\n",
            encoding="utf-8",
        )
    return conf_path


def _build_req_conf(tmp: pathlib.Path, ext_conf: pathlib.Path) -> pathlib.Path:
    """Wrap an extension conf in a minimal [req] section for openssl req -x509."""
    req_conf = tmp / "req.conf"
    ext_content = ext_conf.read_text(encoding="utf-8")
    req_conf.write_text(
        "[req]\ndistinguished_name = _dn\nx509_extensions = v3_ext\n\n[_dn]\n\n"
        + ext_content,
        encoding="utf-8",
    )
    return req_conf


# ---------------------------------------------------------------------------
# Certificate generation
# ---------------------------------------------------------------------------


def _write_chain_file(
    root: pathlib.Path,
    defaults: dict[str, Any],
    entry: dict[str, Any],
    manifest: dict[str, Any],
) -> pathlib.Path:
    chain = cert_chain_path(root, defaults, entry)
    parts: list[str] = [cert_path(root, defaults, entry).read_text(encoding="utf-8")]
    current = entry
    while current.get("signed_by"):
        parent = find_certificate(manifest, current["signed_by"])
        parent_pem = cert_path(root, defaults, parent)
        if not parent_pem.exists():
            print(f"  Warning: ancestor '{current['signed_by']}' not found; chain truncated.")
            break
        parts.append(parent_pem.read_text(encoding="utf-8"))
        current = parent
    chain.write_text("".join(parts), encoding="utf-8")
    return chain


def generate_certificate(
    openssl: str,
    root: pathlib.Path,
    defaults: dict[str, Any],
    entry: dict[str, Any],
    update: bool,
    cert_formats: list[str],
    manifest: dict[str, Any],
) -> tuple[pathlib.Path, pathlib.Path]:
    """Generate or update a certificate.

    Self-signed path (no signed_by):  openssl req -x509.
    Issued path (signed_by present):  openssl req -new  →  openssl x509 -req.

    ext_file (optional manifest field):
      Provide a file with a [v3_ext] stanza to override the default extensions.
      The script wraps it in the boilerplate required by each OpenSSL command.
      Omit for standard CA or leaf certs.
    """
    pem = cert_path(root, defaults, entry)
    der = cert_der_path(root, defaults, entry)
    private_key = key_path(root, defaults, entry)
    pem.parent.mkdir(parents=True, exist_ok=True)
    private_key.parent.mkdir(parents=True, exist_ok=True)

    if update and not private_key.exists():
        raise SystemExit(f"Cannot update '{entry['name']}': key missing at {private_key}")

    signed_by_name: str | None = entry.get("signed_by")
    is_ca: bool = bool(entry.get("is_ca", signed_by_name is None))
    ext_file = _resolve_ext_file(root, entry)

    key_alg: str = entry["key_algorithm"]
    subject: str = entry["subject"]
    days: int = entry_validity_days(defaults, entry)
    leaf_digest = ["-sha256"] if uses_separate_digest(key_alg) else []

    if signed_by_name is not None:
        # ------------------------------------------------------------------ #
        # Issued certificate: CSR  →  sign with issuer CA                    #
        # ------------------------------------------------------------------ #
        issuer_entry = find_certificate(manifest, signed_by_name)
        issuer_cert = cert_path(root, defaults, issuer_entry)
        issuer_key = key_path(root, defaults, issuer_entry)
        issuer_digest = ["-sha256"] if uses_separate_digest(issuer_entry["key_algorithm"]) else []

        for p, label in [(issuer_cert, "issuer cert"), (issuer_key, "issuer key")]:
            if not p.exists():
                raise SystemExit(f"{label} for '{signed_by_name}' not found at {p}. "
                                 f"Run 'generate {signed_by_name}' first.")

        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = pathlib.Path(tmpdir)
            csr = tmp / "request.csr"
            ext_conf = _build_ext_conf(tmp, is_ca, ext_file)

            if update:
                csr_args = ["req", "-new", *leaf_digest, "-nodes",
                            "-key", str(private_key), "-subj", subject, "-out", str(csr)]
            else:
                csr_args = ["req", "-new", *leaf_digest, "-nodes",
                            *newkey_args(key_alg), "-keyout", str(private_key),
                            "-subj", subject, "-out", str(csr)]
            run_openssl(openssl, csr_args)

            run_openssl(openssl, [
                "x509", "-req", *issuer_digest,
                "-in", str(csr),
                "-CA", str(issuer_cert), "-CAkey", str(issuer_key), "-CAcreateserial",
                "-days", str(days),
                "-extfile", str(ext_conf), "-extensions", "v3_ext",
                "-out", str(pem),
            ])
    else:
        # ------------------------------------------------------------------ #
        # Self-signed: openssl req -x509                                      #
        # ------------------------------------------------------------------ #
        with tempfile.TemporaryDirectory() as tmpdir:
            tmp = pathlib.Path(tmpdir)
            ext_conf = _build_ext_conf(tmp, is_ca, ext_file)
            req_conf = _build_req_conf(tmp, ext_conf)

            args = [
                "req", "-x509", "-new", *leaf_digest, "-nodes",
                "-days", str(days), "-subj", subject,
                "-config", str(req_conf),
                "-out", str(pem),
            ]
            if update:
                args.extend(["-key", str(private_key)])
            else:
                args.extend([*newkey_args(key_alg), "-keyout", str(private_key)])
            run_openssl(openssl, args)

    annotate_pem(openssl, pem)
    entry["generated"] = parse_snapshot(openssl, pem)

    if entry.get("chain_file", False):
        chain = _write_chain_file(root, defaults, entry, manifest)
        print(f"  Wrote chain: {chain}")

    if "der" in cert_formats:
        run_openssl(openssl, ["x509", "-in", str(pem), "-outform", "DER", "-out", str(der)])

    if "pem" not in cert_formats:
        pem.unlink()

    primary_format = "pem" if "pem" in cert_formats else "der"
    primary = pem if primary_format == "pem" else der
    kv = write_slot_kv(root, defaults, entry, cert_format=primary_format)
    return primary, kv


# ---------------------------------------------------------------------------
# CRL generation
# ---------------------------------------------------------------------------


def _extract_cert_info(
    openssl: str,
    cert: pathlib.Path,
) -> tuple[str, str, str]:
    """Return (serial_upper, expiry_YYMMDDZ, subject_slash_dn) from a PEM cert."""
    serial = run_openssl(openssl, ["x509", "-in", str(cert), "-noout", "-serial"])
    serial_hex = serial.stdout.strip().split("=", 1)[1].upper()

    enddate = run_openssl(openssl, ["x509", "-in", str(cert), "-noout", "-enddate"])
    enddate_str = " ".join(enddate.stdout.strip().split("=", 1)[1].strip().split())
    dt = datetime_module.datetime.strptime(enddate_str, "%b %d %H:%M:%S %Y GMT")
    expiry = dt.strftime("%y%m%d%H%M%SZ")

    subj = run_openssl(openssl, ["x509", "-in", str(cert), "-noout", "-subject", "-nameopt", "compat"])
    subject = subj.stdout.strip().split("subject=", 1)[1].strip()

    return serial_hex, expiry, subject


def _add_revoked_entry(
    index_txt: pathlib.Path,
    revoked_cert: pathlib.Path,
    openssl: str,
) -> None:
    """Append an R (revoked) entry to an OpenSSL CA index.txt."""
    serial, expiry, subject = _extract_cert_info(openssl, revoked_cert)
    revdate = datetime_module.datetime.now(datetime_module.timezone.utc).strftime("%y%m%d%H%M%SZ")
    with index_txt.open("a", encoding="utf-8") as f:
        f.write(f"R\t{expiry}\t{revdate},unspecified\t{serial}\tunknown\t{subject}\n")


def _add_valid_entry(
    index_txt: pathlib.Path,
    cert: pathlib.Path,
    openssl: str,
) -> None:
    """Append a V (valid) entry to an OpenSSL CA index.txt."""
    serial, expiry, subject = _extract_cert_info(openssl, cert)
    with index_txt.open("a", encoding="utf-8") as f:
        # V entry: empty revocation date field
        f.write(f"V\t{expiry}\t\t{serial}\tunknown\t{subject}\n")


def generate_crl(
    openssl: str,
    root: pathlib.Path,
    defaults: dict[str, Any],
    entry: dict[str, Any],
    manifest: dict[str, Any],
) -> tuple[pathlib.Path, pathlib.Path]:
    """Generate a CA-signed CRL; revokes serials listed in crl.revoked."""
    ca_cert = cert_path(root, defaults, entry)
    ca_key = key_path(root, defaults, entry)
    out_pem = crl_pem_path(root, defaults, entry)
    out_der = crl_der_path(root, defaults, entry)

    for p, label in [(ca_cert, "CA cert"), (ca_key, "CA key")]:
        if not p.exists():
            raise SystemExit(f"{label} not found at {p}. Run 'generate {entry['name']}' first.")

    revoked_names: list[str] = entry.get("crl", {}).get("revoked", [])
    validity_days = entry_validity_days(defaults, entry)

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = pathlib.Path(tmpdir)
        (tmp / "newcerts").mkdir()
        index_txt = tmp / "index.txt"
        index_txt.touch()
        (tmp / "serial").write_text("01\n", encoding="utf-8")

        conf = (
            "[ca]\ndefault_ca = CA_default\n\n"
            "[CA_default]\n"
            f"dir              = {tmp}\n"
            "database         = $dir/index.txt\n"
            "new_certs_dir    = $dir/newcerts\n"
            "serial           = $dir/serial\n"
            f"private_key      = {ca_key}\n"
            f"certificate      = {ca_cert}\n"
            "default_md       = sha256\n"
            f"default_crl_days = {validity_days}\n"
            "preserve         = no\n"
            "policy           = policy_anything\n\n"
            "[policy_anything]\n"
            + "\n".join(f"{f} = optional" for f in [
                "countryName", "stateOrProvinceName", "localityName",
                "organizationName", "organizationalUnitName", "commonName", "emailAddress",
            ]) + "\n"
        )
        conf_path = tmp / "openssl.conf"
        conf_path.write_text(conf, encoding="utf-8")

        for name in revoked_names:
            rev_entry = find_certificate(manifest, name)
            rev_cert = cert_path(root, defaults, rev_entry)
            if not rev_cert.exists():
                raise SystemExit(f"Revoked cert '{name}' not found at {rev_cert}.")
            _add_revoked_entry(index_txt, rev_cert, openssl)
            print(f"  Added revoked entry: {name} ({rev_cert.name})")

        run_openssl(openssl, ["ca", "-gencrl", "-config", str(conf_path), "-out", str(out_pem)])

    annotate_crl_pem(openssl, out_pem)
    run_openssl(openssl, ["crl", "-in", str(out_pem), "-inform", "PEM", "-outform", "DER", "-out", str(out_der)])
    return out_pem, out_der


# ---------------------------------------------------------------------------
# OCSP generation
# ---------------------------------------------------------------------------


def generate_ocsp_request(
    openssl: str,
    root: pathlib.Path,
    defaults: dict[str, Any],
    entry: dict[str, Any],
    manifest: dict[str, Any],
) -> pathlib.Path:
    """Generate a DER OCSP request for <entry> against its issuer CA.

    Produces: <cert_dir>/<name>.ocsp.req.der
    Requires: signed_by is set and both cert + issuer cert are on disk.
    """
    signed_by_name = entry.get("signed_by")
    if not signed_by_name:
        raise SystemExit(
            f"'{entry['name']}' has no 'signed_by' — OCSP request requires a known issuer."
        )

    pem = cert_path(root, defaults, entry)
    issuer_pem = cert_path(root, defaults, find_certificate(manifest, signed_by_name))
    out = ocsp_req_path(root, defaults, entry)

    for p, label in [(pem, "cert"), (issuer_pem, "issuer cert")]:
        if not p.exists():
            raise SystemExit(f"{label} not found at {p}.")

    run_openssl(openssl, [
        "ocsp",
        "-issuer", str(issuer_pem),
        "-cert", str(pem),
        "-reqout", str(out),
    ])
    return out


def generate_ocsp_response(
    openssl: str,
    root: pathlib.Path,
    defaults: dict[str, Any],
    entry: dict[str, Any],
    manifest: dict[str, Any],
) -> pathlib.Path:
    """Generate a pre-computed DER OCSP response for <entry>.

    Manifest fields read from entry.ocsp:
      signer        name of the OCSP-signing cert (must carry OCSPSigning EKU)
      status        "good" | "revoked"  (default "good")
      validity_days response validity window in days (default 7)

    Produces: <cert_dir>/<name>.ocsp.resp.der

    The response is generated offline (no running OCSP responder) by building a
    temporary CA index.txt with the cert's status and calling
    ``openssl ocsp -rsigner ... -index ...``.
    """
    ocsp_cfg: dict[str, Any] = entry.get("ocsp", {})
    signer_name: str | None = ocsp_cfg.get("signer")
    status: str = ocsp_cfg.get("status", "good")
    validity_days: int = int(ocsp_cfg.get("validity_days", 7))

    if not signer_name:
        raise SystemExit(
            f"'{entry['name']}' missing ocsp.signer — OCSP response requires a signing cert."
        )
    signed_by_name = entry.get("signed_by")
    if not signed_by_name:
        raise SystemExit(f"'{entry['name']}' has no 'signed_by' — cannot determine issuer.")

    pem = cert_path(root, defaults, entry)
    issuer_pem = cert_path(root, defaults, find_certificate(manifest, signed_by_name))
    signer_entry = find_certificate(manifest, signer_name)
    signer_pem = cert_path(root, defaults, signer_entry)
    signer_key = key_path(root, defaults, signer_entry)
    out = ocsp_resp_path(root, defaults, entry)

    for p, label in [
        (pem, "cert"), (issuer_pem, "issuer"), (signer_pem, "OCSP signer"), (signer_key, "OCSP signer key"),
    ]:
        if not p.exists():
            raise SystemExit(f"{label} not found at {p}.")

    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = pathlib.Path(tmpdir)
        index_txt = tmp / "index.txt"
        index_txt.touch()

        if status == "revoked":
            _add_revoked_entry(index_txt, pem, openssl)
        else:
            _add_valid_entry(index_txt, pem, openssl)

        run_openssl(openssl, [
            "ocsp",
            "-issuer", str(issuer_pem),
            "-cert", str(pem),
            "-rsigner", str(signer_pem),
            "-rkey", str(signer_key),
            "-CA", str(issuer_pem),
            "-ndays", str(validity_days),
            "-index", str(index_txt),
            "-respout", str(out),
        ])

    return out


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument(
        "action",
        choices=["generate", "update", "crl", "ocsp-req", "ocsp-resp"],
    )
    parser.add_argument("name", help="Manifest certificate name")
    parser.add_argument(
        "--manifest",
        type=pathlib.Path,
        default=pathlib.Path(__file__).with_name("certificate_manifest.json"),
        help="Path to the manifest.json for the target folder (default: adjacent certificate_manifest.json)",
    )
    parser.add_argument("--openssl", default="openssl", help="OpenSSL executable")
    parser.add_argument(
        "--cert-format",
        dest="cert_format",
        choices=["pem", "der", "both"],
        default=None,
        help=(
            "Output format(s) for the certificate (generate/update only). "
            "Overrides the entry's cert_formats manifest field. "
            "'both' writes PEM and DER side by side."
        ),
    )
    args = parser.parse_args()

    manifest_path = args.manifest.resolve()
    manifest = load_manifest(manifest_path)
    defaults: dict[str, Any] = manifest.get("defaults", {})
    entry = find_certificate(manifest, args.name)
    root = manifest_path.parent

    if args.action == "crl":
        if args.cert_format is not None:
            parser.error("--cert-format is only valid for generate/update")
        pem_out, der_out = generate_crl(args.openssl, root, defaults, entry, manifest)
        print(f"Wrote {pem_out}")
        print(f"Wrote {der_out}")

    elif args.action == "ocsp-req":
        if args.cert_format is not None:
            parser.error("--cert-format is only valid for generate/update")
        out = generate_ocsp_request(args.openssl, root, defaults, entry, manifest)
        print(f"Wrote {out}")

    elif args.action == "ocsp-resp":
        if args.cert_format is not None:
            parser.error("--cert-format is only valid for generate/update")
        out = generate_ocsp_response(args.openssl, root, defaults, entry, manifest)
        print(f"Wrote {out}")

    else:  # generate / update
        cert_formats = resolve_cert_formats(defaults, entry, args.cert_format)
        primary, kv = generate_certificate(
            args.openssl, root, defaults, entry,
            update=args.action == "update",
            cert_formats=cert_formats,
            manifest=manifest,
        )
        save_manifest(manifest_path, manifest)
        print(f"Wrote {primary}")
        if "der" in cert_formats:
            der = cert_der_path(root, defaults, entry)
            if der.exists():
                print(f"Wrote {der}")
        print(f"Wrote {kv}")
        print(json.dumps(entry["generated"], indent=2))


if __name__ == "__main__":
    main()
