#!/usr/bin/env python3
"""Generate or refresh certificate-management test certificates from a manifest."""

import argparse
import datetime as datetime_module
import json
import pathlib
import subprocess


def run_openssl(openssl, arguments):
    return subprocess.run([openssl, *arguments], check=True, capture_output=True, text=True)


def parse_snapshot(openssl, certificate_path):
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
    values = {}
    for line in result.stdout.splitlines():
        key, separator, value = line.partition("=")
        if separator:
            values[key] = value.strip()

    def parse_date(value):
        parsed = datetime_module.datetime.strptime(value, "%b %d %H:%M:%S %Y GMT")
        return parsed.replace(tzinfo=datetime_module.timezone.utc).isoformat().replace("+00:00", "Z")

    fingerprint = values["sha256 Fingerprint"].replace(":", "").upper()
    return {
        "not_before": parse_date(values["notBefore"]),
        "not_after": parse_date(values["notAfter"]),
        "sha256_fingerprint": fingerprint,
    }


def load_manifest(path):
    with path.open(encoding="utf-8") as manifest_file:
        return json.load(manifest_file)


def save_manifest(path, manifest):
    with path.open("w", encoding="utf-8") as manifest_file:
        json.dump(manifest, manifest_file, indent=2)
        manifest_file.write("\n")


def find_certificate(manifest, name):
    for certificate in manifest["certificates"]:
        if certificate["name"] == name:
            return certificate
    names = ", ".join(entry["name"] for entry in manifest["certificates"])
    raise SystemExit(f"Unknown certificate '{name}'. Available names: {names}")


def write_slot_kv(root, certificate):
    """Write a KV slot descriptor alongside the generated certificate.

    The cert_path inside the descriptor uses a workspace-relative path so that
    tests can reference the descriptor directly from the Bazel runfiles root
    without copying or modifying it at runtime.
    """
    cert_rel = pathlib.Path(certificate["certificate_path"])
    kv_name = cert_rel.stem + "_slot.kv"
    kv_path = root / kv_name

    try:
        workspace_cert = (root / cert_rel).relative_to(pathlib.Path.cwd())
        cert_path_str = workspace_cert.as_posix()
    except ValueError:
        # Fallback when the script is not invoked from the workspace root.
        cert_path_str = str(root / cert_rel)

    kv_path.write_text(
        f"[certificate]\ncert_path = {cert_path_str}\ncert_format = pem\n",
        encoding="utf-8",
    )
    return kv_path


def generate_certificate(openssl, root, certificate, update):
    certificate_path = root / certificate["certificate_path"]
    key_path = root / certificate["private_key_path"]
    certificate_path.parent.mkdir(parents=True, exist_ok=True)
    key_path.parent.mkdir(parents=True, exist_ok=True)

    if update and not key_path.exists():
        raise SystemExit(f"Cannot update '{certificate['name']}': private key is missing at {key_path}")

    subject = certificate["subject"]
    arguments = [
        "req",
        "-x509",
        "-new",
        "-sha256",
        "-nodes",
        "-days",
        str(certificate["validity_days"]),
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
        arguments.extend(["-key", str(key_path)])
    else:
        arguments.extend(["-newkey", "rsa:2048", "-keyout", str(key_path)])
    run_openssl(openssl, arguments)
    certificate["snapshot"] = parse_snapshot(openssl, certificate_path)
    kv_path = write_slot_kv(root, certificate)
    return certificate_path, kv_path


def main():
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
    certificate = find_certificate(manifest, args.name)
    certificate_path, kv_path = generate_certificate(
        args.openssl,
        manifest_path.parent,
        certificate,
        update=args.action == "update",
    )
    save_manifest(manifest_path, manifest)
    print(f"Wrote {certificate_path}")
    print(f"Wrote {kv_path}")
    print(json.dumps(certificate["snapshot"], indent=2))


if __name__ == "__main__":
    main()
