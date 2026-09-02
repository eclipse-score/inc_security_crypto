<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# Certificate Test Vectors

This directory contains PKI test vectors for the certificate-management daemon
component. Certificates are organized into purpose-driven subfolders, each with
its own `manifest.json` inventory file.

```
certificate/
├── generate_certificates.py   # Shared generation script
├── basic/                     # Primary RSA-2048 PKI — used by most tests
│   ├── manifest.json
│   ├── certificate.pem        # Root CA  (CN=cert-management-test)
│   ├── certificate_slot.kv
│   ├── certificate_updated.pem # Rotated CA  (CN=cert-management-updated)
│   ├── certificate_updated_slot.kv
│   ├── certificate_leaf.pem   # End-entity, signed by certificate CA
│   ├── certificate_leaf.der
│   ├── certificate_leaf.chain.pem
│   ├── certificate_leaf_slot.kv
│   ├── certificate.crl.pem    # CRL issued by certificate, revokes leaf
│   ├── certificate.crl.der
│   ├── trust_store.kv         # Empty trust-store state fixture
│   └── private/               # NOT committed — local keys only
│
├── algorithm_variety/         # One self-signed CA per key algorithm
│   ├── manifest.json
│   ├── rsa_3072.pem,    rsa_3072_slot.kv
│   ├── rsa_4096.pem,    rsa_4096_slot.kv
│   ├── ec_p256.pem,     ec_p256_slot.kv
│   ├── ec_p384.pem,     ec_p384_slot.kv
│   ├── ec_p521.pem,     ec_p521_slot.kv
│   ├── ed25519.pem,     ed25519_slot.kv
│   ├── ed448.pem,       ed448_slot.kv
│   ├── ml_dsa_44.pem,   ml_dsa_44_slot.kv
│   ├── ml_dsa_65.pem,   ml_dsa_65_slot.kv
│   ├── ml_dsa_87.pem,   ml_dsa_87_slot.kv
│   └── private/
│
└── pki_chain/                 # Future: root → intermediate → leaf + OCSP
    ├── manifest.json
    ├── ocsp_signer.ext.conf   # Extension config for the OCSP signing cert
    └── private/
```

Private keys live under each folder's `private/` directory and are ignored by
Git. Never commit them. All PEM files carry a human-readable header (produced by
`openssl x509 -text` or `openssl crl -text`) before the `-----BEGIN ...-----`
block; this header is ignored by all conforming PEM parsers.

---

## Certificate inventory

### `basic/`

| Name | Algorithm | Role | Purpose |
|------|-----------|------|---------|
| `certificate` | RSA-2048 | Root CA (self-signed) | Primary CA for slot and trust-store tests |
| `certificate_updated` | RSA-2048 | Root CA (self-signed) | Replacement CA for slot-rotation and anchor-invalidation tests |
| `certificate_leaf` | RSA-2048 | End-entity, issued by `certificate` | Signed leaf; subject of the CRL; demonstrates chain, DER, and revocation |

Associated artifacts: `certificate.crl.pem/.der` (CRL revoking `certificate_leaf`),
`certificate_leaf.chain.pem` (leaf + root CA bundle).

### `algorithm_variety/`

| Name | Algorithm | Purpose |
|------|-----------|---------|
| `rsa_3072` | RSA-3072 | RSA key-size variety |
| `rsa_4096` | RSA-4096 | RSA key-size variety |
| `ec_p256` | EC P-256 | ECDSA elliptic-curve algorithm tests |
| `ec_p384` | EC P-384 | ECDSA elliptic-curve algorithm tests |
| `ec_p521` | EC P-521 | ECDSA elliptic-curve algorithm tests |
| `ed25519` | Ed25519 | Edwards-curve algorithm tests |
| `ed448` | Ed448 | Edwards-curve algorithm tests |
| `ml_dsa_44` | ML-DSA-44 | Post-quantum (NIST FIPS 204, level 2) |
| `ml_dsa_65` | ML-DSA-65 | Post-quantum (NIST FIPS 204, level 3) |
| `ml_dsa_87` | ML-DSA-87 | Post-quantum (NIST FIPS 204, level 5) |

PQC support requires OpenSSL ≥ 3.5.

### `pki_chain/` (future)

Three-level PKI for chain-verification and OCSP tests. No certificates are
committed yet. Generate in the order listed in `pki_chain/manifest.json`
under `_generation_order`.

---

## Supported `key_algorithm` values

| Family | Values |
|--------|--------|
| RSA | `RSA-2048`, `RSA-3072`, `RSA-4096` (any `RSA-<bits>`) |
| EC | `EC-P256`, `EC-P384`, `EC-P521` |
| EdDSA | `Ed25519`, `Ed448` |
| PQC | `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` |

---

## Generating and refreshing certificates

The `generate_certificates.py` script is invoked from the repository root and
always requires `--manifest` pointing to the folder whose certificates you want
to work with.

### Actions

| Action | Description |
|--------|-------------|
| `generate <name>` | Create a new private key and certificate |
| `update <name>` | Re-sign the certificate reusing the existing local private key |
| `crl <name>` | Sign a CRL for `<name>`; revokes entries in `crl.revoked` |
| `ocsp-req <name>` | Generate a DER OCSP request for `<name>` against its issuer |
| `ocsp-resp <name>` | Generate a pre-computed DER OCSP response for `<name>` |

### Common flags

| Flag | Description |
|------|-------------|
| `--manifest <path>` | Path to the folder's `manifest.json` (required) |
| `--cert-format pem\|der\|both` | Override the entry's `cert_formats` for one invocation |
| `--openssl <path>` | Path to the OpenSSL executable (default: `openssl`) |

### Examples

```sh
# Regenerate the primary CA (new key + cert):
python3 score/tests/test_vectors/certificate/generate_certificates.py \
  generate certificate --manifest score/tests/test_vectors/certificate/basic/manifest.json

# Regenerate the leaf cert (reuses CA key, signs a new CSR):
python3 score/tests/test_vectors/certificate/generate_certificates.py \
  generate certificate_leaf \
  --manifest score/tests/test_vectors/certificate/basic/manifest.json

# Generate the CA CRL that lists the leaf as revoked:
python3 score/tests/test_vectors/certificate/generate_certificates.py \
  crl certificate \
  --manifest score/tests/test_vectors/certificate/basic/manifest.json

# Regenerate an algorithm-variety cert (update keeps the existing key):
python3 score/tests/test_vectors/certificate/generate_certificates.py \
  update ec_p256 \
  --manifest score/tests/test_vectors/certificate/algorithm_variety/manifest.json

# Generate a cert in both PEM and DER (overrides manifest for this run):
python3 score/tests/test_vectors/certificate/generate_certificates.py \
  generate certificate_leaf --cert-format both \
  --manifest score/tests/test_vectors/certificate/basic/manifest.json

# Generate an OCSP request for the pki_chain leaf (once certs exist):
python3 score/tests/test_vectors/certificate/generate_certificates.py \
  ocsp-req leaf \
  --manifest score/tests/test_vectors/certificate/pki_chain/manifest.json

# Generate a pre-computed OCSP response:
python3 score/tests/test_vectors/certificate/generate_certificates.py \
  ocsp-resp leaf \
  --manifest score/tests/test_vectors/certificate/pki_chain/manifest.json
```

After running `generate` or `update`, commit the PEM, any DER/chain/CRL/OCSP
artifacts, the `<name>_slot.kv` descriptor, and the updated `manifest.json`
together. Do not commit private keys.

---

## Manifest schema reference

Each `manifest.json` follows schema version 2. All paths are resolved relative
to the manifest file's directory.

### Entry fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `name` | string | yes | Unique identifier within the manifest |
| `subject` | string | yes | OpenSSL `-subj` value (`/CN=.../O=...`) |
| `key_algorithm` | string | yes | See supported values above |
| `purpose` | string | no | Human-readable description |
| `validity_days` | int | no | Overrides `defaults.validity_days` |
| `cert_dir` | string | no | Overrides `defaults.cert_dir` |
| `key_dir` | string | no | Overrides `defaults.key_dir` |
| `signed_by` | string | no | Name of the issuer CA entry — produces an issued cert instead of self-signed |
| `is_ca` | bool | no | `basicConstraints` CA flag. Defaults `true` for self-signed, `false` when `signed_by` is set |
| `cert_formats` | list | no | `["pem"]` (default), `["der"]`, or `["pem","der"]` |
| `chain_file` | bool | no | Write `<name>.chain.pem` (leaf + all ancestors up to root) |
| `ext_file` | string | no | Path to a file containing a `[v3_ext]` OpenSSL extension stanza. Use only when you need non-default extensions (SANs, `OCSPSigning` EKU, etc.). The script adds the required `[req]` wrapper automatically. |
| `crl.revoked` | list | no | Cert names whose serials appear in the CRL signed by this entry |
| `ocsp.signer` | string | no | Name of the OCSP-signing cert entry (must carry `OCSPSigning` EKU) |
| `ocsp.status` | string | no | `"good"` (default) or `"revoked"` |
| `ocsp.validity_days` | int | no | OCSP response validity window in days (default 7) |
| `generated` | object | auto | Written by the script after generation. Do not edit by hand. |

### When to use `ext_file`

Most certificates do **not** need an `ext_file`. The script generates sensible
defaults from `is_ca`:

- `is_ca: true` → `basicConstraints=critical,CA:TRUE` + `subjectKeyIdentifier` + `authorityKeyIdentifier`
- `is_ca: false` → same, with `CA:FALSE`

Provide an `ext_file` only when you need extensions the script cannot infer,
such as:

```ini
# Example: pki_chain/ocsp_signer.ext.conf
[v3_ext]
basicConstraints = critical,CA:FALSE
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid
extendedKeyUsage = OCSPSigning
noCheck = ignored
```

The file must contain only the `[v3_ext]` section. Reference it from the
manifest as `"ext_file": "ocsp_signer.ext.conf"`.

---

## Adding a new certificate

1. Decide which folder it belongs to (`basic/`, `algorithm_variety/`,
   `pki_chain/`, or a new folder for a new PKI context).
2. Add an entry to that folder's `manifest.json` with at minimum `name`,
   `subject`, and `key_algorithm`. Add `signed_by` if it should be issued by an
   existing CA rather than self-signed.
3. Run `generate_certificates.py generate <name> --manifest <folder>/manifest.json`.
4. Commit the PEM, KV descriptor, and updated `manifest.json`. If `chain_file`
   or DER output was requested, commit those too. Never commit private keys.

## Adding a new PKI context (new folder)

1. Create the folder and a `private/` subfolder (the `private/` subfolder stays
   untracked; optionally add a `.gitignore` inside it).
2. Create `manifest.json` following the schema above with `"schema_version": 2`
   and appropriate `defaults`.
3. If certs in this PKI have non-standard extensions, create the `.ext.conf`
   sidecar file alongside the manifest.
4. Add a new `filegroup` target for the folder in `BUILD` and add it to the
   `certificate_test_vectors` srcs list.
5. Generate certs in dependency order (issuers before leaves).
