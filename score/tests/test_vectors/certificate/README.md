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

`certificate_manifest.json` is the inventory for certificate-management test
certificates. It records each certificate's purpose, subject, key algorithm,
private-key location, validity policy, and the metadata snapshot of the
checked-in public certificate.

Private keys are generated locally under `private/` and are ignored by Git.
Never commit them. The checked-in certificates use a long validity period
because their private keys are intentionally not stored in the public repository.

## Certificate inventory

| Name | Algorithm | Purpose |
|------|-----------|---------|
| `certificate` | RSA-2048 | Primary CA cert for file-backed slot and trust-store tests |
| `certificate_updated` | RSA-2048 | Replacement CA cert for slot-update and anchor-invalidation tests |
| `rsa_3072` | RSA-3072 | RSA key-size variety |
| `rsa_4096` | RSA-4096 | RSA key-size variety |
| `ec_p256` | EC P-256 | ECDSA elliptic-curve algorithm tests |
| `ec_p384` | EC P-384 | ECDSA elliptic-curve algorithm tests |
| `ec_p521` | EC P-521 | ECDSA elliptic-curve algorithm tests |
| `ed25519` | Ed25519 | Edwards-curve algorithm tests |
| `ed448` | Ed448 | Edwards-curve algorithm tests |
| `ml_dsa_44` | ML-DSA-44 | Post-quantum tests (NIST FIPS 204, security level 2) |
| `ml_dsa_65` | ML-DSA-65 | Post-quantum tests (NIST FIPS 204, security level 3) |
| `ml_dsa_87` | ML-DSA-87 | Post-quantum tests (NIST FIPS 204, security level 5) |

All PEM files carry a human-readable header (produced by `openssl x509 -text`)
before the `-----BEGIN CERTIFICATE-----` block. This header is ignored by all
conforming PEM parsers and is present only for readability.

## Supported `key_algorithm` values

The `generate_certificates.py` script accepts the following values for the
`key_algorithm` field in the manifest:

| Family | Values |
|--------|--------|
| RSA | `RSA-2048`, `RSA-3072`, `RSA-4096` (any `RSA-<bits>`) |
| EC | `EC-P256`, `EC-P384`, `EC-P521` |
| EdDSA | `Ed25519`, `Ed448` |
| PQC | `ML-DSA-44`, `ML-DSA-65`, `ML-DSA-87` |

PQC support requires OpenSSL ≥ 3.5 (ML-DSA is in the OpenSSL default provider).

## Generating and refreshing certificates

From the repository root, generate a certificate and its local key with:

```sh
python3 score/tests/test_vectors/certificate/generate_certificates.py generate <name>
```

For example:

```sh
python3 score/tests/test_vectors/certificate/generate_certificates.py generate ec_p256
python3 score/tests/test_vectors/certificate/generate_certificates.py generate ml_dsa_65
```

Running `generate` creates a new local private key and a new self-signed public
certificate, then refreshes the manifest snapshot. Review and commit the public
PEM, the corresponding `<name>_slot.kv` descriptor, and the manifest together.

Only use `update` when the corresponding local private key is available and
preserving the existing key is intentional:

```sh
python3 score/tests/test_vectors/certificate/generate_certificates.py update <name>
```

Do not make tests depend on a private key being present.

## Adding a new certificate

1. Add an entry to `certificate_manifest.json` with `name`, `certificate_path`,
   `private_key_path`, `purpose`, `subject`, `key_algorithm`, and `validity_days`.
2. Run `generate_certificates.py generate <name>`. The script writes the PEM,
   the `<name>_slot.kv` KV descriptor, and updates the manifest snapshot.
3. Commit the PEM, the KV descriptor, and the updated manifest together.
