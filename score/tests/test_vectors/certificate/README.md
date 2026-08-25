# Certificate Test Vectors

`certificate_manifest.json` is the inventory for certificate-management test certificates. It records each certificate's purpose, subject, private-key location, validity policy, and the metadata snapshot of the checked-in public certificate.

Private keys are generated locally under `private/` and are ignored by Git. Never commit them. The checked-in certificates use a long validity period because their private keys are intentionally not stored in the public repository.

From the repository root, generate a certificate and its local key with:

```sh
python3 score/tests/test_vectors/certificate/generate_certificates.py generate certificate
```

When a public snapshot needs renewal, run `generate` again. This creates a new local private key and a new self-signed public certificate, then refreshes the manifest snapshot. Review and commit the public PEM and manifest together.

Only use `update` when the corresponding local private key is available and preserving the existing key is intentional:

```sh
python3 score/tests/test_vectors/certificate/generate_certificates.py update certificate
```

Use `certificate_updated` for the replacement snapshot used by the anchor-invalidation test. To add another certificate, add an entry to `certificate_manifest.json`, then run the `generate` command with its `name`. The script updates the certificate's `snapshot` from OpenSSL after generation. Do not make tests depend on a private key being present.

The generated public certificate and manifest changes should be reviewed together. The KV descriptor templates in this directory describe the storage layouts used by the certificate-management integration tests.
