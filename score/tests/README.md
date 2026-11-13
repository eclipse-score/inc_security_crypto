<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# Tests

## Test Structure

| Folder | Type | Framework | Description |
|---|---|---|---|
| `demo/` | Demo / manual | Google Test | Multi-provider demo binaries (e.g. MAC with SoftHSM + OpenSSL) |
| `grpc_control_plane/` | Component | Google Test | gRPC-based control-plane protocol tests |
| `integration_tests/` | Integration | Google Test + pytest | End-to-end daemon tests running inside Docker containers |
| `key_management/` | Component | Google Test | Key config, access policy, key store, OpenSSL/PKCS#11 key handlers |
| `openssl/` | Component | Google Test | OpenSSL block-cipher operation tests |
| `provider_test/` | Component | Google Test | Provider construction, PKCS#11 provider, multi-token isolation |
| `softhsm/` | Integration | Google Test | SoftHSM-specific token and session tests |
| `config/` | Config | — | Shared runtime configs (e.g. `logging.json` for `mw::log`) |
| `test_vectors/` | Data | — | Known-answer test vectors (HMAC, AES, etc.) |
| `utility/` | Component | Google Test | Shared test utilities and helpers |

### Logging configuration

`tests/config/logging.json` configures `score::mw::log` for local development. It enables
verbose console output so all `LogDebug()` / `LogVerbose()` messages are visible.

Set the env var before running the daemon or any test binary:

```sh
export MW_LOG_CONFIG_FILE=tests/config/logging.json
```

To suppress debug output, simply omit the env var (the library default is `kWarn`).

### Unit tests (Bazel)

```sh
bazel test //score/...
```

### Integration tests (Docker + pytest)

The integration tests run the full daemon inside a Docker container with
SoftHSM configured.

```sh
# From the workspace root:
cd tests/integration_tests
pytest integration_test.py.py -v
```

#### Certificate safeguard regression coverage

Single-certificate parsing accepts only nonempty DER/PEM input up to 8192 bytes.
The client rejects invalid input before buffer acquisition, and the daemon
checks it independently before parsing. The certificate-bundle operation keeps
its existing behavior and is not subject to this single-certificate limit.

File-backed certificate storage rejects data above 64 KiB before writing and
records the actual certificate path and the canonical DER SHA-256 fingerprint.
Required-integrity loading compares that fingerprint with metadata computed by
parsing the bytes read from disk. This detects a changed certificate relative to
the descriptor; it does not authenticate the descriptor or establish trust.

Ordinary certificate save rejects every configured trust-store member, including
disabled members. Existing trust-store operations remain separate. Regression
coverage includes the input-size boundaries, digest validation and refresh,
fallback-path reload, and enabled/disabled member save rejection.

#### Generated-key persistence and CSR signing

The OpenSSL integration case `test_score_api_key_persistence` extends the
`fea_um_crypto_1` generate-to-slot enrollment flow. It generates an ECDSA-P256
private key inside the daemon, stores it in the dedicated `csr/device-key` slot,
and records only a signed public CSR as reference evidence. It then:

- exits the provisioning client, releasing every client-side key handle;
- restarts the daemon gracefully and reloads the slot in a fresh client;
- kills the daemon with SIGKILL and repeats the reload in another fresh client;
- checks that the daemon PID changed, both CSR signatures verify, and the public
  keys are identical. Reload never generates a replacement key.

The test binary is
[score_api_key_persistence_test.cpp](integration_tests/score_api_key_persistence_test.cpp).
Its two phases can also be run separately across an externally controlled ECU
power cycle using `GTEST_FILTER` values
`KeyPersistenceIntegration.GenerateAndPersistDeviceKey` and
`KeyPersistenceIntegration.ReloadPersistedDeviceKeyAndSignCsr`, respectively.
Keep the slot file and reference CSR on persistent target storage between phases;
do not redeploy/clean the test directory or run both phases together as evidence
of power-cycle survival. The automatic integration fixture removes its deployment
only after the whole test class finishes.

`CSR_TEST_ENDPOINT`, `CSR_TEST_DEVICE_RESOURCE` and `CSR_TEST_REFERENCE_CSR`
select the endpoint, configured slot and public reference-CSR location. The
default deployment uses an empty slot under `/opt/crypto/etc/csr-slots`. Phase 1
refuses an occupied slot rather than deleting an existing key. This flow uses
`GenerateKey(target_slot, std::nullopt, params)`; the separate `PersistKey()` API
is still unsupported in the source branch.

CSR generation sends a bounded, versioned provider-neutral FlatBuffers request
and receives a signed PKCS#10 DER request through the shared-memory data plane.
The client reserves input and output buffers before the request, including small inputs;
the control plane carries the operation, SHM descriptors, status and written-byte
count, not the generated DER. The existing CSR DER size limit is unchanged.
The daemon retains the separately identified legacy DER one-input,
inline-output operation for direct callers; the production client uses the
neutral-input, output-buffer operation. The external
daemon CSR and persistence integration tests exercise this client path.

The generation payload contains subject fields, requested extensions and an
optional challenge password. The daemon rejects key, algorithm and enrollment
metadata overrides in that operation. It parses DN/SAN input, validates UTF-8,
OIDs and extension semantics, constructs X.509 objects, derives key-dependent
extensions from its authorized bound key, signs, verifies and encodes the CSR.
There is no client-side public-key query or encoding retry. No private-key
material crosses this interface.

The existing `ICsrGenerationContext` methods are unchanged. Standalone subject,
extension, request and template helpers now take an explicit
`ICsrProcessingService&` as their first argument. Obtain the production service
from the connected stack with `ICryptoStack::CreateCsrProcessingService()`.
For example, `CsrSubject::FromDn(processing, dn)` and
`request.ToDer(processing)` perform their processing in the daemon.
`DerCsrTemplateStorage` takes that service in its constructor; `Save`, `Prepare`,
`Generate` and `GenerateBatch` also accept it explicitly. Keep the service alive
for the storage object's lifetime. No implicit endpoint, process-global service
or local-provider fallback is selected. These helper-signature changes require
updating existing standalone-helper callers; context-only callers are unchanged.

The client libraries contain only plain input/output handling and transport
marshalling. Their dependency graph does not include OpenSSL. The original
processing and DER codecs are compiled only into daemon-side libraries.
Helper processing is connection-scoped and has no signing-key access; CSR
generation still uses the separately authorized, immutable keyed context.

The CSR transport and key-persistence client test executables also contain no
OpenSSL headers, types, calls or link dependency. They export bounded public DER
evidence to an independent offline test verifier, which retains the signature,
subject, key-identity, SKI and extension assertions. This verifier is test-only,
has no SCORE client-stack or daemon connection, and is deployed beside the client
executables; keep it beside them when running the persistence phases manually.
OpenSSL in this separate verifier is not a production client dependency or a
local-provider fallback.

`DerCsrTemplateStorage` stores a versioned ASN.1 DER template, preserving
ordered subject/issuer placeholders, static extension specifications, key-resource
and algorithm names, template ID and submission URL. Encoding, decoding,
placeholder substitution and validation execute in the daemon. Issuer/URL remain
enrollment metadata and are not included in the PKCS#10 request. Template format version 1
is SCORE-specific and distinct from the standard signed CSR format. Applications
must convert previously stored text templates; there is no format auto-detection.

CSR wire version 1 uses the `SCR1` FlatBuffers identifier. Wire framing has a
separate 256 KiB ceiling, accounting for template input/output and schema
overhead; it does not increase the existing 16 KiB aggregate request, 64 KiB
stored-template DER, subject/extension counts or final CSR DER bounds.
Unknown versions/actions, malformed or non-canonical framing, unexpected fields
and invalid output counts are rejected. The socket integration tests exercise
daemon-owned processing; in-process adapters are test-only.

**Limits:** daemon restarts do not power off the operating system or storage.
The imported source storage path uses `WriteFile()`/atomic rename, not PR #369's
fsync-backed storage helper. These tests therefore do not establish sudden
ECU power-loss durability, storage-level fault tolerance, or secure key deletion.

#### SoftHSM token initialisation

The `init_softhsm_token` binary initialises a SoftHSM token and optionally
imports a pre-shared key:

```sh
# Initialise token only:
./init_softhsm_token --label "MyToken" --pin 1234 --so-pin 12345678

# Initialise token and import an HMAC key:
./init_softhsm_token --label "MyToken" --pin 1234 --so-pin 12345678 \
    --import-key-file /path/to/key.bin \
    --import-key-label "hmac_key" \
    --import-key-type GENERIC_SECRET
```

### Multi-token isolation test

```sh
bazel test //score/crypto/tests/provider_test:test_pkcs11_multi_token
```

This test validates that two SoftHSM tokens configured in the same process
maintain independent session pools and login state.
