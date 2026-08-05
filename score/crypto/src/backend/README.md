# Backend Configuration

This package controls which cryptographic backends are compiled into the daemon.
It is the **single source of truth** for backend selection at build time.

## Overview

Two independent backend families exist:

| Family | Factory | Selection |
|--------|---------|-----------|
| **Score provider** | `ScoreProviderFactory` | Multiple sub-backends can be active simultaneously |
| **PKCS#11** | `Pkcs11ProviderFactory` | Exactly one library is active at a time |

### Two-layer split: backend vs. daemon adapter

Both provider families follow the same two-layer structure. Each family has one directory in the backend (the provider-library layer) and a corresponding directory in the daemon (the adapter layer that integrates with `ProviderManager` and the mediator):

| Family             | `backend/` directory                                                                                                                                                              | `daemon/provider/` directory                                                                                                                                                                            |
| ------------------ | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **Score provider** | `backend/score_provider/` — concrete cryptographic implementations; each sub-backend implements `IBackendProviderAdapter` and exposes a `ProviderCreator`; no daemon dependencies | `daemon/provider/score_provider/` — defines `IBackendProviderAdapter`; implements `IProvider`; `ScoreProviderFactory` reads `active_backends_list.hpp` to discover enabled sub-backends at compile time |
| **PKCS#11**        | `backend/pkcs11/` — config parser only (`Pkcs11Config::ParseConfig`); the PKCS#11 library itself is a third-party dependency selected via the `pkcs11_backend` `label_flag`       | `daemon/provider/pkcs11/` — full daemon adapter: `Pkcs11Provider`, `Pkcs11ProviderFactory`, `Pkcs11Module`, session management, and operation handlers                                                  |

The key difference between the two families: for Score provider, this package contains the actual crypto implementations; for PKCS#11, this package contains only the config parser — the library is wired in externally via `label_flag`.

Dependency direction is strictly one-way in both cases: the daemon adapter layer depends on this package, never the reverse.

## Enable / Disable Flags

Backend enable/disable is controlled via `bool_flag` targets. All flags are in
`//score/crypto/src/backend:BUILD`.

| Flag | Default | Command-line override |
|------|---------|----------------------|
| `score_crypto_pkcs11_backend_enabled` | `True` | `--//score/crypto/src/backend:score_crypto_pkcs11_backend_enabled=False` |
| `score_crypto_score_backend_enabled` | `True` | `--//score/crypto/src/backend:score_crypto_score_backend_enabled=False` |
| `score_crypto_score_openssl_enabled` | `True` | `--//score/crypto/src/backend:score_crypto_score_openssl_enabled=False` |
| `score_crypto_score_primula_enabled` | `False` | `--//score/crypto/src/backend:score_crypto_score_primula_enabled=True` |

`score_crypto_score_backend_enabled` is the master gate for the score provider
Individual sub-backend flags (`score_crypto_score_openssl_enabled`, etc.) have
no effect unless the master flag is also `True`.

When a backend is disabled, **all its dependencies are excluded from the binary**
— nothing is compiled or linked for that backend.

## Score Provider Sub-Backends

Score provider sub-backends live under `backend/score_provider/<backend>/`. Each follows
the three-target pattern:

| Target | Purpose |
|--------|---------|
| `*_backend_adapter` | Full implementation (adapter + provider library) |
| `*_backend_define` | Preprocessor define only (lightweight) |
| `*_backend` | Conditional aggregate: define + adapter when enabled |

All `target_compatible_with` attributes in a sub-backend package must use a combined
`config_setting` that requires **both** the master gate (`score_crypto_score_backend_enabled`)
and the sub-backend flag (e.g. `score_crypto_score_openssl_enabled`). The combined setting
is defined in `backend/BUILD` (e.g. `openssl_backend_active`) so that disabling either flag
excludes the sub-backend targets from wildcard builds. A standalone single-flag
`config_setting` for the sub-backend flag alone is not used.

The discovery header `score_provider/active_backends_list.hpp` lists all enabled
sub-backends. The `ScoreProviderFactory` uses it to instantiate providers at
startup.

## PKCS#11 Implementation Selection

Only one PKCS#11 library can be active at a time. The active library is selected
via a `label_flag`:

```starlark
# backend/BUILD
label_flag(
    name = "pkcs11_backend",
    build_setting_default = "//third_party/soft_hsm:softhsm_shared",
)
```

Override at build time:

```bash
bazel build //score/crypto/src/daemon:crypto_daemon \
    --//score/crypto/src/backend:pkcs11_backend=//third_party/vendor_hsm:vendor_hsm
```

Config parsing (`Pkcs11Config::ParseConfig`) lives in `backend/pkcs11/` and is
independent of the selected library.

## Common Configurations

| Use Case | Flags |
|----------|-------|
| Software-only (no HSM) | *(defaults)* |
| HSM-only | `--//score/crypto/src/backend:score_crypto_score_backend_enabled=False` |
| OpenSSL disabled | `--//score/crypto/src/backend:score_crypto_score_openssl_enabled=False` |
| Custom PKCS#11 library | `--//score/crypto/src/backend:pkcs11_backend=//third_party/vendor_hsm:vendor_hsm` |

## Adding a New Score Provider Backend

1. Implement the backend adapter under `backend/score_provider/<backend>/`.
2. Create `score_provider/<backend>/BUILD` using the three-target pattern
   (see `score_provider/openssl/BUILD` as reference).
3. Add a `bool_flag` for the new sub-backend flag in `backend/BUILD`, plus a combined
   `config_setting` (e.g. `<name>_backend_active`) that requires both the master gate
   (`score_crypto_score_backend_enabled`) and the new sub-backend flag. Use this combined
   setting in all `target_compatible_with` attributes in the sub-backend package.
4. Add `*_backend_define` to `score_backend_headers.deps` in `score_provider/BUILD`.
5. Add `*_backend` to `all_score_backends.deps` in `score_provider/BUILD`.
6. Include and instantiate the adapter in `score_provider/active_backends_list.hpp`.

Steps 4 and 5 are both in `score_provider/BUILD`; `backend/BUILD` only needs the
new flag (step 3).

## Adding a New PKCS#11 Backend Library

No BUILD changes are needed for a named default — just point the `label_flag` at
the new library target either in `build_setting_default` (for a permanent change)
or on the command line (for a per-build override).

## Verification

Check which backend libraries are linked into the daemon:

```bash
bazel query 'deps(//score/crypto/src/daemon:crypto_daemon)' | grep -E "openssl|softhsm"
```

Check the effective PKCS#11 backend for a given configuration:

```bash
bazel cquery //score/crypto/src/backend:pkcs11_backend --output=build
```
