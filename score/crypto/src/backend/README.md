# Backend Configuration

This folder controls which cryptographic backends are compiled into the daemon.
It is the **single source of truth** for backend selection at build time.

## Files

| File | Purpose |
|------|---------|
| `backend_exports.bzl` | Master flags (`ENABLE_BACKEND_OPENSSL`, `PKCS11_BACKEND`, ...) |
| `backend_config.bzl` | Helper functions that map flags to Bazel labels/defines |
| `BUILD` | Bazel targets: `active_score_backends`, `active_pkcs11_backend`, `pkcs11_backend` label_flag |
| `score_provider/active_backends_list.hpp` | Compile-time discovery of enabled score backends |

## How It Works

### Score Provider Backends

A single `ScoreProviderFactory` handles multiple score backends (OpenSSL, Primula, etc.).
The factory discovers enabled backends at compile time via `score_provider/active_backends_list.hpp`.
Each backend adapter exposes:

- `backend_id` — implementation tag used for dispatch (e.g. `"openssl"`)
- `backend_name` — human-readable provider name (e.g. `"OPENSSL"`)
- `provider_type` — `"SOFTWARE"`, `"HARDWARE"` or `"SPECIALIZED"`
- `create_provider` — factory function for the concrete provider

### PKCS#11 Backends

A separate `Pkcs11ProviderFactory` handles the PKCS#11 family. Only one PKCS#11
backend can be active at a time. The active backend is selected through a Bazel
`label_flag`:

```starlark
# backend/BUILD
label_flag(
    name = "pkcs11_backend",
    build_setting_default = PKCS11_BACKEND_DEFAULT_LABEL,
)
```

The default value comes from `PKCS11_BACKEND` in `backend_exports.bzl`. It can be
overridden on the command line:

```bash
bazel build //score/crypto/src/daemon:crypto_daemon \
    --//score/crypto/src/backend:pkcs11_backend=//external/vendor_hsm:backend
```

Each PKCS#11 backend target provides:

1. A `Pkcs11Config::ParseConfig()` implementation with backend-specific defaults
2. The PKCS#11 library and headers for linking

## Configuration (`backend_exports.bzl`)

```starlark
# Backend family flags
ENABLE_PKCS11_BACKEND = True   # Enable/disable PKCS#11
ENABLE_SCORE_BACKEND = True    # Enable/disable all score backends

# Individual score backends (only if ENABLE_SCORE_BACKEND = True)
ENABLE_BACKEND_OPENSSL = True
ENABLE_BACKEND_PRIMULA = False

# Active PKCS#11 backend (only if ENABLE_PKCS11_BACKEND = True)
PKCS11_BACKEND = "softhsm"     # Options: "softhsm", "vendor_hsm", ...
```

## Adding a New Score Backend

1. Implement the provider in `score_provider/<backend>/`
2. Create an adapter in `backend/<backend>/`:
   ```cpp
   ProviderCreator GetProviderCreator() const override {
       return {
           .backend_id    = "<backend>",
           .backend_name  = "<BACKEND>",
           .provider_type = "SOFTWARE",  // or "HARDWARE", "SPECIALIZED"
           .create_provider = []() { return std::make_unique<...>(); }
       };
   }
   ```
3. Add flags to `backend_exports.bzl` and update `backend_config.bzl`
4. Update `score_provider/active_backends_list.hpp` (include + instantiate)

## Adding a New PKCS#11 Backend

Config parsing (`Pkcs11Config::ParseConfig`) lives in `backend/pkcs11/` and is
independent of which backend library is selected. Backend targets provide only
the PKCS#11 library and headers.

1. Add the backend name → library label mapping in `backend_config.bzl`:
   ```starlark
   def _pkcs11_backend_map():
       return {
           "softhsm": "//third_party/soft_hsm:softhsm",
           "<name>":  "//third_party/<name>:<name>",  # NEW
       }
   ```
2. Select it in `backend_exports.bzl`:
   ```starlark
   PKCS11_BACKEND = "<name>"
   ```
   Or override at build time:
   ```bash
   bazel build //score/crypto/src/daemon:crypto_daemon \
       --//score/crypto/src/backend:pkcs11_backend=//third_party/<name>:<name>
   ```

## Common Configurations

| Use Case | Config |
|----------|--------|
| **Software-only** | `ENABLE_PKCS11_BACKEND = False`<br/>`ENABLE_SCORE_BACKEND = True`<br/>`ENABLE_BACKEND_OPENSSL = True` |
| **HSM-only** | `ENABLE_PKCS11_BACKEND = True`<br/>`ENABLE_SCORE_BACKEND = False`<br/>`PKCS11_BACKEND = "vendor_hsm"` |
| **Hybrid** | Both families enabled |

## Command-Line Overrides

| What | Example |
|------|---------|
| PKCS#11 backend | `--//score/crypto/src/backend:pkcs11_backend=//external/vendor_hsm:backend` |

## Verification

Check which backends are compiled into the daemon:

```bash
bazel query 'deps(//score/crypto/src/daemon:crypto_daemon)' | grep -E "openssl|softhsm"
```

Check the effective PKCS#11 backend:

```bash
bazel cquery //score/crypto/src/daemon:crypto_daemon --output=build | grep pkcs11_backend
```
