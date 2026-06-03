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
bazel test //tests/...
```

### Integration tests (Docker + pytest)

The integration tests run the full daemon inside a Docker container with
SoftHSM configured.

```sh
# From the workspace root:
cd tests/integration_tests
pytest integration_test.py.py -v
```

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
bazel test //tests/provider_test:test_pkcs11_multi_token
```

This test validates that two SoftHSM tokens configured in the same process
maintain independent session pools and login state.
