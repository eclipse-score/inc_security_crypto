# Valeo Cryptoki Integration Guide

This document describes how the `@score/crypto/provider` Rust PKCS#11 module is integrated into the `score_crypto` daemon, replacing the default SoftHSM implementation.

## Overview

The integration bridges a custom Rust-based PKCS#11 provider with the existing C++ daemon architecture. To achieve this cleanly and natively:

1.  **Toolchain Configuration**: The integration uses the Ferrocene Rust toolchain (Rust 1.83.0+) to support modern Rust features (like `lazy_cell` and `unsafe extern "C"`) required by dependencies such as `score_logging` and `openssl`.
2.  **Compile-Time Toggles**: A Bazel `--define use_rust_pkcs11=true` flag is used to conditionally:
    *   Link `//score/crypto/daemon/provider/cryptoki:cryptoki_cdylib` instead of `libsofthsm`.
    *   Inject the `USE_RUST_PKCS11=1` C++ preprocessor macro.
    *   Switch header includes from `<cryptoki.h>` to the Rust module's `<pkcs11.h>`.
3.  **Runtime Provider Remapping**: When the `USE_RUST_PKCS11` macro is active, the daemon dynamically remaps key-slot provider references from the legacy `"SOFTHSM"` string to `"SCORE_CRYPTO_PROVIDER"`. This ensures existing configuration files and client code remain compatible without modification.

## Prerequisites

Ensure your environment is set up to build the project. The `.bazelrc` is already configured to map the `host_config_1` configuration to the required Ferrocene toolchain for Linux, and `target_config_2` for `aarch64-qnx`.

## Building

Because the Rust module relies on specific toolchains and isolated extensions, you must pass the appropriate flags to Bazel.

### Building for Linux (Host)

To build the main `crypto_daemon` and the integration tools for your local machine:

```bash
bazel build //score/crypto/daemon:crypto_daemon \
            //tests/integration_tests:valeo_pkcs11_demo_client \
            //tests/integration_tests:init_softhsm_token \
    --config=host_config_1 \
    --define use_rust_pkcs11=true \
    --experimental_isolated_extension_usages
```

### Cross-Compiling for QNX (Target)

To build the daemon and tests for QNX (`aarch64-qnx`), use the `target_config_2` configuration. The workspace is configured to correctly map both target and host Ferrocene toolchains to ensure procedural macros build correctly, and automatically disables incompatible shared memory modules.

```bash
bazel build //score/... //tests/... \
    --config=target_config_2 \
    --define use_rust_pkcs11=true \
    --experimental_isolated_extension_usages
```
*(Note: Sphinx documentation targets are typically excluded when cross-compiling).*

## Running the Integration Demo

The `valeo_pkcs11_demo_client` exercises both HASH (software) and MAC (hardware) operations against the Rust PKCS#11 token. To run it successfully on your host, you must first initialize the token and start the daemon.

### 1. Initialize the Token and Key
Use the `init_softhsm_token` tool to initialize a local token store and import a test key. Since it's built with `--define use_rust_pkcs11=true`, it will talk directly to the Rust module rather than SoftHSM.

```bash
mkdir -p /tmp/rust_tokens
export CRYPTOKI_STORE=/tmp/rust_tokens/token.json

./bazel-bin/tests/integration_tests/init_softhsm_token \
  --token-dir /tmp/rust_tokens \
  --config-path /tmp/rust_tokens/softhsm2.conf \
  --token-label ValeoCryptokiToken \
  --so-pin so-pin \
  --user-pin 1234 \
  --import-key-file /opt/crypto/tests/test_vectors/mac/key_aes_256.key \
  --import-key-label integration_test_hmac
```

### 2. Start the Daemon
Start the daemon in the background (or in a separate terminal) so it picks up the Rust token store and the test configuration:

```bash
export CRYPTO_CONFIG_FILE=/opt/crypto/tests/test_vectors/config/integration_test_config.bin
export CRYPTOKI_STORE=/tmp/rust_tokens/token.json

./bazel-bin/score/crypto/daemon/crypto_daemon
```

### 3. Run the Client
Execute the demo client in another terminal to perform cryptographic operations against the running daemon:

```bash
./bazel-bin/tests/integration_tests/valeo_pkcs11_demo_client
```

## Troubleshooting

*   **Toolchain Errors**: If you encounter errors mentioning `rules_rust` or missing toolchains, ensure you are including `--config=host_config_1` or `--config=target_config_2` in your Bazel command. This is strictly required to activate the Ferrocene compiler capable of building the module.
*   **Missing Symbols / Header Errors**: If the C++ compilation fails looking for `<cryptoki.h>`, ensure you have included `--define use_rust_pkcs11=true`.
*   **LoadKey Failed**: If the client fails with `[FAIL] LoadKey failed`, ensure the token was initialized correctly in Step 1 and that the `CRYPTOKI_STORE` environment variable is set for the daemon before running it.
*   **QNX Build Missing Headers**: If QNX fails to compile `typed_memory.h`, ensure `--@score_baselibs//score/memory/shared/flags:use_typedshmd=false` is correctly set in your `.bazelrc` for `shared_qnx`.