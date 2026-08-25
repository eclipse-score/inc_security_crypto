# Valeo Cryptoki Integration Guide

This document describes how the S-CORE Peer Package Rust PKCS#11 module (located under `//score/cryptoki`) is integrated into the `score_crypto` daemon, replacing the default SoftHSM implementation.

## Overview

The integration bridges a custom Rust-based PKCS#11 provider with the existing C++ daemon architecture. To achieve this cleanly and natively:

1.  **Toolchain Configuration**: The integration uses the Ferrocene Rust toolchain (Rust 1.83.0+) to support modern Rust features (like `lazy_cell` and `unsafe extern "C"`) required by dependencies such as `score_logging` and `openssl`.
2.  **Compile-Time Toggles**: A Bazel label-flag `--//score/crypto/src/backend:pkcs11_backend=//score/cryptoki:cryptoki_cdylib_wrapped` is used to conditionally:
    *   Link `//score/cryptoki:cryptoki_cdylib` instead of `libsofthsm`.
    *   Switch header includes from `<cryptoki.h>` to the Rust module's `<pkcs11.h>`.
3.  **Generic Provider Naming**: To achieve true, professional vendor neutrality, S-CORE registers both SoftHSM and the Rust library under the same abstract provider name: `"PKCS11_ENGINE"`. This allows standard, production-grade string-matching and label-matching to connect key slots natively, eliminating legacy hardcoded vendor brand names.

## Prerequisites

Ensure your environment is set up to build the project. The `.bazelrc` is already configured to map the default configuration to the required Ferrocene toolchain for Linux (`x86_64-linux`), and QNX (`aarch64-qnx`).

## Building

Because the Rust module relies on specific toolchains and isolated extensions, you must pass the appropriate flags to Bazel.

### Building for Linux (Host)

To build the main `crypto_daemon` and the integration tools for your local machine:

```bash
bazel build //score/crypto/src/daemon:crypto_daemon \
            //score/tests/integration_tests:init_pkcs11_token \
    --//score/crypto/src/backend:pkcs11_backend=//score/cryptoki:cryptoki_cdylib_wrapped \
    --experimental_isolated_extension_usages
```

### Cross-Compiling for QNX (Target)

To build the daemon and tests for QNX (`aarch64-qnx`), use the `aarch64-qnx` configuration preset. The workspace is configured to correctly map both target and host Ferrocene toolchains to ensure procedural macros build correctly.

```bash
bazel build //score/... \
    --config=aarch64-qnx \
    --//score/crypto/src/backend:pkcs11_backend=//score/cryptoki:cryptoki_cdylib_wrapped \
    --experimental_isolated_extension_usages
```
*(Note: Sphinx documentation targets are typically excluded when cross-compiling).*

## Running the Integration Demo

The `score_demo` exercises both HASH (software) and MAC (hardware) operations against the Rust PKCS#11 token. To run it successfully on your host, you must first initialize the token and start the daemon.

### 1. Initialize the Token and Key
Use the `init_pkcs11_token` tool to initialize a local token store and import a test key. Since S-CORE is built with our secure Rust backend flag active, it will talk directly to the Rust module rather than SoftHSM.

```bash
mkdir -p /tmp/rust_tokens
export CRYPTOKI_STORE=/tmp/rust_tokens/token.json

bazel run //score/tests/integration_tests:init_pkcs11_token \
  --//score/crypto/src/backend:pkcs11_backend=//score/cryptoki:cryptoki_cdylib_wrapped --experimental_isolated_extension_usages \
  -- \
  --token-dir /tmp/rust_tokens \
  --config-path /tmp/rust_tokens/softhsm2.conf \
  --token-label ValeoCryptokiToken \
  --so-pin so-pin \
  --user-pin 1234 \
  --import-key-file $PWD/score/tests/test_vectors/mac/key_aes_256.key \
  --import-key-label integration_test_hmac
```

### 2. Start the Daemon
Start the daemon in the background (or in a separate terminal) so it picks up the Rust token store and the test configuration:

```bash
export CRYPTO_CONFIG_FILE=$PWD/bazel-bin/score/tests/test_vectors/config/integration_test_config.bin
export CRYPTOKI_STORE=/tmp/rust_tokens/token.json

bazel run //score/crypto/src/daemon:crypto_daemon \
  --//score/crypto/src/backend:pkcs11_backend=//score/cryptoki:cryptoki_cdylib_wrapped --experimental_isolated_extension_usages
```

### 3. Run the Client
Execute the demo client in another terminal to perform cryptographic operations against the running daemon:

```bash
bazel run //score/tests/integration_tests:score_demo \
  --//score/crypto/src/backend:pkcs11_backend=//score/cryptoki:cryptoki_cdylib_wrapped --experimental_isolated_extension_usages
```

## Troubleshooting

*   **Toolchain Errors**: If you encounter errors mentioning `rules_rust` or missing toolchains, ensure you are including `--config=x86_64-linux` or `--config=aarch64-qnx` / `--config=x86_64-qnx` in your Bazel command. This is strictly required to activate the Ferrocene compiler capable of building the module.
*   **Missing Symbols / Header Errors**: If the C++ compilation fails looking for `<cryptoki.h>`, ensure you have included `--//score/crypto/src/backend:pkcs11_backend=//score/cryptoki:cryptoki_cdylib_wrapped`.
*   **LoadKey Failed**: If the client fails with `[FAIL] LoadKey failed`, ensure the token was initialized correctly in Step 1 and that the `CRYPTOKI_STORE` environment variable is set for the daemon before running it.
*   **QNX Build Missing Headers**: If QNX fails to compile `typed_memory.h`, ensure `--@score_baselibs//score/memory/shared/flags:use_typedshmd=false` is correctly set in your `.bazelrc` for `shared_qnx`.