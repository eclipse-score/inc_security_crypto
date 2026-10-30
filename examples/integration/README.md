# SCORE Crypto integration example

This directory is an independent Bazel module that consumes
`score_security_crypto` through its public targets. It verifies both the external
module boundary and compile-time backend selection.

The example starts the Crypto daemon, connects through the public C++ API, and
checks the SHA-256 digest of a known message. The runtime smoke test uses the
OpenSSL backend because it does not require external token provisioning.

## Run the example

From this directory, run:

```bash
bazel test //... --config=x86_64-linux --config=openssl-only
```

The following commands verify the other supported build-time selections:

```bash
bazel build //... --config=x86_64-linux --config=pkcs11-only
bazel build //... --config=x86_64-linux --config=all-backends
```

The PKCS#11 configuration is build-tested only. Running it requires a configured
PKCS#11 module and token, including the expected token label and credentials.

## Dependency setup

`MODULE.bazel` declares a normal `bazel_dep` on `score_security_crypto`. While
this example lives in the same repository, `local_path_override` resolves that
dependency to the repository root. A released consumer can remove the override
and replace `0.0.0` with a version published in the S-CORE Bazel registry.

Toolchains are declared by this module because Bazel does not propagate a
dependency module's development-only toolchain declarations to consumers.

## Backend selection

`.bazelrc` defines three named configurations using the public build settings of
`score_security_crypto`:

- `all-backends`: SCORE OpenSSL and PKCS#11 are both compiled in.
- `openssl-only`: SCORE OpenSSL is compiled in and PKCS#11 is excluded.
- `pkcs11-only`: PKCS#11 is compiled in and the SCORE backend family is excluded.

Backend selection is a build-time choice. Runtime provider selection and
provider configuration are separate concerns.
