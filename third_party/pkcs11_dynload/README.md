# PKCS#11 Dynloader

This directory implements a backend-agnostic PKCS#11 dynloader. It loads
PKCS#11 modules at runtime via `dlopen()` and compiles against a selected
`pkcs11.h` header set provided by one of several interchangeable PKCS#11
header providers.

The dynloader itself does not depend on any specific PKCS#11 backend.
Instead, it consumes a single build setting:

    --//third_party/pkcs11_dynload:pkcs11_header_source=<provider>

This keeps the dynloader modular, hermetic, and easy to extend.

## Mandatory pkcs11_lib Definition

The dynloader requires the definition of pkcs11_lib. pkcs11_lib  must contain the 
absolute path to the PKCS#11 module that should be loaded at runtime.

Example:

    --define pkcs11_lib="/usr/lib/softhsm/libsofthsm2.so" 

The build will fail without a --define of pkcs11_lib. 


## Provider Abstraction

The file:

    third_party/pkcs11_dynload/provider.bzl

defines a tiny uniform interface:

    pkcs11_header_provider(name, hdrs, includes = ["include"])

Every PKCS#11 backend implements this rule to expose its header set in a
consistent shape. The dynloader only depends on the selected provider,
not on the backend itself.

All providers must expose `pkcs11.h` and its dependencies in a normalized
include layout.

## Selecting a Provider

SoftHSM (@softhsm_source) is the default provider. It does not imply a default PKCS#11 module path. 
The module path must always be provided explicitly via --define pkcs11_lib=... .

To override the provider:

    bazel build //third_party/pkcs11_dynload:pkcs11_dynload_shared \
        --//third_party/pkcs11_dynload:pkcs11_header_source=//third_party/own_pkcs11:own_header \
        --define pkcs11_lib="/path/to/own_pkcs11.so"

## SoftHSM Provider (Default)

SoftHSM’s `pkcs11.h` is extracted from the SoftHSM source tree (@softhsm_source//:all) and normalized
into `include/pkcs11.h`.

The provider exposes these headers through:

    pkcs11_header_provider(
        name = "soft_hsm_header",
        hdrs = [":extract_pkcs11_headers"],
        includes = ["include"],
    )

## Minimal Example Provider (own_pkcs11)

This example shows how to add a minimal custom PKCS#11 header provider.

Directory:

    third_party/own_pkcs11/
        BUILD
        pkcs11.h

BUILD file:

    load("//third_party/pkcs11_dynload:provider.bzl", "pkcs11_header_provider")

    genrule(
        name = "copy_own_pkcs11_header",
        srcs = ["pkcs11.h"],
        outs = ["include/pkcs11.h"],
        cmd = "mkdir -p $(RULEDIR)/include && cp $(location pkcs11.h) $(RULEDIR)/include/pkcs11.h",
        visibility = ["//visibility:private"],
    )

    pkcs11_header_provider(
        name = "own_header",
        hdrs = [":copy_own_pkcs11_header"],
        includes = ["include"],
    )

Usage:

    --//third_party/pkcs11_dynload:pkcs11_header_source=//third_party/own_pkcs11:own_header \
    --define pkcs11_lib="/path/to/own_pkcs11.so"

## Summary

- The dynloader is backend-agnostic.
- Providers supply PKCS#11 headers in a normalized layout.
- SoftHSM is the default provider.
- Custom providers can be selected via a build flag.
- There must be a --define pkcs11_lib="/path/to/own_pkcs11.so".
- Adding new providers is simple and does not require modifying the dynloader.

This pattern keeps PKCS#11 integration modular, maintainable, and easy to extend.
