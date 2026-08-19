# PKCS11 Dynloader

This directory implements a backend-agnostic PKCS11 dynloader. It loads a
PKCS11 module at runtime via dlopen() and compiles against a selected
pkcs11.h header set. The header set is chosen through a Bazel label_flag,
allowing different PKCS11 backends to supply their own headers without
modifying the dynloader.

## Mandatory pkcs11_lib Definition

The dynloader requires the definition of pkcs11_lib. pkcs11_lib must contain
the absolute path to the PKCS11 module that should be loaded at runtime.

Example:

    --define pkcs11_lib="/usr/lib/softhsm/libsofthsm2.so"

The build will fail if pkcs11_lib is not defined.

The value is written into a generated header:

    include/pkcs11_lib_path.h

which provides:

    static const char* kPkcs11LibPath = "...";

This avoids fragile preprocessor string escaping.

## Selecting a Header Provider

The PKCS11 header used for compilation is selected via:

    --//third_party/pkcs11_dynload:pkcs11_header_source=<target>

The default provider is SoftHSM:

    --//third_party/pkcs11_dynload:pkcs11_header_source=//third_party/pkcs11_dynload:soft_hsm_header

This selects a cc_library that exposes a normalized pkcs11.h.

Important:
The header provider does not imply a default PKCS11 module path.
The module path must always be supplied via --define pkcs11_lib=...

## SoftHSM Header Provider (Default)

SoftHSM's pkcs11.h is extracted from the SoftHSM source tree and placed
into a normalized include layout:

    include/pkcs11.h

The provider is a simple cc_library:

    cc_library(
        name = "soft_hsm_header",
        hdrs = [":extract_pkcs11_headers"],
        includes = ["include"],
    )

This makes SoftHSM the default header source without hard-coding any backend
logic into the dynloader.

## Minimal Example: Custom Header Provider

To use a custom PKCS11 header, create a small directory:

    third_party/own_pkcs11/
        BUILD
        pkcs11.h

Example BUILD file:

    genrule(
        name = "copy_own_pkcs11_header",
        srcs = ["pkcs11.h"],
        outs = ["include/pkcs11.h"],
        cmd = "mkdir -p $(RULEDIR)/include && cp $(location pkcs11.h) $(RULEDIR)/include/pkcs11.h",
    )

    cc_library(
        name = "own_pkcs11_header",
        hdrs = [":copy_own_pkcs11_header"],
        includes = ["include"],
    )

Usage:

    bazel build //third_party/pkcs11_dynload:pkcs11_dynload_shared \
        --//third_party/pkcs11_dynload:pkcs11_header_source=//third_party/own_pkcs11:own_pkcs11_header \
        --define pkcs11_lib="/path/to/your/pkcs11/module.so"

## Summary

- The dynloader is backend-agnostic.
- PKCS11 headers are supplied by selectable cc_library targets.
- SoftHSM is the default header provider.
- Custom providers can be selected via a build flag.
- The PKCS11 module path must always be provided via --define pkcs11_lib=...
- Adding new header providers does not require modifying the dynloader.

## Assumptions of Use

The PKCS11 dynloader operates under the following assumptions:

The selected pkcs11.h header matches the PKCS11 module that will be loaded at runtime.
The header provider and the module path must refer to the same PKCS11 implementation.
Using mismatched headers and modules may result in undefined behavior, missing symbols,
or runtime errors.

The operating system platform provides integrity and authenticity mechanisms for the
specified PKCS11 module. The dynloader assumes that the PKCS11 shared library file is
protected by the platform's security model (for example: filesystem permissions,
package management, signed modules, or other integrity controls). The dynloader does
not perform additional verification of the module's origin or integrity.
