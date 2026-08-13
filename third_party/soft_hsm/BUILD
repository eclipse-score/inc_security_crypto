# *******************************************************************************
# Copyright (c) 2026 Contributors to the Eclipse Foundation
#
# See the NOTICE file(s) distributed with this work for additional
# information regarding copyright ownership.
#
# This program and the accompanying materials are made available under the
# terms of the Apache License Version 2.0 which is available at
# https://www.apache.org/licenses/LICENSE-2.0
#
# SPDX-License-Identifier: Apache-2.0
# *******************************************************************************

load("@rules_cc//cc:defs.bzl", "cc_library")
load("@rules_foreign_cc//foreign_cc:defs.bzl", "cmake")

# SoftHSM build using rules_foreign_cc cmake
# CMake build options reference for SoftHSM 2.7.0:
# https://github.com/softhsm/SoftHSMv2/blob/2.7.0/CMakeLists.txt
# CMake handles cross-compilation via auto-generated toolchain file from rules_foreign_cc,
# which avoids the libtool issues encountered with the autotools (configure_make) approach.
cmake(
    name = "soft_hsm_cmake",
    cache_entries = {
        "BUILD_TESTS": "OFF",  # Disable test suite compilation
        "WITH_CRYPTO_BACKEND": "openssl",  # Use OpenSSL as crypto backend (matches openssl_shared dependency)
        "OPENSSL_ROOT_DIR": "$${EXT_BUILD_DEPS}",  # Root path for OpenSSL headers/libs provided by Bazel deps
        "ENABLE_GOST": "OFF",  # Disable GOST (not in SCORE requirements)
        "ENABLE_EDDSA": "OFF",  # Disable EdDSA/Ed25519/Ed448 (not in SCORE requirements)
        "ENABLE_ECC": "ON",  # Enable ECC for ECDSA/ECDH (feat_req__sec_crypt__sig_algo_ecdsa, feat_req__sec_crypt__asym_algo_ecdh)
        "ENABLE_P11_KIT": "OFF",  # Disable p11-kit integration (desktop feature, not needed in embedded)
        "ENABLE_STATIC": "OFF",  # Disable static build
        "DISABLE_NON_PAGED_MEMORY": "ON",
        "CMAKE_INSTALL_LIBDIR": "lib",
        "CMAKE_INSTALL_SYSCONFDIR": "etc",
        "CMAKE_INSTALL_LOCALSTATEDIR": "var",
        # SoftHSM 2.7.0 uses try_run() to verify OpenSSL feature support.
        # try_run() cannot execute cross-compiled binaries on the build host;
        # cmake sets results to FAILED_TO_RUN in cross-compilation mode.
        # Pre-caching the run results is the standard cmake cross-compilation
        # workaround (see cmake docs on try_run and cross-compiling).
        # Active try_run calls for our config (openssl, ECC=ON, EDDSA=OFF, GOST=OFF):
        #   RUN_ECC            - required, fatal if fails
        #   RUN_AES_KEY_WRAP   - unconditional
        #   RUN_AES_KEY_WRAP_PAD - unconditional
        # We know our OpenSSL is built with ECC and AES-WRAP support.
        "RUN_ECC": "0",
        "RUN_ECC__TRYRUN_OUTPUT": "",
        "RUN_AES_KEY_WRAP": "0",
        "RUN_AES_KEY_WRAP__TRYRUN_OUTPUT": "",
        "RUN_AES_KEY_WRAP_PAD": "0",
        "RUN_AES_KEY_WRAP_PAD__TRYRUN_OUTPUT": "",
    },
    env = select({
        "//platforms:is_qnx_aarch64": {
            # EXT_BUILD_ROOT is captured at the start of the build script (before any cd),
            # so it reliably points to the execroot regardless of working directory changes.
            "QNX_HOST": "$${EXT_BUILD_ROOT}/external/score_bazel_cpp_toolchains++gcc+score_qcc_aarch64_toolchain_pkg/host/linux/x86_64",
            "QNX_TARGET": "$${EXT_BUILD_ROOT}/external/score_bazel_cpp_toolchains++gcc+score_qcc_aarch64_toolchain_pkg/target/qnx",
        },
        "//platforms:is_qnx_x86_64": {
            "QNX_HOST": "$${EXT_BUILD_ROOT}/external/score_bazel_cpp_toolchains++gcc+score_qcc_x86_64_toolchain_pkg/host/linux/x86_64",
            "QNX_TARGET": "$${EXT_BUILD_ROOT}/external/score_bazel_cpp_toolchains++gcc+score_qcc_x86_64_toolchain_pkg/target/qnx",
        },
        "//conditions:default": {},
    }),
    lib_source = "@softhsm_source//:all",
    out_lib_dir = "lib/softhsm",
    out_shared_libs = [
        "libsofthsm2.so",
    ],
    tags = ["no-sandbox"],
    visibility = [
        "//third_party/soft_hsm:__pkg__",  # Internal wrappers
    ],
    deps = ["//third_party/openssl:openssl_shared"],
)

# Extract PKCS#11 headers from SoftHSM source for public consumption
genrule(
    name = "extract_pkcs11_headers",
    srcs = ["@softhsm_source//:all"],
    outs = [
        "include/pkcs11.h",
    ],
    cmd = """
        SRCDIR=$$(dirname $$(echo $(locations @softhsm_source//:all) | awk '{print $$1}'))
        mkdir -p $(RULEDIR)/include
        cp $$SRCDIR/src/lib/pkcs11/pkcs11.h $(RULEDIR)/include/
    """,
    visibility = ["//visibility:private"],
)

# Softhsm pkcs11 target for linking and header consumption
cc_library(
    name = "softhsm_shared",
    hdrs = [":extract_pkcs11_headers"],
    includes = ["include"],
    linkstatic = False,
    visibility = ["//visibility:public"],
    deps = [":soft_hsm_cmake"],
)

# Extract libsofthsm2.so from the foreign_cc output tree into a declared
# output file so that the softhsm_so filegroup can expose it as a plain
# file in Bazel runfiles (e.g. for tests that need the .so at runtime).
genrule(
    name = "softhsm_so_extract",
    srcs = [":soft_hsm_cmake"],
    outs = ["libsofthsm2.so"],
    # $(locations :soft_hsm_cmake) expands to all cmake output paths; pick the .so.
    # Exit immediately after copying so that a missing .so is a build error here,
    # not a silent empty output that causes a confusing failure downstream.
    cmd = "set -e; found=0; for f in $(locations :soft_hsm_cmake); do case $$f in *libsofthsm2.so) cp $$f $@; found=1; break;; esac; done; test $$found -eq 1 || { echo 'ERROR: libsofthsm2.so not found in soft_hsm_cmake outputs' >&2; exit 1; }",
    visibility = ["//visibility:private"],
)

# Data dependency for targets that need libsofthsm2.so as a plain file in
# runfiles (e.g. py_itf_test copying it into a Docker container).
# This mirrors the cc_shared_library pattern used by grpc/openssl: the .so
# appears as a default output and is therefore visible in Bazel runfiles.
filegroup(
    name = "softhsm_so",
    srcs = [":softhsm_so_extract"],
    visibility = ["//:__subpackages__"],
)
