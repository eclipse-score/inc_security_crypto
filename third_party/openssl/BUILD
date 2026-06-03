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
load("@rules_foreign_cc//foreign_cc:defs.bzl", "configure_make")

# OpenSSL build using rules_foreign_cc
# Configure options reference for OpenSSL 3.6.1:
# https://github.com/openssl/openssl/blob/openssl-3.6.1/INSTALL.md
configure_make(
    name = "openssl_make",
    args = ["-j$(nproc)"],
    configure_command = "Configure",  # OpenSSL uses Configure, not configure
    configure_in_place = False,  # Avoid path conflicts with QCC
    configure_options = select({
        # OpenSSL's Configure auto-detects the host (build) machine, not the
        # target. Without an explicit target it always picks linux-x86_64 on a
        # typical CI host and injects -m64 and other x86_64-specific flags.
        # QNX has no target entry in OpenSSL's Configurations/10-main.conf
        # at all (no qnx-*, nto-*, or aarch64-unknown-nto-qnx* target exists),
        # so in all cross-compilation cases we pass the closest Linux target
        # to get the correct ABI and architecture flags. The QNX-specific
        # cross-compilation is handled transparently via the toolchain.
        "//platforms:is_qnx_aarch64": ["linux-aarch64"],
        "//platforms:is_qnx_x86_64": ["linux-x86_64"],
        "//platforms:is_linux_aarch64": ["linux-aarch64"],
        "//conditions:default": [],
    }) + [
        "no-shared",
        "no-asm",  # Disable assembly optimizations to avoid GCC inline assembly issues
        "no-threads",  # Disable threading to avoid pthread requirement on QNX
        "no-makedepend",  # Disable dependency generation that causes QCC issues
        "no-sock",  # Disable socket/network BIO (not needed for a crypto library; avoids missing socket APIs in QNX sysroot)
        # Note: ENGINE API kept enabled for SoftHSM compatibility (ENGINE is deprecated in OpenSSL 3.x but still functional)

        # Build Scope Reduction - Applications and Tools
        "no-apps",  # Skip building CLI tools (not needed for library use)
        "no-tests",  # Skip test suite compilation
        "no-docs",  # Skip documentation generation
        "no-ui-console",  # Disable console UI

        # Build Scope Reduction - Protocols
        # TLS 1.2 and 1.3 intentionally retained for future use (feat_req__sec_crypt__tls_support)
        "no-ssl3",  # Disable SSLv3 (insecure)
        "no-tls1",  # Disable TLS 1.0 (insecure)
        "no-tls1_1",  # Disable TLS 1.1 (insecure)
        "no-dtls",  # Disable DTLS (not in SCORE requirements)
        "no-srtp",  # Disable SRTP (not in SCORE requirements)

        # Build Scope Reduction - High-Level Features Not Needed for Crypto
        "no-cms",  # Disable Cryptographic Message Syntax (not in SCORE requirements)
        "no-ct",  # Disable Certificate Transparency (not in SCORE requirements)
        "no-srp",  # Disable SRP protocol (not in SCORE requirements)
        "no-ocsp",  # Disable OCSP (not in SCORE requirements)
        "no-psk",  # Disable Pre-Shared Key support (not in SCORE requirements)
        "no-nextprotoneg",  # Disable NPN TLS extension (superseded by ALPN, not in SCORE requirements)
        "no-comp",  # Disable TLS compression (CRIME attack vector; not needed)

        # Build Scope Reduction - Legacy/Obsolete Ciphers and Hashes
        "no-md2",  # Disable MD2 (obsolete)
        "no-md4",  # Disable MD4 (obsolete)
        "no-mdc2",  # Disable MDC2 (obsolete)
        "no-rc2",  # Disable RC2 (insecure, vulnerable key schedule)
        "no-rc4",  # Disable RC4 (insecure, broken stream cipher)
        "no-rc5",  # Disable RC5 (legacy, not in SCORE requirements)
        "no-idea",  # Disable IDEA cipher (legacy, not in SCORE requirements)
        "no-seed",  # Disable SEED cipher (legacy, not in SCORE requirements)
        "no-cast",  # Disable CAST cipher (legacy, not in SCORE requirements)
        "no-bf",  # Disable Blowfish (legacy, not in SCORE requirements)
        "no-camellia",  # Disable Camellia cipher (not in SCORE requirements)
        "no-aria",  # Disable ARIA cipher (not in SCORE requirements)
        "no-whirlpool",  # Disable Whirlpool hash (not in SCORE requirements)

        # Build Scope Reduction - Regional/Specialized Algorithms (not in SCORE requirements)
        "no-sm2",  # Disable SM2 (Chinese national standard elliptic curve algorithm)
        "no-sm3",  # Disable SM3 (Chinese national standard hash function)
        "no-sm4",  # Disable SM4 (Chinese national standard block cipher)
        "no-gost",  # Disable GOST (Russian/Soviet national standard cipher suite)
        "no-afalgeng",  # Disable Linux AF_ALG engine (requires linux/version.h, not available in QNX sysroot)
        "no-padlockeng",  # Disable VIA Padlock engine (x86-only, irrelevant for aarch64/QNX targets)
        "no-legacy",  # Disable legacy provider (only default provider used)
        "no-async",  # Disable async dispatch (unused, especially with no-threads)
        "-DUSE_TIMEGM",  # QNX doesn't provide the 'timezone' global variable
        "--prefix=$${INSTALLDIR}",
        "--openssldir=$${INSTALLDIR}",
        "--libdir=lib",
    ],
    env = select({
        "//platforms:is_qnx_aarch64": {
            # Override toolchain paths to use absolute paths instead of /proc/self/cwd
            "QNX_HOST": "$${PWD}/external/score_bazel_cpp_toolchains++gcc+score_qcc_aarch64_toolchain_pkg/host/linux/x86_64",
            "QNX_TARGET": "$${PWD}/external/score_bazel_cpp_toolchains++gcc+score_qcc_aarch64_toolchain_pkg/target/qnx",
        },
        "//platforms:is_qnx_x86_64": {
            "QNX_HOST": "$${PWD}/external/score_bazel_cpp_toolchains++gcc+score_qcc_x86_64_toolchain_pkg/host/linux/x86_64",
            "QNX_TARGET": "$${PWD}/external/score_bazel_cpp_toolchains++gcc+score_qcc_x86_64_toolchain_pkg/target/qnx",
        },
        "//conditions:default": {},
    }),
    lib_source = "@openssl_source//:all",
    out_lib_dir = "lib",
    out_static_libs = [
        "libcrypto.a",
        "libssl.a",
    ],
    tags = ["no-sandbox"],
    targets = [
        "build_libs",
        "install_dev",
    ],
    visibility = ["//third_party/openssl:__subpackages__"],
)

cc_library(
    name = "openssl",
    visibility = ["//visibility:public"],
    deps = [":openssl_make"],
)

cc_shared_library(
    name = "openssl_shared",
    shared_lib_name = "libopenssl.so.3",
    visibility = ["//visibility:public"],
    deps = [
        ":openssl",
        ":openssl_make",
    ],
)
