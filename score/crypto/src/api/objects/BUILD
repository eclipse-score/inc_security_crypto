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

cc_library(
    name = "crypto_objects",
    hdrs = [
        "i_crypto_object.hpp",
        "i_key_object.hpp",
        "i_key_slot_object.hpp",
        "i_private_key_object.hpp",
        "i_public_key_object.hpp",
        "i_symmetric_key_object.hpp",
    ],
    includes = ["."],
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/api/types:types",
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/result",
    ],
)

cc_library(
    name = "cert_objects",
    hdrs = [
        "i_cert_slot_object.hpp",
        "i_certificate_object.hpp",
        "i_trust_store_object.hpp",
    ],
    includes = ["."],
    visibility = ["//visibility:public"],
    deps = [
        ":crypto_objects",
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/api/types:types",
        "@score_baselibs//score/language/futurecpp",
        "@score_baselibs//score/result",
    ],
)

# Concrete implementations of the cert object interfaces.
# Private — only consumed by the API implementation layer (crypto_contexts_impl,
# crypto_context_impl). Not part of the public API surface.
cc_library(
    name = "cert_objects_impl",
    srcs = [
        "src/cert_slot_object_impl.cpp",
        "src/certificate_object_impl.cpp",
        "src/trust_store_object_impl.cpp",
    ],
    hdrs = [
        "src/cert_slot_object_impl.hpp",
        "src/certificate_object_impl.hpp",
        "src/trust_store_object_impl.hpp",
    ],
    includes = ["."],
    visibility = ["//:__subpackages__"],
    deps = [
        ":cert_objects",
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/api/types:types",
        "//score/crypto/src/api/common:release_callback_iface",
        "//score/crypto/src/api/control_plane",
        "//score/crypto/src/daemon/provider/cert_management:cert_management_provider_headers",
        "@score_baselibs//score/mw/log",
        "@score_baselibs//score/result",
    ],
)
