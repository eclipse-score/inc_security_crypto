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
    name = "data_plane_client",
    srcs = [
        "src/allocation_error.hpp",
        "src/buffer_shm_transcoder.cpp",
        "src/buffer_shm_transcoder.hpp",
        "src/pool_allocator.cpp",
        "src/pool_allocator.hpp",
        "src/shm_memory_allocator.cpp",
        "src/shm_memory_allocator.hpp",
        "src/shm_memory_factory.cpp",
        "src/shm_region_registry.cpp",
        "src/shm_region_registry.hpp",
        "src/shm_rw_memory.cpp",
        "src/shm_rw_memory.hpp",
    ],
    hdrs = [
        "i_buffer_transcoder.hpp",
        "i_pool_allocator.hpp",
        "i_read_write_memory_factory.hpp",
        "i_shm_region_registry.hpp",
        "shm_memory_factory.hpp",
    ],
    visibility = ["//visibility:public"],
    deps = [
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/api/control_plane",
        "//score/crypto/src/common:common_types",
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/control_plane:request_handler_hdr",
        "//score/crypto/src/daemon/mediator:mediator_operations",
        "@score_baselibs//score/memory/shared",
        "@score_baselibs//score/mw/log",
    ],
)
