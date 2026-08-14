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

# This module defines a tiny PKCS#11 header provider abstraction.
# Each PKCS#11 backend (SoftHSM, HSE, vendor modules, etc.) implements
# `pkcs11_header_provider(...)` to expose its pkcs11.h header in a uniform way.
# The dynloader depends only on the selected provider (via a label_flag),
# and therefore does not need to know which backend is chosen.

Pkcs11HeaderInfo = provider(fields = ["hdrs", "includes"])

def pkcs11_header_provider(name, hdrs, includes = ["include"]):
    native.cc_library(
        name = name + "_lib",
        hdrs = hdrs,
        includes = includes,
        visibility = ["//visibility:public"],
    )
    native.alias(
        name = name,
        actual = name + "_lib",
        visibility = ["//visibility:public"],
    )
