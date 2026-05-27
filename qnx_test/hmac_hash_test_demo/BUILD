# =============================================================================
#  C O P Y R I G H T
# -----------------------------------------------------------------------------
#  Copyright (c) 2026 by ETAS GmbH. All rights reserved.
#
#  The reproduction, distribution and utilization of this file as
#  well as the communication of its contents to others without express
#  authorization is prohibited. Offenders will be held liable for the
#  payment of damages. All rights reserved in the event of the grant
#  of a patent, utility model or design.
# =============================================================================
load("@rules_cc//cc:defs.bzl", "cc_binary")

cc_binary(
    name = "score_hmac_demo",
    srcs = ["score_demo.cpp"],
    copts = ["-std=c++17"],
    linkstatic = True,
    visibility = ["//visibility:public"],
    deps = [
        "//score/mw/crypto/api:crypto_stack",
        "//tests/utility:utility",
    ],
)

filegroup(
    name = "test_vectors",
    srcs = [
        "//tests/test_vectors/mac:mac_test_vectors",
    ],
    visibility = ["//visibility:public"],
)
