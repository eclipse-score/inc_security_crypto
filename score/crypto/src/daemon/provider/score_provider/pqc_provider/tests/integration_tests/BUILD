load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
    name = "pqc_provider_application_integration_test",
    srcs = ["pqc_provider_application_integration_test.cpp"],
    deps = [
        "//score/crypto/src/api/common:crypto_common",
        "//score/crypto/src/daemon/common:algorithm_catalog",
        "//score/crypto/src/daemon/provider/handler:handler_headers",
        "//score/crypto/src/daemon/provider/handler:sign_handler_operations",
        "//score/crypto/src/daemon/provider/handler:verify_handler_operations",
        "//score/crypto/src/daemon/provider/score_provider/pqc_provider:provider_pqc_provider_library",
        "//score/crypto/src/daemon/provider/score_provider/operations/factory:score_handler_factory",
        "//score/crypto/src/daemon/provider/score_provider/operations/sign:score_sign_handler",
        "//score/crypto/src/daemon/provider/score_provider/operations/verify:score_verify_handler",
        "@googletest//:gtest_main",
    ],
)
