load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
    name = "iav_primula_application_integration_test",
    srcs = ["iav_primula_application_integration_test.cpp"],
    deps = [
        "//score/crypto/src/daemon/provider/handler:handler_headers",
        "//score/crypto/src/daemon/provider/handler:sign_handler_operations",
        "//score/crypto/src/daemon/provider/handler:verify_handler_operations",
        "//score/crypto/src/daemon/provider/score_provider:provider_iav_primula_library",
        "//score/crypto/src/daemon/provider/score_provider/operations/factory:score_handler_factory",
        "@googletest//:gtest_main",
    ],
)
