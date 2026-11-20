load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
    name = "pqc_provider_key_management_test",
    srcs = ["pqc_provider_key_management_test.cpp"],
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/data_manager",
        "//score/crypto/src/daemon/key_management",
        "//score/crypto/src/daemon/key_management:key_management_headers",
        "//score/crypto/src/daemon/provider/executors:key_mgmt_executor",
        "//score/crypto/src/daemon/provider/score_provider/pqc_provider:provider_pqc_provider_library",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "pqc_provider_signature_test",
    srcs = ["pqc_provider_signature_test.cpp"],
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/provider/handler:sign_handler_operations",
        "//score/crypto/src/daemon/provider/score_provider/pqc_provider:provider_pqc_provider_library",
        "//score/crypto/src/daemon/provider/score_provider/operations/sign:score_sign_handler",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "pqc_provider_verification_test",
    srcs = ["pqc_provider_verification_test.cpp"],
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/provider/handler:verify_handler_operations",
        "//score/crypto/src/daemon/provider/score_provider/pqc_provider:provider_pqc_provider_library",
        "//score/crypto/src/daemon/provider/score_provider/operations/verify:score_verify_handler",
        "@googletest//:gtest_main",
    ],
)
