load("@rules_cc//cc:defs.bzl", "cc_test")

cc_test(
    name = "iav_primula_key_management_test",
    srcs = ["iav_primula_key_management_test.cpp"],
    deps = [
        "//score/crypto/src/daemon/provider/score_provider:provider_iav_primula_library",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "iav_primula_signature_test",
    srcs = ["iav_primula_signature_test.cpp"],
    deps = [
        "//score/crypto/src/daemon/provider/score_provider:provider_iav_primula_library",
        "//score/crypto/src/daemon/provider/score_provider/operations/sign:score_sign_handler",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "iav_primula_verification_test",
    srcs = ["iav_primula_verification_test.cpp"],
    deps = [
        "//score/crypto/src/daemon/provider/score_provider:provider_iav_primula_library",
        "//score/crypto/src/daemon/provider/score_provider/operations/verify:score_verify_handler",
        "@googletest//:gtest_main",
    ],
)

cc_test(
    name = "iav_primula_kem_test",
    srcs = ["iav_primula_kem_test.cpp"],
    deps = [
        "//score/crypto/src/daemon/provider/handler:kem_handler_operations",
        "//score/crypto/src/daemon/provider/score_provider:provider_iav_primula_library",
        "//score/crypto/src/daemon/provider/score_provider/operations/kem:score_kem_handler",
        "@googletest//:gtest_main",
    ],
)
