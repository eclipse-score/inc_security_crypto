load("@rules_cc//cc:defs.bzl", "cc_library")
cc_library(
    name = "score_kem_handler",
    srcs = ["src/score_kem_handler.cpp", "src/kem_executor.cpp"],
    hdrs = ["score_kem_handler.hpp", "kem_executor.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/provider/handler:handler_headers",
        "//score/crypto/src/daemon/provider/handler:kem_handler_operations",
    ],
)
