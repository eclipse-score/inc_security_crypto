load("@rules_cc//cc:defs.bzl", "cc_library")
cc_library(
    name = "score_sign_handler",
    srcs = ["src/score_sign_handler.cpp", "src/sign_executor.cpp"],
    hdrs = ["score_sign_handler.hpp", "sign_executor.hpp"],
    visibility = ["//:__subpackages__"],
    deps = [
        "//score/crypto/src/daemon/common",
        "//score/crypto/src/daemon/provider/handler:handler_headers",
        "//score/crypto/src/daemon/provider/handler:handler_utils_impl",
        "//score/crypto/src/daemon/provider/handler:sign_handler_operations",
    ],
)
