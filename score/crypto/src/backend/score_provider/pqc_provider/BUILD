load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "pqc_provider_backend_adapter",
    srcs = ["pqc_provider_backend_adapter.cpp"],
    hdrs = ["pqc_provider_backend_adapter.hpp"],
    target_compatible_with = select({
        "//score/crypto/src/backend:pqc_provider_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//score/crypto/src/backend/score_provider:__pkg__"],
    deps = [
        "//score/crypto/src/daemon/provider/score_provider:score_backend_adapter",
        "//score/crypto/src/daemon/provider/score_provider/pqc_provider:provider_pqc_provider_library",
    ],
)

cc_library(
    name = "pqc_provider_backend_define",
    defines = ["SCORE_BACKEND_PQC_PROVIDER_ENABLED=1"],
    target_compatible_with = select({
        "//score/crypto/src/backend:pqc_provider_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = [
        "//score/crypto/src/backend:__pkg__",
        "//score/crypto/src/backend/score_provider:__pkg__",
    ],
)

cc_library(
    name = "pqc_provider_backend",
    target_compatible_with = select({
        "//score/crypto/src/backend:pqc_provider_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//score/crypto/src/backend/score_provider:__pkg__"],
    deps = [":pqc_provider_backend_adapter", ":pqc_provider_backend_define"],
)
