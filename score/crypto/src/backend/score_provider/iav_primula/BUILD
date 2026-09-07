load("@rules_cc//cc:defs.bzl", "cc_library")

cc_library(
    name = "primula_backend_adapter",
    srcs = ["primula_backend_adapter.cpp"],
    hdrs = ["primula_backend_adapter.hpp"],
    target_compatible_with = select({
        "//score/crypto/src/backend:primula_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//score/crypto/src/backend/score_provider:__pkg__"],
    deps = [
        "//score/crypto/src/daemon/provider/score_provider:score_backend_adapter",
        "//score/crypto/src/daemon/provider/score_provider:provider_iav_primula_library",
    ],
)

cc_library(
    name = "primula_backend_define",
    defines = ["SCORE_BACKEND_PRIMULA_ENABLED=1"],
    target_compatible_with = select({
        "//score/crypto/src/backend:primula_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = [
        "//score/crypto/src/backend:__pkg__",
        "//score/crypto/src/backend/score_provider:__pkg__",
    ],
)

cc_library(
    name = "primula_backend",
    target_compatible_with = select({
        "//score/crypto/src/backend:primula_backend_active": [],
        "//conditions:default": ["@platforms//:incompatible"],
    }),
    visibility = ["//score/crypto/src/backend/score_provider:__pkg__"],
    deps = [":primula_backend_adapter", ":primula_backend_define"],
)
