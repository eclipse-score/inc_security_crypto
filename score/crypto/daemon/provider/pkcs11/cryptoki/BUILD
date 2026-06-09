load("@rules_rust//rust:defs.bzl", "rust_library", "rust_shared_library")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "src",
    srcs = glob(["**/*.rs"]) + ["Cargo.toml", "Cargo.lock"],
)

DEPS = [
    # --- Company Approved (Score Ecosystem) ---
    "@score_crates//:libc",
    "@score_crates//:serde",
    "@score_crates//:serde_json",
    "@score_baselibs_rust//src/log/score_log",
    "@score_logging//score/mw/log/rust/score_log_bridge",

    # --- Community Fallback (Crate Universe) ---
    "@crates//:argon2",
    "@crates//:dirs",
    "@crates//:once_cell",
    "@crates//:parking_lot",
    "@crates//:parsec-client",
    "@crates//:tempfile",
    "@crates//:toml",
    "@crates//:zeroize",
    "@crates//:openssl",
    "//third_party/openssl:openssl",
]

# Shared C/C++ linker flags required by score_log_bridge
CPP_LINKER_FLAGS = [
    "-Clink-arg=-lstdc++",
    "-Clink-arg=-lm",
    "-Clink-arg=-lc",
]

rust_library(
    name = "cryptoki_lib",
    crate_name = "cryptoki",
    crate_root = "lib.rs",
    srcs = glob(["**/*.rs"]),
    rustc_flags = CPP_LINKER_FLAGS,
    deps = DEPS,
)

rust_shared_library(
    name = "cryptoki_cdylib",
    crate_name = "cryptoki",
    crate_root = "lib.rs",
    srcs = glob(["**/*.rs"]),
    rustc_flags = CPP_LINKER_FLAGS,
    deps = DEPS,
)

cc_library(
    name = "cryptoki_headers",
    hdrs = ["cpp/pkcs11.h", "cpp/pkcs11_cpp.hpp"],
    includes = ["cpp"],
    visibility = ["//visibility:public"],
)
