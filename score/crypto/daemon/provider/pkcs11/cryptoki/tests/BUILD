load("@crates//:defs.bzl", "aliases", "all_crate_deps")
load("@rules_rust//rust:defs.bzl", "rust_test")

package(default_visibility = ["//visibility:public"])

filegroup(
    name = "rust_test_sources",
    srcs = glob(["**/*.rs"]),
)

_COMMON_DEPS = ["//score/crypto/daemon/provider/pkcs11/cryptoki:cryptoki_lib"]

_TESTS_WITH_COMMON = [
    "always_authenticate",
    "attribute_policy",
    "copy_object",
    "lifecycle",
    "mechanism_policy",
    "message_api",
    "persistence_integration",
    "pkcs11_integration",
    "pkcs11_v3_integration",
    "profile_objects",
    "ro_session",
    "session_vs_token_objects",
    "token_info",
    "wrap_acl",
]

_TESTS_NO_COMMON = [
    "connect_disconnect",
    "encryption",
    "engine_integration",
    "hashing",
    "misc",
    "object_management",
    "signing",
    "slots_and_tokens",
    "storage_atomic_writes",
]

[rust_test(
    name = name,
    crate_root = name + ".rs",
    srcs = [
        name + ".rs",
        "common/mod.rs",
    ],
    aliases = aliases(
        normal_dev = True,
        proc_macro_dev = True,
        package_name = "score/crypto/daemon/provider/pkcs11/cryptoki",
    ),
    deps = _COMMON_DEPS + all_crate_deps(normal = True, package_name = "score/crypto/daemon/provider/pkcs11/cryptoki") + all_crate_deps(normal_dev = True, package_name = "score/crypto/daemon/provider/pkcs11/cryptoki"),
    proc_macro_deps = all_crate_deps(proc_macro_dev = True, package_name = "score/crypto/daemon/provider/pkcs11/cryptoki"),
    env = {"RUST_TEST_THREADS": "1"},
) for name in _TESTS_WITH_COMMON]

[rust_test(
    name = name,
    crate_root = name + ".rs",
    srcs = [name + ".rs"],
    aliases = aliases(
        normal_dev = True,
        proc_macro_dev = True,
        package_name = "score/crypto/daemon/provider/pkcs11/cryptoki",
    ),
    deps = _COMMON_DEPS + all_crate_deps(normal = True, package_name = "score/crypto/daemon/provider/pkcs11/cryptoki") + all_crate_deps(normal_dev = True, package_name = "score/crypto/daemon/provider/pkcs11/cryptoki"),
    proc_macro_deps = all_crate_deps(proc_macro_dev = True, package_name = "score/crypto/daemon/provider/pkcs11/cryptoki"),
    env = {"RUST_TEST_THREADS": "1"},
) for name in _TESTS_NO_COMMON]

test_suite(
    name = "integration_tests",
    tests = [":" + name for name in _TESTS_WITH_COMMON + _TESTS_NO_COMMON],
)
