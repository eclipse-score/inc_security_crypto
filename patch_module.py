import sys

with open("MODULE.bazel", "r") as f:
    content = f.read()

if "archive_override(\n    module_name = \"score_baselibs_rust\"" not in content:
    with open("MODULE.bazel", "a") as f:
        f.write("""
archive_override(
    module_name = "score_baselibs_rust",
    urls = ["https://github.com/eclipse-score/baselibs_rust/archive/refs/tags/v0.1.2.tar.gz"],
    strip_prefix = "baselibs_rust-0.1.2",
    patches = ["//third_party/patches:score_baselibs_rust_fmt.patch"],
    patch_strip = 1,
)
""")
