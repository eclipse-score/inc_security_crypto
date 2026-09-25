<!--
*******************************************************************************
Copyright (c) 2026 Contributors to the Eclipse Foundation

See the NOTICE file(s) distributed with this work for additional
information regarding copyright ownership.

This program and the accompanying materials are made available under the
terms of the Apache License Version 2.0 which is available at
https://www.apache.org/licenses/LICENSE-2.0

SPDX-License-Identifier: Apache-2.0
*******************************************************************************
-->
# C++ & Rust Bazel Template Repository

This repository serves as a **template** for setting up **C++ and Rust projects** using **Bazel**.
It provides a **standardized project structure**, ensuring best practices for:

- **Build configuration** with Bazel.
- **Testing** (unit and integration tests).
- **Documentation** setup.
- **CI/CD workflows**.
- **Development environment** configuration.

---

## 📂 Project Structure

| File/Folder                         | Description                                       |
| ----------------------------------- | ------------------------------------------------- |
| `README.md`                         | Short description & build instructions            |
| `score/`                            | Crypto component                                  |
| `tests/`                            | Unit tests (UT) and integration tests (IT)        |
| `examples/`                         | Example files used for guidance                   |
| `third_party/`                      | Build file for external dependencies (e.g. gRPC)  |
| `docs/`                             | Documentation (Doxygen for C++ / mdBook for Rust) |
| `.vscode/`                          | Recommended VS Code settings                      |
| `.bazelrc`, `MODULE.bazel`, `BUILD` | Bazel configuration & settings                    |
| `project_config.bzl`                | Project-specific metadata for Bazel macros        |

### Score Folder Layout

```
score/                            ← Source code  ◄ main
├── mw/crypto/
│   └── api/                      ← [LIBRARY]
│       ├── common/
│       ├── config/               ← API config
│       ├── contexts/             ← Crypto contexts
│       ├── objects/              ← Key/cert objects
│       └── src/                  ← Entry point
│
├── crypto/
│   ├── api/
│   │   └── control_plane/        ← [LIB CTRL-PLANE]
│   │
│   ├── ipc/
│   │   └── grpc_adapter/         ← [IPC — gRPC]
│   │
│   └── daemon/
│       ├── control_plane/        ← [DAEMON CTRL-PLANE]
│       ├── mediator/             ← [MEDIATOR]
│       ├── data_manager/         ← [DATA MANAGER]
│       ├── key_management/       ← [KEY MANAGEMENT]
│       ├── config/               ← [CONFIG]
│       └── provider/
│           ├── score_provider/   ← [SW PROVIDER / OpenSSL]
│           └── pkcs11/           ← [HW PROVIDER / PKCS#11]
│
└── cryptoki/                     ← [HW SECURE PROVIDER / PKCS#11 Rust Library]  ◄ Peer Package
```

---

## 🚀 Getting Started

### 1️⃣ Clone the Repository

```sh
git clone https://github.com/eclipse-score/YOUR_PROJECT.git
cd YOUR_PROJECT
```

### 2️⃣ Build the Examples of module

> DISCLAIMER: Depending what module implements, it's possible that different
> configuration flags needs to be set on command line.

To build all targets of the module the following command can be used:

```sh
# host platform
bazel build //score/...
# qnx arm architecture
# check .bazelrc for available host (x86_64) and target (aarch64) configurations
bazel build //score/... --config=aarch64-qnx
```

### 3️⃣ Run Tests

```sh
# pre-requisite: pull ubuntu docker image within devcontainer (once)
docker pull ubuntu:24.04

# host platform
bazel test //score/...
# with detailed output and no caching
bazel test //score/... --test_output=all --cache_test_results=no
# single integration test (via pytest -k option)
bazel test //score/tests/integration_tests:integration_test --test_arg="-k" --test_arg="test_score_api_hash" --test_output=all

# cc_test and rust_test for x86_64-qnx target
bazel test //score/... --config=x86_64-qnx
# itf based integration test for x86_64-qnx target
bazel test //score/... --config=x86_64-qnx-itf
```

Note: Run the `docker pull` command from a VS Code Terminal associated with the devcontainer. This properly sets up all environment variables, which may not be the case when just using docker to attach to the running container.

### 4️⃣ Generate Coverage

Run the LLVM coverage tests and generate the HTML report locally:

```sh
bazel coverage --config=llvm_cov --build_tests_only -- //score/...

COVERAGE_THRESHOLD=0 bazel run @score_tooling//coverage:generate_coverage_html -- \
    --yaml tools/coverage/coverage_justifications.yaml \
    --testlogs-subdir score \
    --archive-dir coverage_artifact
```

---

## 🛠 Tools & Linters

The template integrates **tools and linters** from **centralized repositories** to ensure consistency across projects.

- **C++:** `clang-tidy`, `cppcheck`, `Google Test`
- **Python:** `ruff`
- **Rust:** `clippy`, `rustfmt`, `Rust Unit Tests`
- **CI/CD:** GitHub Actions for automated builds and tests

Generate the Bazel-managed `.venv_test` environment with `bazel run //:venv` and use `.venv_test/bin/python` as the VS Code Python interpreter.

---

## 📖 Documentation

- A **centralized docs structure** is planned.

```sh
bazel run //:docs
```

---

## ⚙️ `project_config.bzl`

This file defines project-specific metadata used by Bazel macros, such as `dash_license_checker`.

### 📌 Purpose

It provides structured configuration that helps determine behavior such as:

- Source language type (used to determine license check file format)
- Safety level or other compliance info (e.g. ASIL level)

### 📄 Example Content

```python
PROJECT_CONFIG = {
    "asil_level": "QM",  # or "ASIL-A", "ASIL-B", etc.
    "source_code": ["cpp", "rust"]  # Languages used in the module
}
```

### 🔧 Use Case

When used with macros like `dash_license_checker`, it allows dynamic selection of file types
 (e.g., `cargo`, `requirements`) based on the languages declared in `source_code`.

## DevContainer Setup

The supported development environment is defined by
`.devcontainer/devcontainer.json` and `.devcontainer/Dockerfile`. It currently
uses `ghcr.io/eclipse-score/devcontainer:v1.11.0` and enables Docker-in-Docker
for integration tests.

### Prerequisites

- Docker Desktop or a compatible Docker Engine
- Visual Studio Code with the **Dev Containers** extension
- A local clone of this repository

The `code` and `devcontainer` terminal commands are optional and are not
installed automatically with the macOS applications.

Create the host paths that are mounted by the devcontainer before opening it:

```bash
touch ~/.netrc
mkdir -p ~/.cache/bazel ~/.qnx/license
```

The QNX license directory may remain empty when only Linux targets are built.
The `.netrc` file may also remain empty when no authenticated dependency source
is required, but it must exist because the devcontainer mounts it as a file.

### Open the official environment

On macOS, open the repository without requiring the optional `code` command:

```bash
open -a "Visual Studio Code" .
```

Alternatively, open Visual Studio Code from Applications and select
**File → Open Folder**. To enable `code .` later, open the Command Palette and
run **Shell Command: Install 'code' command in PATH**.

1. Open the repository root in Visual Studio Code using either method above.
2. Run **Dev Containers: Reopen in Container** from the Command Palette.
3. Wait for the image build and the `onCreateCommand` setup to finish.
4. Open a new VS Code terminal. The terminal is now running inside the official
   development container.

Confirm the expected tools are available:

```bash
bazel --version
clang-format --version
docker version
uname -m
```

The separate Dev Container CLI is only needed for terminal-based startup. Since
Node.js and npm are already available, it can be installed and verified with:

```bash
npm install -g @devcontainers/cli
rehash
devcontainer --version
```

After the optional CLI is installed, the same environment can be started with:

```bash
devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . bash
```

The PR Linux workflow runs on x86_64. On Apple Silicon, the multi-architecture
image starts as `aarch64`; the crypto targets and focused tests below run in
that environment, but the repository-wide `//score/...` set currently reaches
an upstream `score_logging` Rust bridge that has no native aarch64 layout
configuration. Run the full CI-equivalent suite in an x86_64 Linux devcontainer
or CI runner. With the Dev Container CLI, an x86_64 container can be requested
from Apple Silicon as follows when Docker emulation is enabled:

```bash
DOCKER_DEFAULT_PLATFORM=linux/amd64 devcontainer up --workspace-folder .
devcontainer exec --workspace-folder . bash
```

### Build and test inside the devcontainer

Run all commands below from the devcontainer terminal:

```bash
# Build the crypto component (also usable in the native Apple Silicon container).
bazel build //score/crypto/...

# Build every Linux target on the x86_64 CI architecture.
bazel build //score/...

# Run the provider-level hash tests used by the Baselibs hash migration.
bazel test \
  //score/crypto/src/daemon/provider/tests/provider_test:test_provider \
  //score/crypto/src/daemon/provider/tests/provider_test:test_pkcs11_provider \
  --test_output=errors

# The Docker-based integration test needs this image in the devcontainer's
# Docker daemon. Pull it once after creating or rebuilding the devcontainer.
docker pull ubuntu:24.04
bazel test //score/tests/integration_tests:integration_test \
  --test_output=all \
  --cache_test_results=no

# Run the complete PR test scope on the x86_64 CI architecture.
bazel test //score/... --test_output=errors

# Build the project documentation.
bazel run //:docs
```

`bazel run //examples:hashing_example` is a client-only example. It expects a
configured crypto daemon already listening on
`unix:///tmp/crypto_daemon.sock`; use the Docker integration target above for a
self-contained daemon-and-client execution.

### Formatting and repository checks

The repository's pre-commit configuration runs Bazel metadata checks,
`clang-format`, `clang-tidy`, and the Eclipse copyright checker:

```bash
pre-commit run --all-files
```

The current upstream workflow temporarily skips pre-commit in the common PR
job because the repository-wide clang-tidy baseline is not yet clean. Changed
C++ files must still follow the checked-in `.clang-format` configuration.

### Known Issue: Pre-commit Hook Not Running
**Problem:** The pre-commit hook does not run when using `git commit` inside the DevContainer.

**Cause:** A stale `core.hooksPath` configuration overrides the default hook lookup path.

**Fix:** Unset the custom hooks path:

```bash
git config --unset core.hooksPath
```

Note: For a permanent fix, run this command on the **host machine** (outside the DevContainer).
The DevContainer only receives a copy of the host's Git configuration at build time, so changes
made inside the container will not persist after a rebuild.

---

# Valeo S-CORE Crypto Module

This is the main eclipse-score repository of the security-crypto module.

## Supported Providers

This repository supports multiple interchangeable cryptographic backends:
*   **SoftHSM (C++ Default)**: The default fallback emulator.
*   **Valeo Cryptoki (Rust Backend)**: S-CORE's high-security Rust-based PKCS#11 provider. For complete compilation, running, and troubleshooting manuals, please refer directly to the [Valeo Cryptoki Integration Guide](score/cryptoki/README.md).

## Use of genAI in this repository
The repository partially contains AI-generated code by using GitHub Copilot Business.
This notice needs to remain attached to any reproduction of this repository.
