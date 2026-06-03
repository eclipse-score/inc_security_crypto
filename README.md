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
└── crypto/
    ├── api/
    │   └── control_plane/        ← [LIB CTRL-PLANE]
    │
    ├── ipc/
    │   └── grpc_adapter/         ← [IPC — gRPC]
    │
    └── daemon/
        ├── control_plane/        ← [DAEMON CTRL-PLANE]
        ├── mediator/             ← [MEDIATOR]
        ├── data_manager/         ← [DATA MANAGER]
        ├── key_management/       ← [KEY MANAGEMENT]
        ├── config/               ← [CONFIG]
        └── provider/
            ├── score_provider/   ← [SW PROVIDER / OpenSSL]
            └── pkcs11/           ← [HW PROVIDER / PKCS#11]
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
# linux ARM architecture
# check .bazelrc for available host (x86_64) and target (aarch64) configurations
bazel build //score/... --config=target_config_3
```

### 3️⃣ Run Tests

```sh
# pre-requisite: pull ubuntu docker image within devcontainer (once)
docker pull ubuntu:24.04

# host platform
bazel test //tests/...
# with detailed output and no caching
bazel test //tests/... --test_output=all --cache_test_results=no
```

Note: Run the `docker pull` command from a VS Code Terminal associated with the devcontainer. This properly sets up all environment variables, which may not be the case when just using docker to attach to the running container.

---

## 🛠 Tools & Linters

The template integrates **tools and linters** from **centralized repositories** to ensure consistency across projects.

- **C++:** `clang-tidy`, `cppcheck`, `Google Test`
- **Rust:** `clippy`, `rustfmt`, `Rust Unit Tests`
- **CI/CD:** GitHub Actions for automated builds and tests

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

# Use of genAI in this repository
The repository partially contains AI-generated code by using GitHub Copilot Business.
This notice needs to remain attached to any reproduction of this repository.
