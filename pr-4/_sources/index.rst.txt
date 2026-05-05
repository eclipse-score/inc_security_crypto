..
    # =============================================================================
    #  C O P Y R I G H T
    # -----------------------------------------------------------------------------
    #  Copyright (c) 2026 by ETAS GmbH. All rights reserved.
    #
    #  The reproduction, distribution and utilization of this file as
    #  well as the communication of its contents to others without express
    #  authorization is prohibited. Offenders will be held liable for the
    #  payment of damages. All rights reserved in the event of the grant
    #  of a patent, utility model or design.
    # =============================================================================

Crypto Documentation
====================

This documentation covers the **Crypto** module — a cryptographic
middleware stack for automotive ECUs. The module
provides a C++ client library (``score::mw::crypto``) and an accompanying
crypto daemon that together deliver key management, symmetric and asymmetric
cryptography, hashing, signing, certificate handling, and secure memory
allocation.

.. contents:: Table of Contents
   :depth: 2
   :local:

Overview
--------

The ``score::mw::crypto`` module follows a **daemon-based client–server**
architecture:

- **Client library** (``//score/mw/crypto/api/...``) — a pure C++ interface layer
  that applications link against. All operations are expressed through
  factory-created context objects (``IHashContext``, ``IMacContext``, etc.)
  following an ``Init()`` → ``Update()`` → ``Finalize()`` streaming pattern.

- **Crypto daemon** (``//score/crypto/daemon:crypto_daemon``) — a separate process that
  hosts all cryptographic state, enforces per-application Access Control
  List (ACL) and per-key operation permissions (``KeyOperationPermission``
  bitmask), and drives the underlying provider (OpenSSL, SoftHSM / PKCS#11,
  or future HSM/TEE backends).

- **IPC transport** — gRPC over a Unix domain socket (Temporary solution).
  ABI compatibility between library and daemon shall be guarenteed.

Requirements
------------
..
    TODO: write comp_requirements.

Functional requirements are captured implicitly via the public interface
specifications in :ref:`crypto_interfaces` and the design decisions in
:ref:`crypto_design_decisions`.

Architecture
------------

.. toctree::
   :maxdepth: 2

   crypto/architecture/index.rst


Project Layout
--------------

The module template includes the following top-level structure:

- `.github/workflows/`: CI pipelines for Bazel build, unit tests, and documentation generation
- `docs/`: Documentation using `docs-as-code`
- `examples/`: Usage examples for each context type (hash, encrypt, sign, key management, certificates)
- `tests/`: Unit tests, integration tests, provider tests, and test vectors
- `third_party/`: Patches for third-party dependencies (if any)

Quick Start
-----------

To build documentation:

.. code-block:: bash

   bazel run //:docs

To build the module:

.. code-block:: bash

   bazel build //score/... //tests/...

To run tests:

.. code-block:: bash

   # Execute tests
   bazel test //tests/...
