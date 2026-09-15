..
   # *******************************************************************************
   # Copyright (c) 2026 Contributors to the Eclipse Foundation
   #
   # See the NOTICE file(s) distributed with this work for additional
   # information regarding copyright ownership.
   #
   # This program and the accompanying materials are made available under the
   # terms of the Apache License Version 2.0 which is available at
   # https://www.apache.org/licenses/LICENSE-2.0
   #
   # SPDX-License-Identifier: Apache-2.0
   # *******************************************************************************

.. _crypto_feature_architecture:

Feature Architecture
====================

.. document:: Crypto Architecture
   :id: doc__crypto_feat_architecture
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__feature_arch

.. feat:: Security & Crypto
   :id: feat__security_crypto
   :version: 1
   :security: YES
   :safety: QM
   :status: valid



Overview
--------

The Security & Crypto feature provides applications with a provider-independent
way to execute cryptographic operations without coupling application code to a
specific software library, PKCS#11 token, HSM, or TEE. The current implementation
uses a client-daemon split: applications use the C++ API, while a dedicated daemon
selects providers, owns operation contexts, and executes cryptographic jobs.

The feature is security-relevant but currently classified as QM. In particular,
the complete client, IPC/shared-memory, daemon, and provider path is not presented
as an ISO 26262-qualified replacement for safety-certified Baselibs hashing.

Description
-----------

The feature is decomposed into the following responsibilities:

* The public API creates a crypto stack, logical crypto contexts, and typed
  operation contexts such as hash and MAC contexts.
* The control plane serializes lifecycle and operation requests and transports
  them to the daemon.
* The data plane selects in-band, pooled shared-memory, or registered bulk
  shared-memory transport based on the supplied buffers.
* The daemon validates requests, maintains context state, selects a provider,
  and dispatches the requested job.
* Provider adapters translate the common operation contract to a concrete
  backend. The implemented provider families include OpenSSL and PKCS#11.
* Key-management services resolve key slots and provider-owned key objects
  without exposing provider-specific handles through the application API.

Important design decisions are:

* Provider-independent algorithm identifiers are part of the API and wire
  contract. Provider-native identifiers are resolved only inside the daemon.
* Operation contexts are explicit resources with a daemon-managed lifecycle.
* Large buffers use validated shared-memory references to avoid unnecessary
  copies while keeping ownership with the caller.
* Provider selection is performed during context creation; an operation does
  not silently change providers after the context has been created.
* Streaming jobs use an explicit state machine so invalid ordering is rejected
  before a provider call is made.

The design is constrained by provider capability differences, PKCS#11 token and
session limits, process-boundary failure modes, and the lifetime of caller-owned
buffers. Applications must handle unavailable providers and unsupported
algorithms explicitly. Algorithms with variable output or provider-specific
parameters require an API-level contract before they can be exposed portably.

Requirements
------------

Component requirements and assumptions of use are maintained with the Crypto
component documentation. Feature-level ownership and cross-repository consumer
migration for the Baselibs hash transition remain tracked by
`inc_security_crypto issue #125 <https://github.com/eclipse-score/inc_security_crypto/issues/125>`_.
The consumer migration and removal of Baselibs algorithms are deliberately not
claimed by this repository's component requirements.

Rationale Behind Architecture Decomposition
*******************************************

The process boundary isolates applications from provider initialization,
credentials, sessions, and provider-specific failure handling. Separating the
control and data planes permits small requests to remain simple while large data
can use shared memory. A common handler contract lets OpenSSL serve development
and software deployments while PKCS#11 connects the same API to hardware-backed
implementations. Keeping key and operation resources in the daemon also reduces
the amount of provider-specific state exposed to clients.

Static Architecture
-------------------

The principal static dependencies are:

.. code-block:: text

   Application
       |
       v
   Crypto C++ API -- Control plane client -- IPC -- Crypto daemon
       |                                      |
       +-- Buffer/SHM data plane -------------+
                                              |
                                              v
                                     Provider manager
                                       /          \
                                      v            v
                               OpenSSL provider  PKCS#11 provider
                                                    |
                                                    v
                                             Token / HSM / TEE

Detailed component, interface, data-plane, provider, and key-management views
are available in the ``score/crypto/docs/architecture`` documentation.

Dynamic Architecture
--------------------

A typical operation follows this sequence:

#. The application creates a stack and connects to the configured daemon
   endpoint.
#. It creates a crypto context and requests a typed operation context with an
   algorithm and optional provider selection.
#. The daemon resolves and validates the provider, creates a handler, and
   returns an opaque context identifier.
#. Each operation request carries control metadata and either in-band data or
   validated shared-memory references.
#. The handler validates the operation state and dispatches to the selected
   provider.
#. The daemon returns a status and output length; output bytes are written to
   the caller-owned buffer.
#. Reset returns a reusable operation context to its idle state, while context
   destruction releases daemon and provider resources.

For hashing, valid flows are ``SingleShot`` or ``Init`` followed by zero or more
``Update`` calls and ``Finalize``. A retryable validation error such as an
undersized final output buffer does not consume the active stream.

Logical Interfaces
------------------

The public logical interface is the provider-independent Crypto C++ API. The
client-daemon protocol and provider handler interfaces are internal logical
interfaces and are versioned with the component implementation. Provider-native
APIs, including OpenSSL EVP and PKCS#11 Cryptoki, terminate at their respective
daemon adapters and are not exposed to applications.

Used Components
---------------

The feature is currently realized by the ``Crypto`` component
(``comp__crypto``). External consumers and the eventual Baselibs cleanup are
separate repository changes and are outside this component's implementation
boundary.
