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

Mediator Architecture
=====================

.. document:: Mediator Architecture
   :id: doc__crypto_mediator_architecture
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__component_arch
   :tags: mediator, architecture

Purpose
-------

The mediator sits between the control plane and the daemon subsystems. It owns
the decisions that involve more than one subsystem: which provider serves a
context, how a context node comes to exist with its key bound, and where an
operation on an existing context is delivered. It does not own keys,
certificates, provider cryptography or storage; it asks the subsystem that does.

Provider arbitration belongs here because choosing between providers is itself
mediation: the choice depends on the client's preference, the key's owner and
the provider's capabilities, which no single provider can see.

Overview
--------

The mediator handles these operation families:

* **Context creation** (``CTX_CREATE``) — decode, arbitrate, assemble. Described
  below.
* **Context close and shared-memory setup and teardown** — node lifecycle under
  the client's connection.
* **Resource resolution** — session-level lookup of a named resource to a data
  node, through one resolver per resource type. A resolver is registered when
  the mediator is built; key slots are resolved through key management.
* **Forwarding** — an operation addressed to an existing context is delivered to
  that context's handler.

.. uml:: mediator_overview.puml

Request processing
------------------

A request carries one or more operations, all addressed to the node named in the
request. Each operation names an actor. An operation addressed to the mediator
actor is handled by the mediator, and its action selects the family above.
Every other operation is forwarded to the handler of the context node the
request addresses.

The operations of a request run in order and processing stops at the first one
that fails, because later operations can depend on earlier ones. The response
carries the results of the operations that were processed.

Forwarding takes the context's handler from the node and runs the operation on
it; the mediator does not interpret the operation. Closing a context deletes its
node, which also releases the key bound to the context. Deletion is idempotent:
a node that is already absent counts as closed. Shared-memory setup creates a
data node under the connection for a shared-memory region, and teardown deletes
it. Resource resolution looks up a resolver by resource type and returns the
node it resolves to.

Context creation
----------------

Context creation is three steps with one owner each:

.. list-table::
   :header-rows: 1
   :widths: 30 70

   * - Step
     - Responsibility
   * - Decode (``DecodeContextCreationRequest``)
     - Turns the wire parameters into a typed ``ContextCreationRequest`` and
       rejects malformed requests. The only step that knows the parameter
       layout.
   * - Arbitrate (``ProviderArbiter``)
     - Chooses a provider and asks its handler factory for a handler.
   * - Assemble (``ContextAssembler``)
     - Creates the context node, binds and authorizes the key, initializes the
       handler, and undoes the node on failure.

The steps communicate through values, not through each other: the decoder
produces a request, the arbiter returns a provider and a handler, and the
assembler consumes the handler. The mediator's context-creation entry point
only sequences them.

Static decomposition
--------------------

The composition diagram shows the implementation units and what each depends on.

.. uml:: mediator_composition.puml

Responsibilities that stay out of each step
-------------------------------------------

* The decoder performs no provider or data-node work.
* The arbiter does not create data nodes, bind keys or initialize handlers.
* The assembler does not choose providers. It receives a handler that already
  exists and a provider id.

Division of validation
----------------------

Validation is split by what it depends on:

* **The mediator** checks the shape of the request: parameter count and types,
  a known provider preference, a non-zero key reference. It also applies three
  context-type rules, because each decides something that must be known before
  a handler exists or before a key is loaded: whether the type requires a key,
  whether it takes an algorithm, and which provider capability its scope
  requires. Authorizing a bound key against the context's operation and
  direction is delegated to key management for the same reason.
* **The handler** validates everything about what the context does when it
  initializes: operation mode, padding, input mode, and every parameter beyond
  the common prefix. The mediator passes those parameters through unchanged and
  does not interpret them.

The mediator's knowledge of a context type is limited to whether it requires a key
permission, whether it takes an algorithm, and which provider capability its scope
requires. A rule that depends on the context's behaviour belongs in the handler.

This separation matters because the assembler's work is identical for every
context type. Any component that supplies handlers, whether a provider or
another subsystem, returns a handler and nothing else, and does not repeat node
creation, key binding or rollback.

Variation and reuse points
--------------------------

The structure has two points where behaviour varies or is reused without
changing the other steps.

* **The source of a handler** is an arbitration concern only. Decoding and
  assembly are unaffected, because assembly takes a handler without regard to
  where it came from.
* **A daemon-internal caller that needs a context** — for example a handler that
  must have a signature produced by a key it is not allowed to read — reuses
  assembly instead of re-implementing node creation, key binding and rollback.
  Its authorization is taken from the initiating context and goes through the
  same key-management check as a client request, so that one implementation of
  the check serves both paths. The mediator does not define the form of such a
  caller.

A change to the wire format is confined to the decoder. Arbitration and assembly
consume the typed request unchanged.
