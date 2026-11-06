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

Mediator Design Decisions
=========================

Context Creation Is Decoded, Arbitrated and Assembled by Separate Units
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Context Creation Is Decoded, Arbitrated and Assembled by Separate Units
   :id: dec_rec__crypto_mediator__ctx_create_split
   :version: 1
   :status: accepted
   :context: doc__crypto_mediator_architecture
   :decision: Context creation is split into a decoder that produces a typed request, a provider arbiter that returns a provider and handler, and one context assembler that builds the node for every context type. The units exchange values and do not call one another.
   :affects: comp__crypto_mediator

Context
-------

Context creation does three unrelated jobs: it interprets wire parameters, it
chooses who builds the handler, and it creates the node, binds the key and
initializes the handler. They change for different reasons. The wire layout
changes with the client-facing protocol. The choice of provider changes with
provider policy and with the sources of handlers. Assembly changes only with the
node and key-binding contract.

Three structures were considered:

1. **One function.** A single unit, but every change touches code that serves the
   other two concerns, and none of the three can be tested without the others.

2. **A factory per context type doing all three jobs.** Each subsystem would
   decode, create its node and roll back. Node creation, key binding and
   rollback would then exist once per subsystem and drift apart.

3. **Three units, with assembly shared.** Decoding and arbitration are separate
   from assembly, and assembly is implemented once.

Decision
--------

Option 3. The decoder is the only unit that knows the parameter layout, so a change to the
parameter layout touches the decoder and nothing else. The arbiter is the only
unit that varies by how a handler is obtained. The assembler holds the steps that are
identical for every context type, which is why handler sources return a handler
only and never touch the data manager.

Consequences
------------

* Each unit is testable without the other two: the decoder with a parameter
  list, the arbiter with a provider manager, the assembler with a data manager.
* Node creation, key binding and rollback have one implementation.
* The mediator's context-creation entry point reduces to sequencing the units
  and writing the response.

Key Authorization Has One Implementation
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Key Authorization Has One Implementation
   :id: dec_rec__crypto_mediator__key_authorization
   :version: 1
   :status: accepted
   :context: doc__crypto_mediator_architecture
   :decision: Authorizing a key for a context and binding it to the context node is one key-management operation. Every caller that binds a key to a context uses it, and it runs before the handler is initialized.
   :affects: comp__crypto_mediator

Context
-------

A key bound to a context is used for one operation and one direction for the
context's whole life, so one check at binding covers every operation that runs
on the context. The check compares the permissions the key grants with the
permission the context type and mode require. It must be decided before the key
is loaded or bound, so that a request the key does not permit is refused from
metadata alone.

Three placements were considered:

1. **A check in each caller.** Each caller that needs a bound key carries its own
   copy. The copies can disagree, and a disagreement is a way around key
   permissions.

2. **A check in the handler at initialization.** The handler sees only a key that
   is already bound, so the key has been loaded and bound before the refusal.
   Every handler would also need the same check.

3. **One key-management operation.** The check and the binding are a single
   operation owned by the component that owns the keys.

Decision
--------

Option 3. The operation checks that the context type requires a key permission,
then that the key grants it, then binds the key. The assembler calls it when a
key is referenced, and any other caller that needs a key bound to a context calls
the same operation.

Consequences
------------

* The check order and its error codes are defined in one place.
* The handler receives a key that has already been authorized and does not
  repeat the check.

Capability Routing Applies Only When the Client Expresses No Provider Preference
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Capability Routing Applies Only When the Client Expresses No Provider Preference
   :id: dec_rec__crypto_mediator__cap_default_only
   :version: 1
   :status: accepted
   :context: doc__crypto_mediator_architecture
   :decision: A context-type scope that requires a provider capability selects the provider by capability only when the requested provider type is DEFAULT. An explicit provider type selects by type, and the chosen provider must still have the required capability.
   :affects: comp__crypto_mediator

Context
-------

Some context families, such as certificate contexts, are served by providers
with a particular capability, and the daemon prefers a software provider for
them. A client can also ask for a hardware or software provider explicitly.

If capability routing overrode an explicit request, a client could not obtain
the provider it named. If an explicit request ignored the capability, a provider
that cannot serve the context could be selected and fail later, at handler
creation or at first use.

Decision
--------

The capability preference is the default only. An explicit provider type selects
by type, and the capability is then checked on the selected provider. A provider
without it is skipped and the failure is reported as unsupported, which is
eligible for fallback when the client allowed one.

Consequences
------------

* The scope-to-capability table is arbitration policy. It sits with the
  context-type definitions and not with the wire-protocol definitions, so
  arbitration does not depend on the wire format.
* A context type whose scope is not in the table adds no capability
  constraint.
