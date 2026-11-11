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

Context Creation Is Decoded, Selected and Assembled by Separate Units
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Context Creation Is Decoded, Selected and Assembled by Separate Units
   :id: dec_rec__crypto_mediator__ctx_create_split
   :version: 1
   :status: accepted
   :context: doc__crypto_mediator_architecture
   :decision: Context creation is split into a decoder that produces a typed request, a handler selector that returns the handler, and one context assembler that builds the node for every context type. The selector uses a registered factory if there is one and otherwise a provider chosen by the provider arbiter. The units exchange values, and the mediator sequences them.
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

3. **Three units, with assembly shared.** Decoding and handler selection are
   separate from assembly, and assembly is implemented once.

Decision
--------

Option 3. The decoder is the only unit that knows the parameter layout, so a change to the
parameter layout touches the decoder and nothing else. The selector is the only
unit that varies by how a handler is obtained: it applies the rule of a registered
factory first and a provider otherwise, in one place. The assembler holds the steps that are
identical for every context type, which is why handler sources return a handler
only and never touch the data manager.

Consequences
------------

* Each unit is testable without the other two: the decoder with a parameter
  list, the selector with a factory registry and an arbiter, the arbiter with a
  provider manager, the assembler with a data manager.
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

Subsystems Register Through One Call, Made by the Mediator Factory
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Subsystems Register Through One Call, Made by the Mediator Factory
   :id: dec_rec__crypto_mediator__registration
   :version: 1
   :status: accepted
   :context: doc__crypto_mediator_architecture
   :decision: A subsystem implements one registrar interface and adds all of its context factories, resource resolvers and mediator queries in a single call. The mediator factory builds the registries, calls each registrar the daemon passes, and creates the mediator from the result. The daemon holds no registry logic and the mediator package names no subsystem.
   :affects: comp__crypto_mediator

Context
-------

The mediator needs the registries to function, and the subsystems that fill them
are created by the daemon. Three structures were considered:

1. **The daemon builds the registries.** The daemon would own the registry types,
   the order of registration and the failure handling, none of which it has any
   other use for.

2. **The mediator factory takes each subsystem module.** The daemon's code is
   short, but the factory's signature and body grow with every subsystem, and the
   mediator package depends on each subsystem's header.

3. **The mediator factory takes registrars.** Each subsystem registers itself
   through the same interface.

Decision
--------

Option 3. The daemon creates the subsystems and passes them to the factory as
registrars. Adding a subsystem adds one entry to that list and changes neither the
factory nor the mediator. A registration that is rejected, a null registrar, or a
query registered for an operation the mediator implements itself prevents the
mediator from being created, so a wiring mistake stops startup.

Consequences
------------

* The registries are read-only once the mediator exists; the mediator holds them
  as const.
* The mediator factory still receives the key-management service directly,
  because the arbiter and the assembler call it. That is a collaborator of those
  two units, not a registration. The mediator factory builds the arbiter and the
  selector over it.

Subsystem-Served Context Types Are Selected by Exact Type Before Provider Arbitration
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Subsystem-Served Context Types Are Selected by Exact Type Before Provider Arbitration
   :id: dec_rec__crypto_mediator__factory_selection
   :version: 1
   :status: accepted
   :context: doc__crypto_mediator_architecture
   :decision: The context-factory registry is consulted first for every context creation, by exact match on the full context type. A match is created by that factory and skips provider selection. Any other type goes through provider arbitration. The handler selector applies this rule.
   :affects: comp__crypto_mediator

Context
-------

Some context types are served by a subsystem and not by a provider. Their handler
is created from the subsystem's own services, and only parts of their work, such as
verification or encoding, need a provider. Routing such a type through a provider's
handler factory made the provider depend on the subsystem.

Two selection rules were considered:

1. **By scope.** Every type in a scope such as ``CERT`` would go to the subsystem
   that owns the scope. A scope can contain types that a provider serves, and a
   new type would change routing without being registered.

2. **By exact type.** A type is served by a subsystem only if that subsystem
   registered a factory for it.

Decision
--------

Option 2. The full context type is the key, so routing changes only when a factory
is registered or removed. The capability rule for a scope still applies to
provider selection, because a factory-served context is never provider-selected by
the mediator. A factory that needs a provider for part of its work selects it with
the provider preference that it receives in the request.

Consequences
------------

* The mediator does not bind a key for a factory-served context, because key
  authorization is decided per context type and such a type defines no required
  permission. A keyed request for one is refused before the factory is called.
* A context that is given a key after creation holds only the key reference; no key is
  bound at creation.
