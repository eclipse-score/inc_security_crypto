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

Mediator Requirements
=====================

.. document:: Mediator Requirements
   :id: doc__crypto_mediator_requirements
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__requirements_comp[version==1]
   :tags: mediator, crypto_daemon

Scope
-----

The requirements below cover how the mediator processes a request: context
creation (``CTX_CREATE``), delivery of an operation to an existing context,
context close, the order in which the operations of one request run, and the
entries that subsystems register with the mediator. Shared-memory setup and
teardown are described in the architecture and detailed design and are not
restated here.

Functional requirements
-----------------------

.. comp_req:: Validate context-creation requests before selecting a provider
   :id: comp_req__crypto_mediator__decode_validate
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_mediator

   The mediator shall refuse a context-creation request that fails validation
   without selecting a provider or creating a data node. Checks shall run in a
   fixed order and the first failure shall be the error the client receives:
   parameter count, context type, algorithm, provider preference, key reference,
   key requirement of the context type, algorithm catalog lookup.

.. comp_req:: Deliver creation parameters to the handler unchanged
   :id: comp_req__crypto_mediator__handler_semantics
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_mediator

   The mediator shall deliver the creation parameters of an accepted request to
   the handler's initialization unchanged, including the parameters beyond the
   common prefix. When the handler's initialization rejects them, the mediator
   shall return the handler's error to the client.

.. comp_req:: Select a provider by preference, key affinity and capability
   :id: comp_req__crypto_mediator__arbitration
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_mediator

   The mediator shall select the provider for a context from the requested
   provider type, the provider that owns the bound key (when a key is
   referenced), and the capability that the context-type scope requires. When
   the preference is ``DEFAULT`` and the scope requires a capability, selection
   shall be by capability. An explicit provider type shall still be checked
   against the required capability.

.. comp_req:: Fall back only when the client allowed it and the failure permits it
   :id: comp_req__crypto_mediator__fallback
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_mediator

   The mediator shall try a fallback provider only when the client's preference
   names one and the primary provider failed with an error classed as fallback
   eligible. A request that names one provider type shall not fall back. The
   same provider shall never be tried twice for one request.

.. comp_req:: Create the context node, bind the key and initialize the handler as one unit
   :id: comp_req__crypto_mediator__assembly
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_mediator

   The mediator shall create the context node under the client's connection,
   bind the referenced key, and initialize the handler, in that order, for every
   context type. When key binding or handler initialization fails, the mediator
   shall remove the node it created before it returns the error.

.. comp_req:: Refuse a key that does not permit the context
   :id: comp_req__crypto_mediator__key_authorization
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_mediator

   The mediator shall refuse to bind a key to a context when the key does not
   grant the permission that the context type and mode require. The refusal
   shall be decided from the key's metadata, before the key is loaded.

.. comp_req:: Report context-creation errors in the public vocabulary
   :id: comp_req__crypto_mediator__error_mapping
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_mediator

   The mediator shall report a failed context creation to the client with a
   public error code. Each daemon-internal error code shall be reported as its
   public counterpart.

.. comp_req:: Deliver an operation to the context it addresses
   :id: comp_req__crypto_mediator__forwarding
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_mediator

   The mediator shall run an operation addressed to an existing context on that
   context's handler with the operation's parameters. It shall return the
   handler's response parameters on success and the handler's error, as a public
   error code, on failure. It shall refuse an operation addressed to a node that
   does not exist or is not a context of the client, as an invalid argument,
   without running any handler.

.. comp_req:: Remove a context on close and treat an absent context as closed
   :id: comp_req__crypto_mediator__close
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_mediator

   The mediator shall remove the node of a context when the client closes it,
   which also releases the key bound to the context. Closing a context whose
   node is already absent shall succeed.

.. comp_req:: Stop a request at its first failing operation
   :id: comp_req__crypto_mediator__stop_on_failure
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_mediator

   The mediator shall run the operations of one request in order and shall stop
   at the first operation that fails. Operations after it shall not run, and the
   response shall carry only the operations that were processed.

.. comp_req:: Create a context through the factory registered for its type
   :id: comp_req__crypto_mediator__context_factory
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_mediator

   The mediator shall create a context whose type has a registered factory
   through that factory, without selecting a provider, and shall create and
   initialize the context node as it does for any other context. The factory
   shall receive the validated request. A factory error shall be returned to the
   client and no node shall remain. A request for such a type that references a
   key shall be refused as not permitted, and the factory shall not be called.

.. comp_req:: Dispatch an operation without a built-in handler to its registered query
   :id: comp_req__crypto_mediator__query_dispatch
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_mediator

   The mediator shall pass a mediator operation that it does not implement itself
   to the query registered for its operation code and return the query's result.
   An operation code with neither a built-in handler nor a registered query shall
   fail. An operation that the mediator implements itself shall never be passed
   to a query.

.. comp_req:: Resolve a named resource through the resolver registered for its type
   :id: comp_req__crypto_mediator__res_resolution
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_mediator

   The mediator shall resolve a named resource through the resolver registered
   for its resource type, passing the client and the resource name, and shall
   return the resolver's result. A resource type with no registered resolver
   shall be refused as unsupported.

.. comp_req:: Create the mediator with the entries its subsystems register
   :id: comp_req__crypto_mediator__registration
   :version: 1
   :reqtype: Functional
   :security: YES
   :safety: QM
   :status: valid
   :satisfied_by: comp__crypto_mediator

   The mediator shall be created with the context factories, resource resolvers
   and mediator queries that its subsystems register, before it serves a request.
   A rejected registration, a null registrar, or a mediator query registered for
   an operation that the mediator implements itself shall prevent its creation.
