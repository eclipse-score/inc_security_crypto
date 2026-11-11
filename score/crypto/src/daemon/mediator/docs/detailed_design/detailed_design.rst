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

Mediator Detailed Design
========================

.. document:: Mediator Detailed Design
   :id: doc__crypto_mediator_detailed_design
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__sw_implementation
   :tags: mediator, detailed_design

Implementation units
--------------------

The composition diagram in the architecture shows the implementation units and
their dependencies. The use cases below show how they interact.

Use cases
---------

Creating a context
~~~~~~~~~~~~~~~~~~

Decoding reports every failure as ``kInvalidArgument`` except an algorithm name
the catalog does not know, which is ``kUnsupportedAlgorithm``. The validation
order is defined by the validation requirement. After decoding, the handler selector
chooses the handler. A context type with a registered factory is created by that
factory; any other type is created through a provider chosen by the arbiter. A factory
error is returned to the client and no node is created; a key reference on a
factory-served type is refused with ``kKeyOperationNotPermitted`` and the factory is
not called.

.. uml:: uc_context_creation.puml

Operating on and closing a context
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. uml:: uc_operation_forwarding.puml

Registered entries
------------------

The mediator hands an operation to a registered query only when it implements no
handler for that operation code itself; a query at a built-in code is never called.
An operation code with neither fails. A resource type with no registered resolver is
``kUnsupportedOperation``.

Creating the mediator fails with ``kInternalError`` if a registrar is null or reports
a rejected registration, and with ``kInvalidArgument`` if a query is registered for a
built-in operation code.

Fallback policy
---------------

A provider failure moves a request to its fallback provider only when the failure
is one of ``kUnsupportedOperation``, ``kUnsupportedAlgorithm``,
``kProviderNotAvailable`` or ``kIncompatibleKeyType``. Any other failure ends
arbitration with that error. When every candidate fails, the last error is
returned. A provider that lacks the capability the context-type scope requires
counts as unsupported.

Shared-memory provider selection
--------------------------------

Shared-memory setup selects a provider only to obtain its shared-memory factory.
This differs from context creation: it accepts a provider id as well as a type
hint, it has no key or capability input, and it falls back to the second type of a
preference only when the first type has no provider, not when a provider cannot
supply a factory. Pool mode takes its size, factory and quotas from the
deployment configuration of the requesting user, not from the request.

Error vocabulary
----------------

Decoding, handler selection and arbitration report public error codes. A factory
returns a daemon error code, which the selector translates. Assembly and handler
initialization report daemon error codes. The response builder translates a daemon
error code to the public code when it writes the response. Arbitration translates
the daemon error that key-affinity resolution returns, because fallback
eligibility is defined on public codes.
