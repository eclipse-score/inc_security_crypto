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
Data Manager
============

Overview
--------

The Data Manager component provides a centralized store for managing "data
nodes" used by the crypto daemon. A data node can hold any data needed across multiple requests
such as the state associated with an ongoing cryptographic operation (e.g. a hash context
or cipher session). The components in the daemon's request processing chain insert and
access these nodes through the Data Manager. The Data Manager is responsible for storing,
lookup, lifecycle management, and safe concurrent access to those nodes.

Responsibilities
----------------

- Provide a single registry for data nodes, indexed by both ClientId and DataNodeId.
- Control lifetime and ownership semantics for nodes.
- Ensure thread-safe access to nodes across the daemon using mutex-based synchronization
  for all public operations.
- Offer efficient O(1) lookup while preventing resource leaks through proper RAII patterns.
- Manage hierarchical parent-child relationships between nodes and ensure cascading
  cleanup when a parent is deleted.
- Enforce exclusive access semantics for nodes marked with ``exclusiveAccess=true`` via
  a busy-node tracking mechanism.

Design Decisions
----------------

.. dec_rec:: Central Data Node Manager
   :id: dec_rec__crypto__central_data_node_manager
   :status: accepted
   :context: doc__crypto_architecture
   :decision: Extract state information into a central Data Manager component.

   .. :affects: comp__crypto

State information for ongoing daemon operations is stored in a dedicated, central
Data Manager component rather than being managed locally by individual handlers in the
request processing chain.

Context
*******

The crypto daemon needs to maintain state for ongoing operations (e.g. hash
contexts, cipher sessions). Clients reference this state via opaque DataNodeId values passed
through IPC, and different handlers in the request processing chain need to look up the
associated state by ID. Without a centralized facility, each handler would need to
independently manage node storage, lifecycle, and concurrency, which may result in duplicated logic,
inconsistent cleanup, and race conditions.

Consequences
************

**Positive:**

* Single point of responsibility for node creation, lookup, and deletion, avoiding
  duplicated state-management logic across daemon components.
* Consistent lifecycle management through RAII patterns and
  hierarchical parent-child relationships with cascading cleanup.
* Thread-safe access enforced uniformly via mutex-based synchronization within the
  Data Manager, rather than each consumer implementing its own locking.
* Efficient O(1) node lookup through a two-level index (ClientId → DataNodeId → node).
* Exclusive-access semantics via a busy-node tracking mechanism and the DataNodeAccessor
  RAII guard, preventing concurrent mutation of in-use nodes.
* Clean separation of concerns: handlers interact through the IDataManager interface
  and DataNodeAccessor without knowing storage or concurrency internals.
* Hierarchical cleanup ensures that when a node is removed, all of its
  children (e.g. crypto operation contexts) are automatically cleaned up, preventing
  orphaned resources.
* Decouples state from thread affinity: since all node state is held centrally, any
  worker thread can pick up a task and retrieve the associated state from the Data
  Manager, making it straightforward to distribute or reassign work across threads.

**Negative:**

* The central Data Manager introduces a single mutex that serializes all node operations,
  which may become a bottleneck under high contention.
* All handlers in the request processing chain become dependent on the Data Manager
  interface, increasing coupling to this central component.

.. note::
   In case the mutex contention becomes a bottleneck, potential improvements could be analyzed
   such as splitting the mutex per ClientId to allow more concurrent access
   while still maintaining thread safety.

Alternatives Considered
***********************

Distributed State Management per Component
"""""""""""""""""""""""""""""""""""""""""""

Each handler in the request processing chain manages its own set of data nodes
independently using local data structures and per-handler synchronization.

Advantages
""""""""""

* No single contention point — each component locks only its own state, allowing
  independent scalability.
* Components remain self-contained with no shared dependency on a central manager.

Disadvantages
"""""""""""""

* Duplicated storage and lifecycle logic across multiple handlers, increasing
  maintenance burden and risk of inconsistencies.
* No centralized hierarchical cleanup — each handler must independently track
  parent-child relationships and handle cascading removal.
* Risk of inconsistent cleanup semantics across handlers may lead to resource leaks.
* Harder to enforce uniform concurrency guarantees and exclusive-access semantics.
* State is tied to the handler that created it, making it harder to redistribute
  work across threads.

Justification for the Decision
******************************

The crypto daemon's data nodes need to be accessed by different handlers in the request
processing chain, each looking up state by ID. Centralizing this state in a single Data
Manager eliminates duplicated storage and lifecycle logic, provides uniform thread safety
through a single synchronization strategy, and enables consistent hierarchical lifecycle
management with cascading cleanup. The serialization cost of a single mutex is acceptable
given the expected operation frequency, and the simplicity it provides outweighs the
theoretical contention risk.
