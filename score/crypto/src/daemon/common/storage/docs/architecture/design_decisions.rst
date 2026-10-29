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

Common Storage Design Decisions
===============================

Atomic File Writes via Temporary File and Rename
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. dec_rec:: Atomic File Writes via Temporary File and Rename
   :id: dec_rec__crypto_common_storage__atomic_writes
   :version: 1
   :status: accepted
   :context: doc__crypto_common_storage_architecture
   :decision: Whole-file replacements use one shared storage primitive. It writes the complete new content to a temporary file beside the target and then replaces the target, so a reader sees either the previous complete file or the new one. The replacement is atomic but not durable across power loss: the new content may be lost and the previous content kept.
   :affects: comp__crypto_common_storage

The contract applies to every write made through the shared primitive. Other
persistence backends define their own write behavior.

Context
-------

The daemon may be terminated while writing a certificate payload or deployment
descriptor. An in-place write can leave truncated content at the target and
discard the previous valid file. The shared storage component needs one
replacement primitive that its consumers can use consistently. Three strategies
were evaluated:

1. **Direct writes** - open the target file and write in place. Simple, but an
   interruption mid-write can leave truncated or partially overwritten content.

2. **Write-ahead log (WAL)** - record the intent before writing, then apply and
   mark it complete. This provides recovery but requires a WAL reader at startup
   and adds journal management for individual file updates.

3. **Temporary file and atomic replacement** - write the complete new content
   to a sibling temporary file, then replace the target atomically. The old
   content remains until the replacement succeeds, and readers do not observe
   an in-place partial write.

Decision
--------

Temporary-file replacement (option 3) is the replacement strategy for whole-file
writes. The shared primitive writes the complete new content to a sibling
temporary file and then replaces the target. The file content is synced before
the rename. The directory entry is not synced, so a power failure can roll the
replacement back to the previous content. Callers that need the new content to
survive power loss cannot rely on this primitive alone.

Consequences
------------

**Positive:**

* The previous target remains intact until the complete replacement is ready.
* Readers see the previous or new complete file, never a partial write.
* One shared primitive serves every whole-file replacement, so the guarantee is
  the same everywhere it is used.

**Negative:**

* The replacement is not durable across power loss (see the decision).
* The temporary file and the target must be on the same filesystem, so the
  temporary file is created beside the target.
* Each update writes a complete new copy rather than patching in place. This
  suits small whole-file payloads, not large append-oriented data.
