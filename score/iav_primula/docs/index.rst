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

.. _iav_primula_component:

IAV Primula Component
#####################

.. note:: Document header

.. document:: IAV Primula Component
   :id: doc__iav_primula
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__cmpt_request
   :tags: iav_primula

Abstract
========

IAV Primula is a post-quantum provider integration skeleton for the S-CORE
crypto daemon. Its C++ implementation registers the Primula backend, creates
the provider and handler factories, routes SIGN and VERIFY requests, and
integrates key generation and KEM operations with key management.

A stable C-compatible interface separates the C++ provider from the Rust
library. The interface defines ML-DSA-44/65/87 and ML-KEM-512/768/1024
identifiers, opaque key handles, status values, and entry points for signatures,
key management, and KEM operations.

The current Rust entry points are placeholders that return
``IavStatusUnsupportedAlgorithm``. Therefore, the implementation establishes
the provider architecture and API boundary but does not yet generate keys,
signatures, ciphertexts, or shared secrets.


Rationale
=========

The implementation separates crypto-daemon integration from the future PQC
backend. Provider registration, routing, key ownership, error translation, and
the C ABI can therefore be reviewed and tested before cryptographic processing
is connected. Returning an explicit unsupported status prevents placeholder
operations from being mistaken for successful cryptographic results.

.. note::
   The rationale should provide evidence of consensus within the community and discuss important objections or concerns raised during discussion.
   For the documentation of the decision the :need:`gd_temp__change_decision_record` can be used.

Specification
=============

The component currently provides:

- backend registration as implementation ``primula``, name ``PRIMULA``, and
  provider type ``SPECIALIZED``;
- provider and handler factories for PQC request routing;
- SIGN and VERIFY handlers for ML-DSA algorithms;
- key-generation and KEM routing through key management; and
- the C-compatible interface declared in ``iav_primula_ffi.h``.

The detailed requirements, architecture, design, manual, and safety analysis
are documented in the linked sub-documents.


Backwards Compatibility
=======================

No backwards compatibility impact is expected at this stage. The component is
new and currently has no consumers with compatibility constraints.


Security Impact
===============

The component is security-relevant because it defines PQC operation routing,
key-handle ownership, and a C/Rust FFI boundary. The current placeholder does
not produce cryptographic output, but callers must reject every non-success
status and must not use output buffers after a failed operation. Pointer,
length, algorithm, and ownership validation remain security concerns at the
integration boundary.

.. note::
   If there are security concerns in relation to the CR, those concerns should be explicitly written out to make sure reviewers of the CR are aware of them.

Which security requirements are affected or has to be changed?
Could the new/modified component enable new threat scenarios?
Could the new/modified component enable new attack paths?
Could the new/modified component impact functional safety?
If applicable, which additional security measures must be implemented to mitigate the risk?

.. note::
   Use Security Software Critically Analysis, Vulnerability Analysis.
   [Methods will be defined later in Process area Security Analysis]


Safety Impact
=============

No safety requirements are allocated to the current ``QM`` component, and it
does not implement safety mechanisms. The DFA and FMEA nevertheless record
shared integration dependencies and applicable failure modes. Reassessment is
required when functional cryptographic processing is connected.

.. note::
   If there are safety concerns in relation to the CR, those concerns should be explicitly written out to make sure reviewers of the CR are aware of them.

Which safety requirements are affected or has to be changed?
Could the new/modified component be a potential common cause or cascading failure initiator?
If applicable, which additional safety measures must be implemented to mitigate the risk?

.. note::
   Use Dependency Failure Analysis and/or Safety Software Critically Analysis.
   [Methods will be defined later in Process area Safety Analysis]

For new feature/component contributions:

- Expected ASIL level: ``QM``
- Expected classification of the contribution: preliminary ``Q``

.. note::
   Use the component classification method here to classify your component, if it shall to be used in a safety context: :need:`gd_temp__component_classification`.

License Impact
==============

No additional license impact is currently expected. Implementation is original
project code under Apache-2.0.


How to Teach This
=================

Use the integration manual to explain provider registration, algorithm routing,
the C-compatible interface, and the expected unsupported result from the
placeholder backend. The component must not be presented as a functional PQC
implementation.

.. note::
   For a CR that adds new functionality or changes behaviour, it is helpful to include a section on how to teach users, new and experienced, how to apply the CR to their work.

Rejected Ideas
==============

No alternatives were evaluated yet due to the intentionally small first scope.

.. note::
   Throughout the discussion of a CR, various ideas will be proposed which are not accepted.
   Those rejected ideas should be recorded along with the reasoning as to why they were rejected.
   This both helps record the thought process behind the final version of the CR as well as preventing people from bringing up the same rejected idea again in subsequent discussions.
   In a way this section can be thought of as a breakout section of the Rationale section that is focused specifically on why certain ideas were not ultimately pursued.



Open Issues
===========

- Connect an approved PQC backend and replace the unsupported FFI placeholders.
- Define how public API clients select the ``SPECIALIZED`` Primula provider.
- Add cryptographic conformance and failure-path tests when processing is
  implemented.
- Re-evaluate the security and safety analyses when functional cryptographic
  behavior is introduced.

.. note::
   While a CR is in draft, ideas can come up which warrant further discussion.
   Those ideas should be recorded so people know that they are being thought about but do not have a concrete resolution.
   This helps make sure all issues required for the CR to be ready for consideration are complete and reduces people duplicating prior discussion.



Footnotes
=========

None.


Further Documentation of the component can be found in the following sections:

Component Detail Information
============================

.. toctree::
   :maxdepth: 1

   architecture/index
   detailed_design/index
   manuals/index
   requirements/index
   safety_analysis/dfa
   safety_analysis/fmea
   safety_analysis/aou_requirements_template
   component_classification
