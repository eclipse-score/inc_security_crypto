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

IAV_Primula is a cryptographic driver in Rust focused on integrating
post-quantum (PQ) algorithms and establishing a future-ready foundation for
cryptographic processing in the S-CORE context. The component emphasizes a
clear, robust, and maintainable architecture that provides safe and structured
integration paths for quantum-resistant methods. At the current planning stage,
integrating classical cryptographic algorithms is not intended; the initial
scope is fully focused on PQ-based capabilities and their clean technical
embedding.

The cryptodriver is designed around a consistent job-processing model. The
offered processing jobs include, among others, Signature Generate, Signature
Verification, Key Generate, and Key Exchange. Processing is intended to follow
clearly defined interfaces and traceable request/response flows, enabling
integrators to use cryptographic operations and key-related processes in a
uniform way. Extensibility is also considered from the beginning so that
additional PQ algorithms and operations can be added in a controlled manner.

By being implemented in Rust, IAV_Primula benefits from strong memory-safety
properties and improved robustness against common implementation errors.
Overall, the component addresses the need for a modern, integration-friendly,
and post-quantum-focused cryptographic driver baseline designed for long-term
security and structured evolution.


Rationale
=========

The initial implementation is intentionally minimal. A deterministic and
side-effect-free function allows us to validate repository setup, Rust crate
integration, and first test execution with very low complexity.

.. note::
   The rationale should provide evidence of consensus within the community and discuss important objections or concerns raised during discussion.
   For the documentation of the decision the :need:`gd_temp__change_decision_record` can be used.

Specification
=============

The component currently provides a single public interface:

- ``get_hello_message() -> &'static str``

The requirement, architecture, and implementation inspection preparation are
documented in the linked sub-documents.


Backwards Compatibility
=======================

No backwards compatibility impact is expected at this stage. The component is
new and currently has no consumers with compatibility constraints.


Security Impact
===============

No relevant security impact is identified for the current scope. The API
returns a constant string and performs no external interaction.

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

No safety impact is identified for the current scope. The component is
classified as ``QM`` and currently does not implement safety mechanisms.

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

Use the component as a simple Rust library baseline and reference the test
``returns_expected_message`` as a minimal example for unit/integration flow.

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

- Extend API beyond baseline hello message.
- Decide whether detailed design document remains needed after growth.
- Confirm if safety analysis artifacts are required once safety-relevant
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
   requirements/index
   safety_analysis/dfa
   safety_analysis/fmea
   safety_analysis/aou_requirements_template
   component_classification
