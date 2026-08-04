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

IAV Primula Detailed Design
===========================

.. document:: IAV Primula Detailed Design
   :id: doc__iav_primula_detailed_design
   :version: 1
   :status: draft
   :safety: QM
   :security: YES
   :realizes: wp__sw_implementation
   :tags: iav_primula

Detailed Design for Component: IAV Primula
==========================================

Description
-----------

The implementation is intentionally small and centralized in ``src/main.rs``.

Design constraints:

- Keep public API simple for onboarding.
- Keep deterministic output for stable first tests.
- Avoid unnecessary abstractions until additional behavior is introduced.

Current unit split:

- ``src/main.rs``: public API and implementation of ``get_hello_message()``.

Rationale Behind Decomposition into Units
******************************************
No further unit decomposition is needed at this stage.

.. note:: Reason for split into multiple units could be-
	    - Based on design principles like SOLID,DRY etc
	    - Based on design pattern's etc.

Static Diagrams for Unit Interactions
-------------------------------------

A static view provides an overview of the units and their relationships using
UML 2.0 notations (e.g. class diagrams, component diagrams). Use ``.. uml::``
or ``.. image::`` directives to include the diagram.

For this first baseline implementation no additional static UML is required.

Dynamic Diagrams for Unit Interactions (optional)
--------------------------------------------------

A dynamic view illustrates how the units within a component interact over their
interfaces to fulfill a specific use case or functionality. It is optional when the
component's behaviour is straightforward and can be understood from the static view
and interface documentation alone.

Use standard UML behavioural diagrams (sequence diagrams, state machine diagrams)
with ``.. uml::`` or ``.. image::`` directives.

For this first baseline implementation no additional dynamic UML is required.

Units within the Component
--------------------------

The relationship between a unit and its parent component is established implicitly
through the file path. Each component has its own directory, and units residing
within that directory belong to it. The unit's attributes and behaviour are documented
in the source code itself. A separate static diagram per unit is not required.

Interface documentation of a software unit is part of the source code (e.g. public
API headers, trait definitions, or documented function signatures).

Current unit list:

- ``main.rs``: returns constant hello message string.
