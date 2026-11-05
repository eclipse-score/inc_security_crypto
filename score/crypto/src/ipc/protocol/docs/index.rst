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

Crypto IPC Control Protocol
===========================

The protocol component defines the wire-format boundary between typed crypto
control requests and serialized IPC frames. It is independent of the transport
that carries those frames.

IControlCodec
-------------

``IControlCodec`` defines serialization, deserialization, and request-metadata
inspection for control requests and responses.

FlatBufferCodec
---------------

``FlatBufferCodec`` is the current implementation of ``IControlCodec``. It
encodes and decodes the control protocol using the FlatBuffers schema.

The schema is maintained in ``control.fbs`` alongside the codec. The serialized
frame-size limit is defined in ``protocol_config.h``.

.. toctree::
   :maxdepth: 1

   architecture/index
