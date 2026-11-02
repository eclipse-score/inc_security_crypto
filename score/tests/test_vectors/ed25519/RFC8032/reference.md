<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# Ed25519 — RFC 8032 test vector

Source: <https://www.rfc-editor.org/rfc/rfc8032>.
Reference vector data: <https://ed25519.cr.yp.to/python/sign.input>.

## Ed25519 signing vector

The vector uses record 100 from the reference implementation's `sign.input`
file. Its message is 99 bytes long, and its deterministic Ed25519 signature is
retained as a known-answer value for traceability.

## Source record

The source record is line 100 of `sign.input` and is colon-separated. The fields
are recorded below exactly as supplied by the source:

### Field 1 — secret key and public key

```text
f215d34fe2d757cff9cf5c05430994de587987ce45cb0459f61ec6c825c622591ed506485b09a6450be7c9337d9fe87ef99c96f8bd11cd631ca160d0fd73067e
```

This field contains 64 bytes: the 32-byte Ed25519 private seed followed by the
32-byte public key. The private seed is:

```text
f215d34fe2d757cff9cf5c05430994de587987ce45cb0459f61ec6c825c62259
```

### Field 2 — public key

```text
1ed506485b09a6450be7c9337d9fe87ef99c96f8bd11cd631ca160d0fd73067e
```

### Field 3 — message

```text
fbed2a7df418ec0e8036312ec239fcee6ef97dc8c2df1f2e14adee287808b788a6072143b851d975c8e8a0299df846b19113e38cee83da71ea8e9bd6f57bdcd3557523f4feb616caa595aea01eb0b3d490b99b525ea4fbb9258bc7fbb0deea8f568cb2
```

This is 99 bytes, represented as hexadecimal.

### Field 4 — signature record

The source field is:

```text
cbef65b6f3fd580969fc3340cfae4f7c99df1340cce54626183144ef468871634b0a5c0033534108e1c67c0dc99d3014f01084e98c95e1014b309b1dbb2e6704fbed2a7df418ec0e8036312ec239fcee6ef97dc8c2df1f2e14adee287808b788a6072143b851d975c8e8a0299df846b19113e38cee83da71ea8e9bd6f57bdcd3557523f4feb616caa595aea01eb0b3d490b99b525ea4fbb9258bc7fbb0deea8f568cb2
```

The first 64 bytes are the Ed25519 signature stored in `signature.bin`:

```text
cbef65b6f3fd580969fc3340cfae4f7c99df1340cce54626183144ef468871634b0a5c0033534108e1c67c0dc99d3014f01084e98c95e1014b309b1dbb2e6704
```

The source field contains the 64-byte signature followed by the message. The
final 99 bytes are not part of the Ed25519 signature.

The packaged files are:

- `private_key.der` — Ed25519 private key.
- `public_key.der` — corresponding Ed25519 public key.
- `message.bin` — 99-byte message input.
- `signature.bin` — expected Ed25519 signature.

The integration tests use the provisioned key and vector message for signing
and verification. They also verify that prehashed operation is rejected for
Ed25519, which requires the original message rather than a digest.
