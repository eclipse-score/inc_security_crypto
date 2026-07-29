<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# AES-192-CBC — NIST CAVP Multi-block Message Test vectors

Source: <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers>
Archive: `aesmmt.zip`, file `CBCMMT192.rsp`, `[ENCRYPT]` section.

Each vector is four files: `*_key.bin`, `*_iv.bin`, `*_plaintext.bin` and the
expected `*_ciphertext.bin`.

## Padding

CAVP plaintexts are whole blocks and the expected ciphertext carries **no
padding**. The cipher contexts of this stack always apply PKCS#7 padding, so
encrypting `*_plaintext.bin` yields `*_ciphertext.bin` **followed by one extra
padding block**: a test compares the leading `len(plaintext)` bytes against the
vector, then decrypts the full padded ciphertext to recover the plaintext.
Feeding `*_ciphertext.bin` to a decrypt context directly would fail the padding
check, which is expected and not a defect.

### vector1 — CBCMMT192.rsp [ENCRYPT] COUNT = 0

```
KEY        = ba75f4d1d9d7cf7f551445d56cc1a8ab2a078e15e049dc2c
IV         = 531ce78176401666aa30db94ec4a30eb
PLAINTEXT  = c51fc276774dad94bcdc1d2891ec8668
CIPHERTEXT = 70dd95a14ee975e239df36ff4aee1d5d
```
### vector2 — CBCMMT192.rsp [ENCRYPT] COUNT = 3

```
KEY        = 067bb17b4df785697eaccf961f98e212cb75e6797ce935cb
IV         = 8b59c9209c529ca8391c9fc0ce033c38
PLAINTEXT  = db3785a889b4bd387754da222f0e4c2d2bfe0d79e05bc910fba941beea30f1239eacf0068f4619ec01c368e986fca6b7c58e490579d29611bd10087986eff54f
CIPHERTEXT = d5f5589760bf9c762228fde236de1fa2dd2dad448db3fa9be0c4196efd46a35c84dd1ac77d9db58c95918cb317a6430a08d2fb6a8e8b0f1c9b72c7a344dc349f
```
