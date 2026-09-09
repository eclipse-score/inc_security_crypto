<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# AES-256-CBC — NIST CAVP Multi-block Message Test vectors

Source: <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers>
Archive: `aesmmt.zip`, file `CBCMMT256.rsp`, `[ENCRYPT]` section.

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

### vector1 — CBCMMT256.rsp [ENCRYPT] COUNT = 0

```
KEY        = 6ed76d2d97c69fd1339589523931f2a6cff554b15f738f21ec72dd97a7330907
IV         = 851e8764776e6796aab722dbb644ace8
PLAINTEXT  = 6282b8c05c5c1530b97d4816ca434762
CIPHERTEXT = 6acc04142e100a65f51b97adf5172c41
```
### vector2 — CBCMMT256.rsp [ENCRYPT] COUNT = 3

```
KEY        = 0493ff637108af6a5b8e90ac1fdf035a3d4bafd1afb573be7ade9e8682e663e5
IV         = c0cd2bebccbb6c49920bd5482ac756e8
PLAINTEXT  = 8b37f9148df4bb25956be6310c73c8dc58ea9714ff49b643107b34c9bff096a94fedd6823526abc27a8e0b16616eee254ab4567dd68e8ccd4c38ac563b13639c
CIPHERTEXT = 05d5c77729421b08b737e41119fa4438d1f570cc772a4d6c3df7ffeda0384ef84288ce37fc4c4c7d1125a499b051364c389fd639bdda647daa3bdadab2eb5594
```
