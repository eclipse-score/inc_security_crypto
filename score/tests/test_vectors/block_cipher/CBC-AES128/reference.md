<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# AES-128-CBC — NIST CAVP Multi-block Message Test vectors

Source: <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/block-ciphers>
Archive: `aesmmt.zip`, file `CBCMMT128.rsp`, `[ENCRYPT]` section.

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

### vector1 — CBCMMT128.rsp [ENCRYPT] COUNT = 0

```
KEY        = 1f8e4973953f3fb0bd6b16662e9a3c17
IV         = 2fe2b333ceda8f98f4a99b40d2cd34a8
PLAINTEXT  = 45cf12964fc824ab76616ae2f4bf0822
CIPHERTEXT = 0f61c4d44c5147c03c195ad7e2cc12b2
```
### vector2 — CBCMMT128.rsp [ENCRYPT] COUNT = 3

```
KEY        = b7f3c9576e12dd0db63e8f8fac2b9a39
IV         = c80f095d8bb1a060699f7c19974a1aa0
PLAINTEXT  = 9ac19954ce1319b354d3220460f71c1e373f1cd336240881160cfde46ebfed2e791e8d5a1a136ebd1dc469dec00c4187722b841cdabcb22c1be8a14657da200e
CIPHERTEXT = 19b9609772c63f338608bf6eb52ca10be65097f89c1e0905c42401fd47791ae2c5440b2d473116ca78bd9ff2fb6015cfd316524eae7dcb95ae738ebeae84a467
```
