<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# Hash Test Vectors

## Input Files

| File | Contents | Bytes |
|------|----------|-------|
| `input_empty.bin` | Empty byte sequence | 0 |
| `input_abc.bin` | Raw ASCII `abc` (no null terminator or newline) | 3 |
| `input_hello_world.bin` | Raw ASCII `Hello, World!` (no null terminator) | 13 |
| `input_complete_data.bin` | Raw ASCII `complete_data` (no null terminator) | 13 |

## Digest Files

| File | Algorithm | Input | Expected Hex |
|------|-----------|-------|-------------|
| `sha256_empty.bin` | SHA-256 | `input_empty.bin` | `e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855` |
| `sha256_abc.bin` | SHA-256 | `input_abc.bin` | `ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad` |
| `sha256_hello_world.bin` | SHA-256 | `input_hello_world.bin` | `dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f` |
| `sha256_complete_data.bin` | SHA-256 | `input_complete_data.bin` | `5757e96ca92c35872e34c6d38e457e78a39bd78ee2d96d3050aee2a54fc2a6cf` |
| `sha384_empty.bin` | SHA-384 | `input_empty.bin` | `38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b` |
| `sha384_abc.bin` | SHA-384 | `input_abc.bin` | `cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8086072ba1e7cc2358baeca134c825a7` |
| `sha384_hello_world.bin` | SHA-384 | `input_hello_world.bin` | `5485cc9b3365b4305dfb4e8337e0a598a574f8242bf17289e0dd6c20a3cd44a089de16ab4ab308f63e44b1170eb5f515` |
| `sha384_complete_data.bin` | SHA-384 | `input_complete_data.bin` | `04efb41b79a3675f843df1e1b52e2845745129d0286abf10021d298c50fc7c3bc1e1225a8f7fa0a0477956fd3efed06e` |
| `sha512_empty.bin` | SHA-512 | `input_empty.bin` | `cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e` |
| `sha512_abc.bin` | SHA-512 | `input_abc.bin` | `ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f` |
| `sha512_hello_world.bin` | SHA-512 | `input_hello_world.bin` | `374d794a95cdcfd8b35993185fef9ba368f160d8daf432d08ba9f1ed1e5abe6cc69291e0fa2fe0006a52570ef18c19def4e617c33ce52ef0a6e5fbe318cb0387` |
| `sha512_complete_data.bin` | SHA-512 | `input_complete_data.bin` | `be92cc1d8780572b654339f1fb133eb9383d1c924c3751f0f745361318ed41a6387df1674d0c7213af592308b714197327c01cca21301f6185d287190f888ffc` |

## Conventions

- Binary files contain raw digest bytes with **no** null terminator, consistent with the
  existing ECB-AES128 block-cipher test vector convention.
- Digests were generated as binary files with `openssl dgst -sha{256,384,512} -binary`.
- The hexadecimal values were independently verified with `shasum -a 256`,
  `shasum -a 384`, and `shasum -a 512`.
