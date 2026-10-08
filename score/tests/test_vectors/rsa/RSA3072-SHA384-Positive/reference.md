<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# RSA-PSS RSA-3072 / SHA-384 — NIST FIPS 186-4 CAVS vector

Source: <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures>
Archive: `186-3rsatestvectors.zip`.

## Positive case — `../SigGenPSS_186-3.rsp`, section `[mod = 3072]`, SHA-384

The original response file is retained in the parent `rsa` directory. The
selected signing record is used as a verification known-answer vector:

```
SHAAlg = SHA384
Msg     = a454391a7c3695486c337a41c2add417d8e9e9c6466d2ebb56ad5f97b9e7ce30784cfcd82d6066e372a3a1639a71a9369f2777435c87d100fc5e6638b3631a0bac639f36429b4594726613e5901816cf3a29f9228b96d66090844c7d0026d2e327e24ab924afda6554c2f74f0e69c2e8913798ec3a61e4e4fb6838ee08f89dc0
S       = 261180717edd905b647bc869f5259203811606221f545a3aee5fc123f297cf7d8a7ee6cee3dc8f97d24284ccdec2fd4680f1428ee75797e0379512aecb9fc1667523413e323c4bd7dded5caf9e5c606e5ee0c694d4d1b5a1f1cb613b980129f64146e42e8261c1f7ef5603954d34d56a50f7431beee5ab291a4759168655a5123640d596b744d97979d39f874ea7ff13a7466a7655d02edb492b58049f2208852297eb023e657f3240c5da9a99fd377728bff3cc073109c31712d94bc24e08c433533d4b86a73b58fbf2c598ccad78d46ca0a055601850960195aac1364dfaddbd06f14a78aac2ab4d374505cc61fc72c1050647d95a733517b709aed2d896721e7484208501480058fa4f6044302dd705c273fa7fb42eaeb02d025092b252e16d270d88dab6f68fd7ad571011f89627683e029d1bf1edc149d47452ebe87ec68679579940f5aec25999b0dedb820a5483ec6901abfee041c03b1a7f743548a2caabca613ff5d9f8fd7c694af12b29f2c2468eff55f9e008757443960fae459e
```

`message.bin` and `signature.bin` are the hexadecimal `Msg` and `S` values
decoded to raw bytes. `public_key.der` is the DER SubjectPublicKeyInfo built
from the record's `n` and `e` values. The implementation uses
`RSA_PSS_SALTLEN_DIGEST`, which is 48 bytes for SHA-384.
