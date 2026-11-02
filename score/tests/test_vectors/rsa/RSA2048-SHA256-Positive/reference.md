<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# RSA-PSS RSA-2048 / SHA-256 — NIST FIPS 186-4 CAVS vector

Source: <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures>
Archive: `186-3rsatestvectors.zip`.

## Positive case — `../SigVerPSS_186-3.rsp`, section `[mod = 2048]`, SHA-256, `Result = P`

The original response file is retained in the parent `rsa` directory. The
selected record supplies `n`, `e`, `Msg`, and `S`:

```
SHAAlg = SHA256
e       = ...0010e43f
Msg     = e002377affb04f0fe4598de9d92d31d6c786040d5776976556a2cfc55e54a1dcb3cb1b126bd6a4bed2a184990ccea773fcc79d246553e6c64f686d21ad4152673cafec22aeb40f6a084e8a5b4991f4c64cf8a927effd0fd775e71e8329e41fdd4457b3911173187b4f09a817d79ea2397fc12dfe3d9c9a0290c8ead31b6690a6
S       = 4f9b425c2058460e4ab2f5c96384da2327fd29150f01955a76b4efe956af06dc08779a374ee4607eab61a93adc5608f4ec36e47f2a0f754e8ff839a8a19b1db1e884ea4cf348cd455069eb87afd53645b44e28a0a56808f5031da5ba9112768dfbfca44ebe63a0c0572b731d66122fb71609be1480faa4e4f75e43955159d70f081e2a32fbb19a48b9f162cf6b2fb445d2d6994bc58910a26b5943477803cdaaa1bd74b0da0a5d053d8b1dc593091db5388383c26079f344e2aea600d0e324164b450f7b9b465111b7265f3b1b063089ae7e2623fc0fda8052cf4bf3379102fbf71d7c98e8258664ceed637d20f95ff0111881e650ce61f251d9c3a629ef222d
SaltVal = d66f72f10b69001a5b59cf1092ad274d5056c4e95ccccfbe3b530dcb027e57d6
Result  = P
```

`message.bin` and `signature.bin` are the hexadecimal `Msg` and `S` values
decoded to raw bytes. `public_key.der` is the DER SubjectPublicKeyInfo built
from the record's `n` and `e` values. The vector is used for verification;
RSA-PSS signing is randomized and is not expected to reproduce `S`.
