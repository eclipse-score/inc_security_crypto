<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# ECDSA P384 / SHA384 — NIST FIPS 186-4 CAVP vectors

Source: <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures>
Archive: `186-4ecdsatestvectors.zip`.

## Positive case — `SigGen.txt`, section `[P-384,SHA-384]`, first record

`siggen_private_key.der` is the DER (PKCS#8) encoding of the private key `d`,
`siggen_public_key.der` the SubjectPublicKeyInfo of `(Qx, Qy)`, and
`siggen_signature.bin` the vector's `(R, S)` in the fixed-length IEEE P1363
form `r||s` (48 + 48 bytes) that this stack uses on the wire.

```
Msg = 6b45d88037392e1371d9fd1cd174e9c1838d11c3d6133dc17e65fa0c485dcca9f52d41b60161246039e42ec784d49400bffdb51459f5de654091301a09378f93464d52118b48d44b30d781eb1dbed09da11fb4c818dbd442d161aba4b9edc79f05e4b7e401651395b53bd8b5bd3f2aaa6a00877fa9b45cadb8e648550b4c6cbe
d   = 201b432d8df14324182d6261db3e4b3f46a8284482d52e370da41e6cbdf45ec2952f5db7ccbce3bc29449f4fb080ac97
Qx  = c2b47944fb5de342d03285880177ca5f7d0f2fcad7678cce4229d6e1932fcac11bfc3c3e97d942a3c56bf34123013dbf
Qy  = 37257906a8223866eda0743c519616a76a758ae58aee81c5fd35fbf3a855b7754a36d4a0672df95d6c44a81cf7620c2d
R   = 50835a9251bad008106177ef004b091a1e4235cd0da84fff54542b0ed755c1d6f251609d14ecf18f9e1ddfe69b946e32
S   = 0475f3d30c6463b646e8d3bf2455830314611cbde404be518b14464fdb195fdcc92eb222e61f426a4a592c00a6a89721
```

ECDSA is randomised, so re-signing `siggen_message.bin` does **not** reproduce
`siggen_signature.bin` — NIST's per-message secret `k` is not settable through
this API. The vector is therefore used for *verification*: the published
signature must verify under the published key, and a signature this stack
produces must verify too.

## Negative case — `SigVer.rsp`, section `[P-384,SHA-384]`, first `Result = F` record

```
Msg    = 4132833a525aecc8a1a6dea9f4075f44feefce810c4668423b38580417f7bdca5b21061a45eaa3cbe2a7035ed189523af8002d65c2899e65735e4d93a16503c145059f365c32b3acc6270e29a09131299181c98b3c76769a18faf21f6b4a8f271e6bf908e238afe8002e27c63417bda758f846e1e3b8e62d7f05ebd98f1f9154
Qx     = 1f94eb6f439a3806f8054dd79124847d138d14d4f52bac93b042f2ee3cdb7dc9e09925c2a5fee70d4ce08c61e3b19160
Qy     = 1c4fd111f6e33303069421deb31e873126be35eeb436fe2034856a3ed1e897f26c846ee3233cd16240989a7990c19d8c
R      = 3c15c3cedf2a6fbff2f906e661f5932f2542f0ce68e2a8182e5ed3858f33bd3c5666f17ac39e52cb004b80a0d4ba73cd
S      = 9de879083cbb0a97973c94f1963d84f581e4c6541b7d000f9850deb25154b23a37dd72267bdd72665cc7027f88164fab
Result = F (2 - R changed)
```

Verification of `sigver_invalid_signature.bin` under
`sigver_invalid_public_key.der` must fail. Unlike a bit-flipped signature this
is a well-formed value NIST authored to be rejected.
