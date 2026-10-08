<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# ECDSA P256 / SHA256 — NIST FIPS 186-4 CAVP vectors

Source: <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures>
Archive: `186-4ecdsatestvectors.zip`.

## Positive case — `SigGen.txt`, section `[P-256,SHA-256]`, first record

`siggen_private_key.der` is the DER (PKCS#8) encoding of the private key `d`,
`siggen_public_key.der` the SubjectPublicKeyInfo of `(Qx, Qy)`, and
`siggen_signature.bin` the vector's `(R, S)` in the fixed-length IEEE P1363
form `r||s` (32 + 32 bytes) that this stack uses on the wire.

```
Msg = 5905238877c77421f73e43ee3da6f2d9e2ccad5fc942dcec0cbd25482935faaf416983fe165b1a045ee2bcd2e6dca3bdf46c4310a7461f9a37960ca672d3feb5473e253605fb1ddfd28065b53cb5858a8ad28175bf9bd386a5e471ea7a65c17cc934a9d791e91491eb3754d03799790fe2d308d16146d5c9b0d0debd97d79ce8
d   = 519b423d715f8b581f4fa8ee59f4771a5b44c8130b4e3eacca54a56dda72b464
Qx  = 1ccbe91c075fc7f4f033bfa248db8fccd3565de94bbfb12f3c59ff46c271bf83
Qy  = ce4014c68811f9a21a1fdb2c0e6113e06db7ca93b7404e78dc7ccd5ca89a4ca9
R   = f3ac8061b514795b8843e3d6629527ed2afd6b1f6a555a7acabb5e6f79c8c2ac
S   = 8bf77819ca05a6b2786c76262bf7371cef97b218e96f175a3ccdda2acc058903
```

ECDSA is randomised, so re-signing `siggen_message.bin` does **not** reproduce
`siggen_signature.bin` — NIST's per-message secret `k` is not settable through
this API. The vector is therefore used for *verification*: the published
signature must verify under the published key, and a signature this stack
produces must verify too.

## Negative case — `SigVer.rsp`, section `[P-256,SHA-256]`, first `Result = F` record

```
Msg    = e4796db5f785f207aa30d311693b3702821dff1168fd2e04c0836825aefd850d9aa60326d88cde1a23c7745351392ca2288d632c264f197d05cd424a30336c19fd09bb229654f0222fcb881a4b35c290a093ac159ce13409111ff0358411133c24f5b8e2090d6db6558afc36f06ca1f6ef779785adba68db27a409859fc4c4a0
Qx     = 87f8f2b218f49845f6f10eec3877136269f5c1a54736dbdf69f89940cad41555
Qy     = e15f369036f49842fac7a86c8a2b0557609776814448b8f5e84aa9f4395205e9
R      = d19ff48b324915576416097d2544f7cbdf8768b1454ad20e0baac50e211f23b0
S      = a3e81e59311cdfff2d4784949f7a2cb50ba6c3a91fa54710568e61aca3e847c6
Result = F (3 - S changed)
```

Verification of `sigver_invalid_signature.bin` under
`sigver_invalid_public_key.der` must fail. Unlike a bit-flipped signature this
is a well-formed value NIST authored to be rejected.
