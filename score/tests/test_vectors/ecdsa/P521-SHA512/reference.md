<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# ECDSA P521 / SHA512 — NIST FIPS 186-4 CAVP vectors

Source: <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures>
Archive: `186-4ecdsatestvectors.zip`.

## Positive case — `SigGen.txt`, section `[P-521,SHA-512]`, first record

`siggen_private_key.der` is the DER (PKCS#8) encoding of the private key `d`,
`siggen_public_key.der` the SubjectPublicKeyInfo of `(Qx, Qy)`, and
`siggen_signature.bin` the vector's `(R, S)` in the fixed-length IEEE P1363
form `r||s` (66 + 66 bytes) that this stack uses on the wire.

```
Msg = 9ecd500c60e701404922e58ab20cc002651fdee7cbc9336adda33e4c1088fab1964ecb7904dc6856865d6c8e15041ccf2d5ac302e99d346ff2f686531d25521678d4fd3f76bbf2c893d246cb4d7693792fe18172108146853103a51f824acc621cb7311d2463c3361ea707254f2b052bc22cb8012873dcbb95bf1a5cc53ab89f
d   = 0f749d32704bc533ca82cef0acf103d8f4fba67f08d2678e515ed7db886267ffaf02fab0080dca2359b72f574ccc29a0f218c8655c0cccf9fee6c5e567aa14cb926
Qx  = 061387fd6b95914e885f912edfbb5fb274655027f216c4091ca83e19336740fd81aedfe047f51b42bdf68161121013e0d55b117a14e4303f926c8debb77a7fdaad1
Qy  = 0e7d0c75c38626e895ca21526b9f9fdf84dcecb93f2b233390550d2b1463b7ee3f58df7346435ff0434199583c97c665a97f12f706f2357da4b40288def888e59e6
R   = 04de826ea704ad10bc0f7538af8a3843f284f55c8b946af9235af5af74f2b76e099e4bc72fd79d28a380f8d4b4c919ac290d248c37983ba05aea42e2dd79fdd33e8
S   = 087488c859a96fea266ea13bf6d114c429b163be97a57559086edb64aed4a18594b46fb9efc7fd25d8b2de8f09ca0587f54bd287299f47b2ff124aac566e8ee3b43
```

ECDSA is randomised, so re-signing `siggen_message.bin` does **not** reproduce
`siggen_signature.bin` — NIST's per-message secret `k` is not settable through
this API. The vector is therefore used for *verification*: the published
signature must verify under the published key, and a signature this stack
produces must verify too.

## Negative case — `SigVer.rsp`, section `[P-521,SHA-512]`, first `Result = F` record

```
Msg    = a0732a605c785a2cc9a3ff84cbaf29175040f7a0cc35f4ea8eeff267c1f92f06f46d3b35437195185d322cbd775fd24741e86ee9236ba5b374a2ac29803554d715fa4656ac31778f103f88d68434dd2013d4c4e9848a11198b390c3d600d712893513e179cd3d31fb06c6e2a1016fb96ffd970b1489e36a556ab3b537eb29dff
Qx     = 12a593f568ca2571e543e00066ecd3a3272a57e1c94fe311e5df96afc1b792e5862720fc730e62052bbf3e118d3a078f0144fc00c9d8baaaa8298ff63981d09d911
Qy     = 17cea5ae75a74100ee03cdf2468393eef55ddabfe8fd5718e88903eb9fd241e8cbf9c68ae16f4a1db26c6352afcb1894a9812da6d32cb862021c86cd8aa483afc26
R      = 1aac7692baf3aa94a97907307010895efc1337cdd686f9ef2fd8404796a74701e55b03ceef41f3e6f50a0eeea11869c4789a3e8ab5b77324961d081e1a3377ccc91
S      = 009c1e7d93d056b5a97759458d58c49134a45071854b8a6b8272f9fe7e78e1f3d8097e8a6e731f7ab4851eb26d5aa4fdadba6296dc7af835fe3d1b6dba4b031d5f3
Result = F (2 - R changed)
```

Verification of `sigver_invalid_signature.bin` under
`sigver_invalid_public_key.der` must fail. Unlike a bit-flipped signature this
is a well-formed value NIST authored to be rejected.
