<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# ECDSA P384 / SHA512 — RFC 6979 Appendix A.2.6 vectors

The NIST FIPS 186-4 CAVP archive has no `[P-384,SHA-512]` section, so instead of
generating an ephemeral key pair these vectors come from the published,
deterministic test vectors of RFC 6979, Appendix A.2.6
(`ECDSA, 384 Bits (Prime Field)`), taking the `SHA-512` entries.

Source: <https://www.rfc-editor.org/info/rfc6979/#appendix-A.2.6>

Because RFC 6979 fixes the per-message secret `k`, the `(r, s)` below are genuine
known-answer values for NIST P-384, not freshly signed ones. Re-run
`generate.py` in this directory to reproduce the `*.der` and `*.bin` files byte
for byte.

## Key pair (RFC 6979 A.2.6)

```
curve: NIST P-384
x  = 6b9d3dad2e1b8c1c05b19875b6659f4de23c3b667bf297ba9aa47740787137d896d5724e4c70a825f872c9ea60d2edf5
Ux = ec3a4e415b4e19a4568618029f427fa5da9a8bc4ae92e02e06aae5286b300c64def8f0ea9055866064a254515480bc13
Uy = 8015d9b72d7d57244ea8ef9ac0c621896708a59367f9dfb9f54ca84b3f1c9db1288b231c3ae0d4fe7344fd2533264720
```

`siggen_private_key.der` is the PKCS#8 DER encoding of `x`, and
`siggen_public_key.der` the SubjectPublicKeyInfo of `(Ux, Uy)`.

## Positive case — `siggen_*` (SHA-512, message = "sample")

`siggen_message.bin` is the ASCII string `sample`, and `siggen_signature.bin`
the vector's `(r, s)` in the fixed-length IEEE P1363 form `r||s` (48 + 48 = 96
bytes) that this stack uses on the wire.

```
r = ed0959d5880ab2d869ae7f6c2915c6d60f96507f9cb3e047c0046861da4a799cfe30f35cc900056d7c99cd7882433709
s = 512c8cceee3890a84058ce1e22dbc2198f42323ce8aca9135329f03c068e5112dc7cc3ef3446defceb01a45c2667fdd5
```

The signature is a published known answer: it must verify under the published
key. ECDSA signatures this stack produces are randomised and will differ, but
must verify too.

## Negative case — `sigver_invalid_*` (SHA-512, message = "test")

The negative record reuses the same published key — there is no second key to
generate — so `sigver_invalid_public_key.der` is the same SubjectPublicKeyInfo
blob as `siggen_public_key.der`. `sigver_invalid_message.bin` is the ASCII string
`test`, whose RFC 6979 A.2.6 SHA-512 signature is:

```
r = a0d5d090c9980faf3c2ce57b7ae951d31977dd11c775d314af55f76c676447d06fb6495cd21b4b6e340fc236584fb277
s = 976984e59b4c77b0e8e4460dca3d9f20e07b9bb1f63beefaf576f6b2e8b224634a2092cd3792e0159ad9cee37659c736
```

`sigver_invalid_signature.bin` is that `r||s` with the low bit of `r` flipped, so
it is a well-formed value that must fail verification — the same role the NIST
`Result = F` records play in the other directories.
