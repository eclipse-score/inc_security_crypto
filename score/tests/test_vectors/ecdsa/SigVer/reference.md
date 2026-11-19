<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# ECDSA SigVer — NIST FIPS 186-4 CAVP, all catalog curve/digest pairs

`SigVer.rsp` is the `SigVer.rsp` file of the NIST CAVP archive
`186-4ecdsatestvectors.zip`, reduced to the twelve ECDSA rows of the algorithm
catalog: P-256, P-384 and P-521, each with SHA-224, SHA-256, SHA-384 and
SHA-512. NIST's file header and the records of those sections are copied
verbatim; line endings are LF.

Source: <https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Algorithm-Validation-Program/documents/dss/186-4ecdsatestvectors.zip>
(SHA-256 of the archive `fe47cc92b4cee418236125c9ffbcd9bb01c8c34e74a4ba195d954bcb72824752`).
NIST test vectors are public domain.

To reproduce the file byte for byte from the downloaded archive:

```
unzip -p 186-4ecdsatestvectors.zip 186-4ecdsatestvectors/SigVer.rsp \
  | tr -d '\r' \
  | awk 'BEGIN { k = 1 } /^\[/ { k = /^\[P-(256|384|521),SHA-(224|256|384|512)\]$/ } k' \
  | sed '$d' > SigVer.rsp
```

`awk` keeps NIST's header and the twelve sections; `sed` drops the blank line
that ends the last one.

## Content

Each section holds 15 records of `Msg`, public key `Qx`/`Qy`, signature `R`/`S`
and the expected `Result`:

| Result                     | Records per section |
| -------------------------- | ------------------- |
| `P` (valid)                | 3                   |
| `F (1 - Message changed)`  | 3                   |
| `F (2 - R changed)`        | 3                   |
| `F (3 - S changed)`        | 3                   |
| `F (4 - Q changed)`        | 3                   |

`Msg` is the message, not its digest. P-521 values are listed with 131 hex
digits and are left-padded with zero to the 66-byte field size when read.

## Use

`score_api_ecdsa_test` (`EcdsaNistSigVerTest`) imports each `Q` as a raw SEC1
point, verifies `R||S` over `Msg` in message mode and over the digest of `Msg`
in prehashed mode, and expects the verdict NIST lists. A changed `Q` that is no
longer a point on the curve is refused at import, which also counts as a
rejection.
