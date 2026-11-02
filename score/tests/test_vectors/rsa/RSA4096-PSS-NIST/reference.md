<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# RSA-PSS RSA-4096 — NIST CAVS vector

Source: <https://csrc.nist.gov/projects/cryptographic-algorithm-validation-program/digital-signatures>.
Archive: `186-2rsatestvectors.zip`.

## RSA-4096 key material — `KeyGenRSA.rsp`, section `[mod = 4096]`

The RSA-4096 private key was generated from the NIST CAVS RSA key-generation
vector. The selected record uses public exponent `3` and is stored as DER
key material for the OpenSSL provider.

The source response file is retained under
`../186-2rsatestvectors/KeyGenRSA.rsp`. The packaged files are:

- `private_key.der` — RSA-4096 private key used by the integration signing tests.
- `public_key.der` — corresponding RSA public key.

The integration tests use this provisioned key with RSA-PSS and exercise
SHA-256, SHA-384, and SHA-512 signing and verification, including streaming
verification. Generated signatures are not compared byte-for-byte because
RSA-PSS signatures use randomized salt.
