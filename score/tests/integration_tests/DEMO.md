<!-- ----------------------------------------------------------------------------
  Copyright (c) 2026 Contributors to the Eclipse Foundation

  See the NOTICE file(s) distributed with this work for additional
  information regarding copyright ownership.

  This program and the accompanying materials are made available under the
  terms of the Apache License Version 2.0 which is available at
  https://www.apache.org/licenses/LICENSE-2.0

  SPDX-License-Identifier: Apache-2.0
----------------------------------------------------------------------------- -->

# Steps to run demo without bazel (integration environment)

## Prepare Environment

> Note: Ensure integration_test_config.bin was generated with the test user's UID listed in both 
> allowed_uids and the application-resource mapping. If test user's UID is neithet 0 nor 1000,
> the settings in `score/tests/test_vectors/config/integration_test_config.json` need to be adapted.

```
bazel build //score/...

mkdir -p /opt/crypto/share
mkdir -p /opt/crypto/etc
cp -r score/tests/test_vectors /opt/crypto/share && rm -r /opt/crypto/share/test_vectors/config
cp score/tests/test_vectors/config/*.kv /opt/crypto/etc
cp bazel-bin/score/tests/test_vectors/config/integration_test_config.bin /opt/crypto/etc
cp score/tests/config/logging.json /opt/crypto/etc

./bazel-bin/score/tests/integration_tests/init_pkcs11_token \
  --token-dir /tmp/softhsm_tokens \
  --config-path /tmp/softhsm2.conf \
  --token-label SoftHSM \
  --so-pin 12345678 \
  --user-pin 1234 \
  --import-key-file /opt/crypto/share/test_vectors/mac/key_aes_256.key \
  --import-key-label integration_test_hmac
```

## Start Daemon

```
export CRYPTO_CONFIG_FILE=/opt/crypto/etc/integration_test_config.bin
export SOFTHSM2_CONF=/tmp/softhsm2.conf
export MW_LOG_CONFIG_FILE=/opt/crypto/etc/logging.json

./bazel-bin/score/crypto/src/daemon/crypto_daemon
```

> `MW_LOG_CONFIG_FILE` points to the logging config in `/opt/crypto/etc/logging.json`.
> It enables verbose console logging (`kVerbose`). Omit it to fall back to the default log level (`kWarn`) — debug messages will not be shown.

## Start Demo

```
./bazel-bin/score/tests/integration_tests/score_demo
```
