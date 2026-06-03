# Steps to run demo without bazel (integration environment)

## Prepare Environment

```
bazel build //score/... //tests/...

mkdir -p /opt/crypto/tests/test_vectors/config
mkdir -p /opt/crypto/deploy
cp -r ./tests/test_vectors /opt/crypto/tests/
cp -r bazel-bin/tests/test_vectors /opt/crypto/tests/
cp -r tests/test_vectors/config/*.kv /opt/crypto/deploy

./bazel-bin/tests/integration_tests/init_softhsm_token \
  --token-dir /tmp/softhsm_tokens \
  --config-path /tmp/softhsm2.conf \
  --token-label SoftHSM \
  --so-pin 12345678 \
  --user-pin 1234 \
  --import-key-file /opt/crypto/tests/test_vectors/mac/key_aes_256.key \
  --import-key-label integration_test_hmac
```

## Start Daemon

```
export CRYPTO_CONFIG_FILE=/opt/crypto/tests/test_vectors/config/integration_test_config.bin
export SOFTHSM2_CONF=/tmp/softhsm2.conf
export MW_LOG_CONFIG_FILE=tests/config/logging.json

./bazel-bin/score/crypto/daemon/crypto_daemon
```

> `MW_LOG_CONFIG_FILE` points to the logging config in `tests/config/logging.json`.
> It enables verbose console logging (`kVerbose`). Omit it to fall back to the default log level (`kWarn`) — debug messages will not be shown.

## Start Demo

```
./bazel-bin/tests/integration_tests/score_demo
```
