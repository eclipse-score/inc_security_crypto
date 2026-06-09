#!/bin/bash
WS_DIR="/home/oeweda/essam/security/pkcs11_workspace/inc_security_crypto_valeo_pitch"
export CRYPTO_CONFIG_FILE="$WS_DIR/bazel-bin/tests/test_vectors/config/integration_test_config.bin"

echo "Cleaning up old token..."
rm -rf ~/.cryptoki

echo "Initializing token and importing key..."
bazel run --config=host_config_1 --define use_rust_pkcs11=true //tests/integration_tests:init_softhsm_token -- \
  --token-dir /tmp/foo \
  --config-path /tmp/foo/conf \
  --token-label ValeoCryptokiToken \
  --so-pin so-pin \
  --user-pin 1234 \
  --import-key-file "$WS_DIR/tests/test_vectors/mac/key_aes_256.key" \
  --import-key-label integration_test_hmac \
  --import-key-type generic
  
echo "Starting Crypto Daemon..."
bazel run --config=host_config_1 --define use_rust_pkcs11=true //score/crypto/daemon:crypto_daemon &
DAEMON_PID=$!

echo "Waiting for daemon to initialize..."
sleep 5

echo "Running client..."
export USE_RUST_PKCS11=1
bazel run --config=host_config_1 --define use_rust_pkcs11=true //tests/integration_tests:valeo_pkcs11_demo_client

echo "Killing Daemon..."
kill -9 $DAEMON_PID
