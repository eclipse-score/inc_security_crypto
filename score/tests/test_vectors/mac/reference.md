# HAMC-Test Vectors

## Generation

```
# Generate expected Data (input and key expected in files: in, key)
cat in | openssl sha256 -hmac "$(cat key)" -binary -out out
```

## Re-used test vectors:

`Hi There` test vector and key taken from: https://datatracker.ietf.org/doc/html/rfc4231 (Test Case 1)

Test vectors with other data generated with above approach based on the key from the RFC Test Case 1
