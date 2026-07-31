# Hash Test Vectors

## Input Files

| File | Contents | Bytes |
|------|----------|-------|
| `input_hello_world.bin` | Raw ASCII `Hello, World!` (no null terminator) | 13 |
| `input_complete_data.bin` | Raw ASCII `complete_data` (no null terminator) | 13 |

## Digest Files

| File | Algorithm | Input | Expected Hex |
|------|-----------|-------|-------------|
| `sha256_hello_world.bin` | SHA-256 | `input_hello_world.bin` | `dffd6021bb2bd5b0af676290809ec3a53191dd81c7f70a4b28688a362182986f` |
| `sha384_hello_world.bin` | SHA-384 | `input_hello_world.bin` | `5485cc9b3365b4305dfb4e8337e0a598a574f8242bf17289e0dd6c20a3cd44a089de16ab4ab308f63e44b1170eb5f515` |
| `sha256_complete_data.bin` | SHA-256 | `input_complete_data.bin` | `5757e96ca92c35872e34c6d38e457e78a39bd78ee2d96d3050aee2a54fc2a6cf` |

## Conventions

- Binary files contain raw digest bytes with **no** null terminator, consistent with the
  existing ECB-AES128 block-cipher test vector convention.
- Digests were generated with Python `hashlib` and verified against OpenSSL CLI.
