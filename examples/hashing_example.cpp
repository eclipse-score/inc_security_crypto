/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

/// @file hashing_example.cpp
/// @brief Demonstrates SHA-256 hashing using the score::mw::crypto API.
///
/// Shows both streaming (Init → Update* → Finalize) and single-shot modes.

#include "score/mw/crypto/api/config/hash_context_config.hpp"
#include "score/mw/crypto/api/contexts/i_hash_context.hpp"
#include "score/mw/crypto/api/crypto_stack_factory.hpp"
#include "score/mw/crypto/api/i_crypto_context.hpp"
#include "score/mw/crypto/api/i_crypto_stack.hpp"

#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>

using namespace score::mw::crypto;

namespace
{

void PrintHex(const char* label, const uint8_t* data, std::size_t len)
{
    std::printf("%s: ", label);
    for (std::size_t i = 0; i < len; ++i)
    {
        std::printf("%02x", data[i]);
    }
    std::printf("\n");
}

}  // namespace

int main()
{
    // 1. Create the crypto stack and connect to the daemon
    CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint("unix:///var/run/crypto-daemon.sock");

    auto stack_result = CreateCryptoStack(stack_config);
    if (!stack_result.has_value())
    {
        std::cout << "Error: Failed to create crypto stack" << std::endl;
        return 1;
    }
    auto stack = std::move(stack_result).value();

    // 2. Create a crypto context (session)
    auto ctx_result = stack->CreateCryptoContext();
    if (!ctx_result.has_value())
    {
        std::cout << "Error: Failed to create crypto context" << std::endl;
        return 1;
    }
    auto ctx = std::move(ctx_result).value();

    // 3. Configure and create a SHA-256 hash context
    HashContextConfig hash_config;
    hash_config.SetAlgorithm("SHA-256");

    auto hash_result = ctx->CreateHashContext(hash_config);
    if (!hash_result.has_value())
    {
        std::cout << "Error: Failed to create hash context" << std::endl;
        return 1;
    }
    auto hash = std::move(hash_result).value();

    // 4. Streaming hash: Init → Update → Update → Finalize
    constexpr std::size_t kSha256DigestSize = 32;
    std::array<uint8_t, kSha256DigestSize> digest{};

    const char* chunk1 = "Hello, ";
    const char* chunk2 = "World!";

    auto init_result = hash->Init();
    if (!init_result.has_value())
    {
        std::cout << "Error: Init failed" << std::endl;
        return 1;
    }

    hash->Update({reinterpret_cast<const uint8_t*>(chunk1), std::strlen(chunk1)});
    hash->Update({reinterpret_cast<const uint8_t*>(chunk2), std::strlen(chunk2)});

    auto finalize_result = hash->Finalize({digest.data(), digest.size()});
    if (!finalize_result.has_value())
    {
        std::cout << "Error: Finalize failed" << std::endl;
        return 1;
    }

    PrintHex("Streaming SHA-256", digest.data(), finalize_result.value());

    // 5. Single-shot hash (equivalent to Init + Update + Finalize)
    const char* message = "Hello, World!";
    std::array<uint8_t, kSha256DigestSize> digest2{};

    auto single_result = hash->SingleShot({reinterpret_cast<const uint8_t*>(message), std::strlen(message)},
                                          {digest2.data(), digest2.size()});

    if (!single_result.has_value())
    {
        std::cout << "Error: SingleShot failed" << std::endl;
        return 1;
    }

    PrintHex("SingleShot SHA-256", digest2.data(), single_result.value());

    // 6. Verify both produce the same digest
    if (digest == digest2)
    {
        std::cout << "OK: Streaming and single-shot digests match" << std::endl;
    }

    // 7. Context reuse via Reset()
    //    Reset() returns the context to its post-construction state — the key
    //    (none for hash) and algorithm binding are preserved but the streaming
    //    state machine and intermediate data are cleared.  This avoids the
    //    factory + IPC cost of creating a new context, which matters for
    //    high-throughput scenarios (per-frame V2X AEAD, bulk log hashing).
    auto reset_result = hash->Reset();
    if (!reset_result.has_value())
    {
        std::cout << "Error: Reset failed" << std::endl;
        return 1;
    }

    // Hash a different message using the same context
    const char* second_msg = "Context reuse is efficient!";
    std::array<uint8_t, kSha256DigestSize> digest3{};

    hash->Init();
    hash->Update({reinterpret_cast<const uint8_t*>(second_msg), std::strlen(second_msg)});
    auto finalize3 = hash->Finalize({digest3.data(), digest3.size()});
    if (!finalize3.has_value())
    {
        std::cout << "Error: Finalize after Reset failed" << std::endl;
        return 1;
    }
    PrintHex("Reused-ctx SHA-256", digest3.data(), finalize3.value());

    // Reset() also works mid-stream to abort and restart
    hash->Init();
    hash->Update({reinterpret_cast<const uint8_t*>(chunk1), std::strlen(chunk1)});
    hash->Reset();  // discard partial work

    hash->Init();
    hash->Update({reinterpret_cast<const uint8_t*>(second_msg), std::strlen(second_msg)});
    std::array<uint8_t, kSha256DigestSize> digest4{};
    hash->Finalize({digest4.data(), digest4.size()});

    if (digest3 == digest4)
    {
        std::cout << "OK: Reset mid-stream + re-hash matches" << std::endl;
    }

    // 8. Query digest size
    auto digest_size = hash->GetDigestSize();
    std::cout << "Digest size: " << digest_size << " bytes" << std::endl;

    return 0;
}
