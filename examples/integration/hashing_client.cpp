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

#include "score/crypto/src/api/config/hash_context_config.hpp"
#include "score/crypto/src/api/contexts/i_hash_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <iostream>
#include <string_view>

namespace
{

constexpr std::string_view kDefaultEndpoint{"unix:///tmp/crypto_daemon.sock"};
constexpr std::string_view kMessage{"Hello, World!"};
constexpr std::array<std::uint8_t, 32U> kExpectedDigest{
    0xdfU, 0xfdU, 0x60U, 0x21U, 0xbbU, 0x2bU, 0xd5U, 0xb0U, 0xafU, 0x67U, 0x62U, 0x90U, 0x80U, 0x9eU, 0xc3U, 0xa5U,
    0x31U, 0x91U, 0xddU, 0x81U, 0xc7U, 0xf7U, 0x0aU, 0x4bU, 0x28U, 0x68U, 0x8aU, 0x36U, 0x21U, 0x82U, 0x98U, 0x6fU,
};

}  // namespace

int main(int argc, char** argv)
{
    const std::string_view endpoint = argc > 1 ? std::string_view{argv[1]} : kDefaultEndpoint;

    score::crypto::CryptoStackConfig stack_config;
    stack_config.SetConnectionEndpoint(endpoint);

    auto stack_result = score::crypto::CreateCryptoStack(stack_config);
    if (!stack_result.has_value())
    {
        std::cerr << "Failed to connect to the crypto daemon\n";
        return 1;
    }

    auto context_result = stack_result.value()->CreateCryptoContext();
    if (!context_result.has_value())
    {
        std::cerr << "Failed to create a crypto context\n";
        return 1;
    }

    score::crypto::HashContextConfig hash_config;
    hash_config.SetAlgorithm("SHA256");

    auto hash_result = context_result.value()->CreateHashContext(hash_config);
    if (!hash_result.has_value())
    {
        std::cerr << "Failed to create a SHA256 context\n";
        return 1;
    }

    auto& hash = hash_result.value();
    if (hash->GetDigestSize() != kExpectedDigest.size())
    {
        std::cerr << "Unexpected SHA256 digest size\n";
        return 1;
    }

    std::array<std::uint8_t, kExpectedDigest.size()> digest{};
    const auto hash_operation = hash->SingleShot(
        {reinterpret_cast<const std::uint8_t*>(kMessage.data()), kMessage.size()}, {digest.data(), digest.size()});
    if (!hash_operation.has_value())
    {
        std::cerr << "SHA256 operation failed\n";
        return 1;
    }
    if ((hash_operation.value() != digest.size()) ||
        !std::equal(digest.cbegin(), digest.cend(), kExpectedDigest.cbegin()))
    {
        std::cerr << "SHA256 digest did not match the expected value\n";
        return 1;
    }

    std::cout << "SCORE Crypto SHA256 integration example passed\n";
    return 0;
}
