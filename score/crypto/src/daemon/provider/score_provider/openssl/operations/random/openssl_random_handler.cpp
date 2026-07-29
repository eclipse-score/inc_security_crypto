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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/random/openssl_random_handler.hpp"

#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <openssl/crypto.h>  // OPENSSL_cleanse
#include <openssl/rand.h>

#include "score/mw/log/logging.h"

#include <cstdint>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

using ::score::crypto::daemon::common::DaemonErrorCode;

namespace
{
/// OpenSSL's public RNG is a CTR-DRBG; the empty identifier means
/// "whatever the provider considers its default".
constexpr std::string_view kDefaultAlgorithm{};
constexpr std::string_view kCtrDrbgAlgorithm{"CTR-DRBG"};
}  // namespace

OpenSslRandomHandler::OpenSslRandomHandler(std::unique_ptr<operations::random::RandomExecutor> executor,
                                           const common::AlgorithmId& algorithm)
    : ScoreRandomHandler{std::move(executor), algorithm}
{
}

bool OpenSslRandomHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    const std::string_view name{algorithm.data(), algorithm.size()};
    return (name == kDefaultAlgorithm) || (name == kCtrDrbgAlgorithm);
}

::score::crypto::Expected<std::size_t, DaemonErrorCode> OpenSslRandomHandler::GenerateRandom(
    score::cpp::span<std::uint8_t> buffer)
{
    if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1)
    {
        // Never leave a partially-filled buffer behind: a caller that ignored the
        // error would otherwise use predictable bytes as key or IV material.
        OPENSSL_cleanse(buffer.data(), buffer.size());
        score::mw::log::LogError() << LOG_PREFIX << "GenerateRandom: RAND_bytes failed for" << buffer.size() << "bytes";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kOperationFailed);
    }

    return buffer.size();
}

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslRandomHandler::SeedRandom(
    score::cpp::span<const std::uint8_t> /*seed*/)
{
    // GenerateRandom draws from RAND_bytes, OpenSSL's process-wide DRBG, which
    // also feeds key and signature generation. Stirring caller-supplied material
    // into it would let one client reach state every other client depends on,
    // however the contribution is credited. Seeding becomes supportable once a
    // context owns an EVP_RAND_CTX of its own.
    return ::score::crypto::make_unexpected(DaemonErrorCode::kUnsupportedOperation);
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
