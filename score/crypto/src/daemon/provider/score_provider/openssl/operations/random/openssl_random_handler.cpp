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
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"

#include <openssl/crypto.h>  // OPENSSL_cleanse
#include <openssl/rand.h>

#include "score/mw/log/logging.h"

#include <cstdint>
#include <utility>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

using ::score::crypto::daemon::common::DaemonErrorCode;
using ::score::crypto::daemon::provider::handler::handler_utils::CheckAndGetSpan;

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
    score::cpp::span<std::uint8_t> output)
{
    if (RAND_bytes(output.data(), static_cast<int>(output.size())) != 1)
    {
        // Never leave a partially-filled buffer behind: a caller that ignored the
        // error would otherwise use predictable bytes as key or IV material.
        OPENSSL_cleanse(output.data(), output.size());
        score::mw::log::LogError() << LOG_PREFIX << "GenerateRandom: RAND_bytes failed for" << output.size() << "bytes";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kOperationFailed);
    }

    return output.size();
}

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslRandomHandler::SeedRandom(
    const common::RequestParameter& seed)
{
    const auto seedSpan = CheckAndGetSpan<const std::uint8_t>(seed);
    if (!seedSpan.has_value())
    {
        return ::score::crypto::make_unexpected(seedSpan.error());
    }

    // Entropy estimate 0.0: application-supplied material is stirred into the
    // pool but is not credited as entropy, so a caller passing predictable bytes
    // cannot degrade the generator.
    RAND_add(seedSpan.value().data(), static_cast<int>(seedSpan.value().size()), 0.0);

    return std::monostate{};
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
