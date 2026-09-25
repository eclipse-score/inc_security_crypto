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

#include <openssl/err.h>
#include <openssl/evp.h>

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/hash/openssl_hash_handler.hpp"

#include "score/mw/log/logging.h"
#include <cstdint>

#include <memory>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

// Using declarations for convenience
using common::DaemonErrorCode;
using common::ResponseParameters;
using common::StreamOperationState;

bool OpenSslHashHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    return ::score::crypto::daemon::provider::openssl::detail::LookupHashEVPMD(algorithm) != nullptr;
}

OpenSslHashHandler::OpenSslHashHandler(
    std::unique_ptr<::score::crypto::daemon::provider::score_provider::operations::hash::HashExecutor> executor,
    common::AlgorithmId algorithm,
    const DigestUpdateFunction digestUpdate)
    : ScoreHashHandler(std::move(executor), algorithm), mCurrentStreamContext(nullptr), mDigestUpdate(digestUpdate)
{
    // Operation support is defined by the executor
}

OpenSslHashHandler::~OpenSslHashHandler()
{
    CleanupStreamContext();
}

Expected<std::monostate, DaemonErrorCode> OpenSslHashHandler::ValidateAlgorithm(const std::string& algorithm) const
{
    return GetEVPMD(algorithm) != nullptr ? Expected<std::monostate, DaemonErrorCode>{std::monostate{}}
                                          : make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
}

Expected<std::monostate, DaemonErrorCode> OpenSslHashHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& init_params)
{
    score::mw::log::LogDebug() << "DEBUG: InitializeContext called with algorithm:" << m_algorithm;

    // Validate the algorithm
    const auto result = ValidateAlgorithm(m_algorithm);
    if (!result.has_value())
    {
        score::mw::log::LogError() << "ERROR: Algorithm validation failed in InitializeContext";
        return result;
    }

    // Call base to set state to IDLE
    return ScoreHashHandler::InitializeContext(init_params);
}

void OpenSslHashHandler::CleanupStreamContext()
{
    if (mCurrentStreamContext != nullptr)
    {
        EVP_MD_CTX_free(mCurrentStreamContext);
        mCurrentStreamContext = nullptr;
    }
}

const EVP_MD* OpenSslHashHandler::GetEVPMD(const std::string& algorithm) const
{
    return ::score::crypto::daemon::provider::openssl::detail::LookupHashEVPMD(algorithm);
}

Expected<std::monostate, DaemonErrorCode> OpenSslHashHandler::Reset()
{
    CleanupStreamContext();
    m_state = StreamOperationState::IDLE;
    return {};
}

Expected<std::monostate, DaemonErrorCode> OpenSslHashHandler::InitHash()
{
    score::mw::log::LogDebug() << "[OPENSSL_HASH] Initializing stream for algorithm:" << m_algorithm;
    const EVP_MD* md = GetEVPMD(m_algorithm);
    if (md == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    // Initialize stream context if needed (OpenSSL-specific)
    if (mCurrentStreamContext == nullptr)
    {
        mCurrentStreamContext = EVP_MD_CTX_new();
        if (mCurrentStreamContext == nullptr)
        {
            return make_unexpected(DaemonErrorCode::kContextCreationFailed);
        }
    }

    // Reset the context (OpenSSL-specific)
    if (EVP_DigestInit_ex(mCurrentStreamContext, md, nullptr) != 1)
    {
        CleanupStreamContext();
        m_state = StreamOperationState::IDLE;
        return make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }

    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> OpenSslHashHandler::UpdateHash(
    const score::cpp::span<const std::uint8_t> dataToHash)
{
    // Validate stream context exists (OpenSSL-specific)
    if (mCurrentStreamContext == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    const std::uint8_t emptyInput{0U};
    const auto* inputData = dataToHash.empty() ? &emptyInput : dataToHash.data();
    if (mDigestUpdate(mCurrentStreamContext, inputData, dataToHash.size()) != 1)
    {
        CleanupStreamContext();
        m_state = StreamOperationState::IDLE;
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    return std::monostate{};
}

Expected<common::ResponseParameters, DaemonErrorCode> OpenSslHashHandler::FinalizeHash(
    const score::cpp::span<std::uint8_t> hashOutput)
{
    if (mCurrentStreamContext == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    // Get the hash size (OpenSSL-specific)
    const int digestSizeResult = EVP_MD_CTX_size(mCurrentStreamContext);
    if (digestSizeResult <= 0)
    {
        CleanupStreamContext();
        m_state = StreamOperationState::IDLE;
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    const auto digestSize = static_cast<std::size_t>(digestSizeResult);

    // On an undersized output buffer the digest operation remains active so
    // the caller can retry Finalize() with a corrected buffer.
    if (hashOutput.size() < digestSize)
    {
        return make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
    }

    unsigned int digestLen = 0;
    if (EVP_DigestFinal_ex(mCurrentStreamContext, hashOutput.data(), &digestLen) != 1)
    {
        CleanupStreamContext();
        m_state = StreamOperationState::IDLE;
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    // Clean up the context
    CleanupStreamContext();

    common::ResponseParameters response;
    response.push_back(static_cast<uint64_t>(digestLen));
    return response;
}

Expected<common::ResponseParameters, DaemonErrorCode> OpenSslHashHandler::SingleShotHash(
    const score::cpp::span<const std::uint8_t> dataToHash,
    const score::cpp::span<std::uint8_t> outputHash)
{
    if (m_algorithm.empty())
    {
        return make_unexpected(DaemonErrorCode::kInsufficientParameters);
    }

    const auto algResult = ValidateAlgorithm(m_algorithm);
    if (!algResult.has_value())
    {
        return make_unexpected(algResult.error());
    }

    const EVP_MD* md = GetEVPMD(m_algorithm);
    if (md == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    const int digestSizeResult = EVP_MD_size(md);
    if (digestSizeResult <= 0)
    {
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    const auto digestSize = static_cast<std::size_t>(digestSizeResult);

    if (outputHash.size() < digestSize)
    {
        return make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
    }

    // Single OpenSSL call: handles context creation, init, update, final, and cleanup internally
    unsigned int digestLen = 0;
    const std::uint8_t emptyInput{0U};
    const auto* inputData = dataToHash.empty() ? &emptyInput : dataToHash.data();
    if (EVP_Digest(inputData, dataToHash.size(), outputHash.data(), &digestLen, md, nullptr) != 1)
    {
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    common::ResponseParameters response;
    response.push_back(static_cast<uint64_t>(digestLen));
    return response;
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
