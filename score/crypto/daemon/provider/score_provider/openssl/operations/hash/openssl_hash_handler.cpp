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

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/operations/hash/openssl_hash_handler.hpp"

#include "score/mw/log/logging.h"
#include <cassert>
#include <cstdint>
#include <cstring>

#include <memory>
#include <optional>
#include <sstream>
#include <thread>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

// Using declarations for convenience
using common::DaemonErrorCode;
using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;

// Static array initialization
static constexpr const char* SUPPORTED_ALGORITHMS[] = {"SHA256", "SHA384", "SHA512", "SHA224", "SHA1", "MD5"};

bool OpenSslHashHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    for (const char* supported : SUPPORTED_ALGORITHMS)
    {
        if (algorithm == supported)
        {
            return true;
        }
    }
    return false;
}

OpenSslHashHandler::OpenSslHashHandler(
    std::unique_ptr<::score::crypto::daemon::provider::score_provider::operations::hash::HashExecutor> executor,
    common::AlgorithmId algorithm)
    : ScoreHashHandler(std::move(executor), algorithm), mCurrentStreamContext(nullptr)
{
    // Operation support is defined by the executor
}

OpenSslHashHandler::~OpenSslHashHandler()
{
    CleanupStreamContext();
}

Expected<std::monostate, DaemonErrorCode> OpenSslHashHandler::ValidateAlgorithm(const std::string& algorithm) const
{
    for (const char* supported : SUPPORTED_ALGORITHMS)
    {
        if (algorithm == supported)
        {
            return std::monostate{};
        }
    }
    return make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
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

Expected<std::monostate, DaemonErrorCode> OpenSslHashHandler::InitHash(
    const std::optional<common::RequestParameter> initialDataOrIV)
{
    std::ostringstream tid;
    tid << std::this_thread::get_id();
    score::mw::log::LogDebug() << "DEBUG: InitHash called with algorithm:" << m_algorithm << ", thread ID:" << tid.str()
                               << ", this:" << reinterpret_cast<uintptr_t>(this);
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
        return make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }

    // If initial data is provided, process it (OpenSSL-specific)
    if (initialDataOrIV.has_value())
    {
        const uint8_t* buffer = nullptr;
        size_t size = 0;

        const auto result = ::score::crypto::daemon::provider::handler::handler_utils::ExtractBufferData(
            initialDataOrIV.value(), buffer, size);
        if (!result.has_value())
        {
            return result;
        }

        if (EVP_DigestUpdate(mCurrentStreamContext, buffer, size) != 1)
        {
            return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
        }
    }

    return std::monostate{};
}

Expected<std::monostate, DaemonErrorCode> OpenSslHashHandler::UpdateHash(const common::RequestParameter& dataToHash)
{
    // Validate stream context exists (OpenSSL-specific)
    if (mCurrentStreamContext == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    // Extract and update with data (OpenSSL-specific)
    const uint8_t* buffer = nullptr;
    size_t size = 0;

    const auto result =
        ::score::crypto::daemon::provider::handler::handler_utils::ExtractBufferData(dataToHash, buffer, size);
    if (!result.has_value())
    {
        return result;
    }

    if (EVP_DigestUpdate(mCurrentStreamContext, buffer, size) != 1)
    {
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    return std::monostate{};
}

Expected<common::ResponseParameters, DaemonErrorCode> OpenSslHashHandler::FinalizeHash(
    std::optional<common::RequestParameter> hashOutput,
    const std::optional<common::RequestParameter> finalDataToHash)
{
    if (mCurrentStreamContext == nullptr)
    {
        return make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    // Process final data if provided (OpenSSL-specific)
    if (finalDataToHash.has_value())
    {
        const uint8_t* buffer = nullptr;
        size_t size = 0;

        const auto result = ::score::crypto::daemon::provider::handler::handler_utils::ExtractBufferData(
            finalDataToHash.value(), buffer, size);
        if (!result.has_value())
        {
            return make_unexpected(result.error());
        }

        if (EVP_DigestUpdate(mCurrentStreamContext, buffer, size) != 1)
        {
            CleanupStreamContext();
            return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
        }
    }

    // Get the hash size (OpenSSL-specific)
    unsigned int digestSize = EVP_MD_CTX_size(mCurrentStreamContext);
    if (digestSize == 0)
    {
        CleanupStreamContext();
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    // Resolve output buffer: validate size if caller-provided, else allocate internally
    unsigned char* outputBuf = nullptr;
    auto allocateOutputBuffer = !hashOutput.has_value();
    if (!allocateOutputBuffer)
    {
        common::RequestParameter& outputRef = hashOutput.value();
        uint8_t* outputBuffer = nullptr;
        size_t outputSize = 0;
        const auto result = ::score::crypto::daemon::provider::handler::handler_utils::ExtractOutputBufferData(
            outputRef, outputBuffer, outputSize);
        if (!result.has_value())
        {
            CleanupStreamContext();
            return make_unexpected(result.error());
        }
        if (outputSize < digestSize)
        {
            CleanupStreamContext();
            return make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
        }
        outputBuf = outputBuffer;
    }
    else
    {
        AllocateOutputBuffer(digestSize);
        outputBuf = mOutputBuffer.data();
    }

    unsigned int digestLen = 0;
    if (EVP_DigestFinal_ex(mCurrentStreamContext, outputBuf, &digestLen) != 1)
    {
        CleanupStreamContext();
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    // Clean up the context
    CleanupStreamContext();

    common::ResponseParameters response;
    if (allocateOutputBuffer)
    {
        response.push_back(common::OwnedBuffer{std::move(mOutputBuffer)});
    }
    else
    {
        response.push_back(common::VirtualMemoryBufferConst{outputBuf, digestLen});
    }

    return response;
}

Expected<common::ResponseParameters, DaemonErrorCode> OpenSslHashHandler::SingleShotHash(
    const common::RequestParameter& dataToHash,
    std::optional<common::RequestParameter> outputHash,
    std::optional<common::RequestParameter> initializationVector)
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

    unsigned int digestSize = EVP_MD_size(md);

    // Extract input data
    const uint8_t* inputBuffer = nullptr;
    size_t inputSize = 0;

    const auto inputResult = ::score::crypto::daemon::provider::handler::handler_utils::ExtractBufferData(
        dataToHash, inputBuffer, inputSize);
    if (!inputResult.has_value())
    {
        return make_unexpected(inputResult.error());
    }

    // Determine output destination
    unsigned char* outputBuf = nullptr;
    unsigned int digestLen = 0;

    auto allocateOutputBuffer = !outputHash.has_value();
    if (!allocateOutputBuffer)
    {
        common::RequestParameter& outputRef = outputHash.value();
        uint8_t* outputBuffer = nullptr;
        size_t outputSize = 0;

        const auto outputResult = ::score::crypto::daemon::provider::handler::handler_utils::ExtractOutputBufferData(
            outputRef, outputBuffer, outputSize);
        if (!outputResult.has_value())
        {
            return make_unexpected(outputResult.error());
        }

        if (outputSize < digestSize)
        {
            return make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
        }

        outputBuf = outputBuffer;
    }
    else
    {
        AllocateOutputBuffer(digestSize);
        outputBuf = mOutputBuffer.data();
    }

    // Single OpenSSL call: handles context creation, init, update, final, and cleanup internally
    if (EVP_Digest(inputBuffer, inputSize, outputBuf, &digestLen, md, nullptr) != 1)
    {
        return make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    common::ResponseParameters response;
    if (allocateOutputBuffer)
    {
        response.push_back(common::OwnedBuffer{std::move(mOutputBuffer)});
    }
    else
    {
        response.push_back(common::VirtualMemoryBufferConst{outputBuf, digestLen});
    }

    return response;
}

void OpenSslHashHandler::AllocateOutputBuffer(size_t size)
{
    mOutputBuffer.clear();
    mOutputBuffer.resize(size);
    score::mw::log::LogDebug() << "[HASH_HANDLER] Output buffer allocated with size:" << size;
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
