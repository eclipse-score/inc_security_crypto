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

#include "score/crypto/daemon/provider/score_provider/openssl/operations/mac/openssl_hmac_handler.hpp"
#include "score/crypto/daemon/common/algorithm_info.hpp"
#include "score/crypto/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/detail/openssl_algorithm_info.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include <openssl/crypto.h>  // CRYPTO_memcmp, OPENSSL_cleanse
#include <openssl/params.h>  // OSSL_PARAM

#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/mw/log/logging.h"
#include <cstring>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

using common::OperationIdentifier;
using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;
using ::score::crypto::daemon::common::DaemonErrorCode;
namespace handler_utils = ::score::crypto::daemon::provider::handler::handler_utils;

// ---------------------------------------------------------------------------
// Supported algorithms
// ---------------------------------------------------------------------------

static constexpr const char* kSupportedAlgorithms[] = {
    "HMAC-SHA256",
    "HMAC-SHA384",
    "HMAC-SHA512",
};

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

OpenSslHmacHandler::OpenSslHmacHandler(std::unique_ptr<operations::mac::MacExecutor> executor,
                                       const common::AlgorithmId& algorithm)
    : ScoreMacHandler{std::move(executor), algorithm}
{
}

OpenSslHmacHandler::~OpenSslHmacHandler()
{
    CleanupContext();
}

void OpenSslHmacHandler::CleanupContext() noexcept
{
    if (m_ctx != nullptr)
    {
        EVP_MAC_CTX_free(m_ctx);
        m_ctx = nullptr;
    }
    if (m_mac != nullptr)
    {
        EVP_MAC_free(m_mac);
        m_mac = nullptr;
    }
    OPENSSL_cleanse(m_output_buffer.data(), m_output_buffer.size());
    m_output_buffer.clear();
}

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------

const char* OpenSslHmacHandler::GetDigestName() const noexcept
{
    const std::string_view algo{m_algorithm.data(), m_algorithm.size()};
    if (algo == "HMAC-SHA256")
    {
        return "SHA256";
    }
    if (algo == "HMAC-SHA384")
    {
        return "SHA384";
    }
    if (algo == "HMAC-SHA512")
    {
        return "SHA512";
    }
    return nullptr;
}

bool OpenSslHmacHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    for (const char* supported : kSupportedAlgorithms)
    {
        if (algorithm == supported)
        {
            return true;
        }
    }
    return false;
}

std::size_t OpenSslHmacHandler::GetMacSize() const noexcept
{
    return ::score::crypto::daemon::common::LookupMacSize(std::string_view{m_algorithm.data(), m_algorithm.size()})
        .value_or(0U);
}

// ---------------------------------------------------------------------------
// Handler interface
// ---------------------------------------------------------------------------

::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslHmacHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& init_params)
{
    // Validate algorithm (m_algorithm is set at construction).
    bool found{false};
    for (const char* algo : kSupportedAlgorithms)
    {
        if (m_algorithm == algo)
        {
            found = true;
            break;
        }
    }
    if (!found)
    {
        score::mw::log::LogError() << LOG_PREFIX << "Unsupported algorithm:" << m_algorithm;
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }

    m_state = StreamOperationState::IDLE;

    // Fetch the EVP_MAC object for HMAC and allocate context.
    CleanupContext();
    m_mac = EVP_MAC_fetch(nullptr, "HMAC", nullptr);
    if (m_mac == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "EVP_MAC_fetch(\"HMAC\") failed";
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }
    m_ctx = EVP_MAC_CTX_new(m_mac);
    if (m_ctx == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "EVP_MAC_CTX_new failed";
        EVP_MAC_free(m_mac);
        m_mac = nullptr;
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kAllocationFailed);
    }

    m_output_buffer.resize(GetMacSize());

    // Bind key if provided via InitializationParams (bound_key_handler != nullptr).
    if (init_params.bound_key_handler != nullptr)
    {
        // Provider-id check validates the key comes from the same provider (no dynamic_cast/RTTI).
        if (init_params.bound_key_handler->GetProviderId() != 0)  // OPENSSL provider ID
        {
            score::mw::log::LogError() << LOG_PREFIX << "InitializeContext: bound key is not an OpenSSL key handler";
            return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
        }
        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast) � type tag verified above
        const auto* openssl_key = static_cast<const ::score::crypto::daemon::provider::openssl::OpenSslKeyHandler*>(
            init_params.bound_key_handler);

        std::size_t key_len{0U};
        const uint8_t* key_bytes = openssl_key->GetRawKeyBytes(key_len);
        if (key_bytes == nullptr || key_len == 0U)
        {
            score::mw::log::LogError() << LOG_PREFIX << "InitializeContext: invalid key handle";
            return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
        }

        // Key is valid � store params so InitMac() and Reset() can use them.
        m_init_params = init_params;
        m_state = StreamOperationState::STREAM_INITIALIZED;
    }

    return std::monostate{};
}

::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> OpenSslHmacHandler::InitMac(
    const std::optional<common::RequestParameter> /*initialDataOrIV*/)
{
    if (m_ctx == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitMac: HMAC context not allocated";
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kStreamNotInitialized);
    }

    const uint8_t* key_bytes{nullptr};
    std::size_t key_len{0U};
    if (!GetBoundKeyMaterial(key_bytes, key_len))
    {
        score::mw::log::LogError() << LOG_PREFIX
                                   << "InitMac: no valid key material \u2014 call InitializeContext with a key first";
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kStreamNotInitialized);
    }

    const char* digest_name = GetDigestName();
    if (digest_name == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitMac: unsupported digest for algorithm" << m_algorithm;
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }

    // EVP_MAC_init with key + OSSL_PARAM for digest algorithm
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast) ? OpenSSL OSSL_PARAM API requires non-const char*
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string("digest", const_cast<char*>(digest_name), 0),
        OSSL_PARAM_construct_end(),
    };

    const int rv = EVP_MAC_init(m_ctx, key_bytes, key_len, params);
    if (rv != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitMac: EVP_MAC_init failed";
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kAlgorithmInitializationFailed);
    }

    return std::monostate{};
}

bool OpenSslHmacHandler::GetBoundKeyMaterial(const uint8_t*& key_bytes, std::size_t& key_len) const noexcept
{
    if (m_init_params.bound_key_handler == nullptr)
    {
        return false;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast) � type tag verified in InitializeContext
    const auto* openssl_key = static_cast<const ::score::crypto::daemon::provider::openssl::OpenSslKeyHandler*>(
        m_init_params.bound_key_handler);
    key_bytes = openssl_key->GetRawKeyBytes(key_len);
    return key_bytes != nullptr && key_len > 0U;
}

::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> OpenSslHmacHandler::Reset()
{
    return InitializeContext(m_init_params);
}

// ---------------------------------------------------------------------------
// MacHandler interface
// ---------------------------------------------------------------------------

::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslHmacHandler::UpdateMac(const common::RequestParameter& dataToMac)
{
    if (m_ctx == nullptr || m_state == StreamOperationState::IDLE)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kStreamNotInitialized);
    }

    const uint8_t* data{nullptr};
    std::size_t data_len{0U};
    auto extract = handler_utils::ExtractBufferData(dataToMac, data, data_len);
    if (!extract.has_value())
    {
        return ::score::crypto::make_unexpected(extract.error());
    }

    const int rv = EVP_MAC_update(m_ctx, data, data_len);
    if (rv != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "EVP_MAC_update failed";
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    return std::monostate{};
}

::score::crypto::Expected<common::ResponseParameters, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslHmacHandler::FinalizeMac(std::optional<common::RequestParameter> macOutput,
                                const std::optional<common::RequestParameter> finalDataToMac)
{
    // If final data is provided, feed it before producing the tag.
    if (finalDataToMac.has_value())
    {
        auto update_result = UpdateMac(finalDataToMac.value());
        if (!update_result.has_value())
        {
            return ::score::crypto::make_unexpected(update_result.error());
        }
    }

    const std::size_t mac_size = GetMacSize();
    const bool allocateOutputBuffer = !macOutput.has_value();

    // Resolve output buffer: caller-provided or internal.
    uint8_t* outputBuf = nullptr;
    std::size_t outputBufSize = 0U;
    if (!allocateOutputBuffer)
    {
        common::RequestParameter& outputRef = macOutput.value();
        const auto result = handler_utils::ExtractOutputBufferData(outputRef, outputBuf, outputBufSize);
        if (!result.has_value())
        {
            return ::score::crypto::make_unexpected(result.error());
        }
        if (outputBufSize < mac_size)
        {
            return ::score::crypto::make_unexpected(
                ::score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
        }
    }
    else
    {
        AllocateOutputBuffer(mac_size);
        outputBuf = m_output_buffer.data();
        outputBufSize = m_output_buffer.size();
    }

    std::size_t hmac_len{0U};
    const auto raw_res = FinalizeMacInternal(outputBuf, outputBufSize, hmac_len);
    if (!raw_res.has_value())
    {
        return ::score::crypto::make_unexpected(raw_res.error());
    }

    common::ResponseParameters response;
    if (allocateOutputBuffer)
    {
        response.push_back(common::OwnedBuffer{std::move(m_output_buffer)});
    }
    else
    {
        response.push_back(common::VirtualMemoryBufferConst{outputBuf, hmac_len});
    }
    return response;
}

::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
OpenSslHmacHandler::FinalizeMacInternal(uint8_t* output_buf, std::size_t buf_len, std::size_t& out_len)
{
    if (m_ctx == nullptr)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kStreamNotInitialized);
    }

    const std::size_t mac_size = GetMacSize();
    if (buf_len < mac_size)
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
    }

    std::size_t hmac_len = 0U;
    const int rv = EVP_MAC_final(m_ctx, output_buf, &hmac_len, buf_len);
    if (rv != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "EVP_MAC_final failed";
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    out_len = hmac_len;
    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

::score::crypto::Expected<bool, ::score::crypto::daemon::common::DaemonErrorCode> OpenSslHmacHandler::VerifyMac(
    const common::RequestParameter& expectedTag)
{
    const uint8_t* tag{nullptr};
    std::size_t tag_len{0U};
    auto extract = handler_utils::ExtractBufferData(expectedTag, tag, tag_len);
    if (!extract.has_value())
    {
        return ::score::crypto::make_unexpected(extract.error());
    }

    if (tag_len != GetMacSize())
    {
        return ::score::crypto::make_unexpected(
            ::score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
    }

    AllocateOutputBuffer(GetMacSize());
    std::size_t out_len{0U};
    const auto final_res = FinalizeMacInternal(m_output_buffer.data(), m_output_buffer.size(), out_len);
    if (!final_res.has_value())
    {
        OPENSSL_cleanse(m_output_buffer.data(), m_output_buffer.size());
        return ::score::crypto::make_unexpected(final_res.error());
    }

    // Constant-time comparison.
    const int match = CRYPTO_memcmp(m_output_buffer.data(), tag, out_len);
    OPENSSL_cleanse(m_output_buffer.data(), m_output_buffer.size());
    return match == 0;
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

void OpenSslHmacHandler::AllocateOutputBuffer(std::size_t size)
{
    m_output_buffer.clear();
    m_output_buffer.resize(size);
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
