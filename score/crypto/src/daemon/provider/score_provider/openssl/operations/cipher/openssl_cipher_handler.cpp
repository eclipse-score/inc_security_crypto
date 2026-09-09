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

#include "score/crypto/src/daemon/provider/score_provider/openssl/operations/cipher/openssl_cipher_handler.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include "score/mw/log/logging.h"

#include <array>
#include <cstring>
#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

using common::ResponseParameters;
using common::StreamOperationState;
using ::score::crypto::daemon::common::DaemonErrorCode;
namespace algo_info = ::score::crypto::daemon::common;
using ::score::crypto::daemon::provider::handler::handler_utils::CheckAndGetSpan;

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------

OpenSslCipherHandler::OpenSslCipherHandler(std::unique_ptr<operations::cipher::CipherExecutor> executor,
                                           const common::AlgorithmId& algorithm)
    : ScoreCipherHandler{std::move(executor), algorithm}
{
}

OpenSslCipherHandler::~OpenSslCipherHandler()
{
    CleanupContext();
}

void OpenSslCipherHandler::CleanupContext() noexcept
{
    if (m_ctx != nullptr)
    {
        EVP_CIPHER_CTX_free(m_ctx);
        m_ctx = nullptr;
    }
    if (m_cipher != nullptr)
    {
        EVP_CIPHER_free(m_cipher);
        m_cipher = nullptr;
    }
}

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------

bool OpenSslCipherHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    // The provider-independent table is the single source of truth for which AES
    // modes this stack exposes; OpenSSL happens to accept the same names.
    return algo_info::LookupCipher(algorithm).has_value();
}

bool OpenSslCipherHandler::GetBoundKeyMaterial(const std::uint8_t*& key_bytes, std::size_t& key_len) const noexcept
{
    if (m_init_params.bound_key_handler == nullptr)
    {
        return false;
    }
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast) - provider id verified in InitializeContext
    const auto* openssl_key = static_cast<const ::score::crypto::daemon::provider::openssl::OpenSslKeyHandler*>(
        m_init_params.bound_key_handler);
    key_bytes = openssl_key->GetRawKeyBytes(key_len);
    return (key_bytes != nullptr) && (key_len > 0U);
}

// ---------------------------------------------------------------------------
// Handler interface
// ---------------------------------------------------------------------------

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslCipherHandler::InitializeContext(
    const ::score::crypto::daemon::provider::handler::InitializationParams& init_params)
{
    const auto info = algo_info::LookupCipher(m_algorithm);
    if (!info.has_value())
    {
        score::mw::log::LogError() << LOG_PREFIX << "Unsupported algorithm:" << m_algorithm;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    // Picks up the encrypt/decrypt direction from CTX_CREATE param[4].
    auto base_result = ScoreCipherHandler::InitializeContext(init_params);
    if (!base_result.has_value())
    {
        return base_result;
    }

    CleanupContext();

    // OpenSSL's algorithm names match the identifiers used by this stack
    // ("AES-256-CBC", "AES-128-CTR", ...), so no translation table is needed.
    const std::string algorithm_name{m_algorithm.data(), m_algorithm.size()};
    m_cipher = EVP_CIPHER_fetch(nullptr, algorithm_name.c_str(), nullptr);
    if (m_cipher == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "EVP_CIPHER_fetch failed for" << m_algorithm;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kUnsupportedAlgorithm);
    }

    m_ctx = EVP_CIPHER_CTX_new();
    if (m_ctx == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "EVP_CIPHER_CTX_new failed";
        CleanupContext();
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAllocationFailed);
    }

    if (init_params.bound_key_handler == nullptr)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitializeContext: cipher context requires a bound key";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    // Provider-id check validates the key comes from the same provider (no dynamic_cast/RTTI).
    if (init_params.bound_key_handler->GetProviderId() != init_params.provider_id)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitializeContext: bound key is not an OpenSSL key handler"
                                   << " (key provider_id=" << init_params.bound_key_handler->GetProviderId()
                                   << ", expected=" << init_params.provider_id << ")";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    m_init_params = init_params;

    const std::uint8_t* key_bytes{nullptr};
    std::size_t key_len{0U};
    if (!GetBoundKeyMaterial(key_bytes, key_len))
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitializeContext: bound key has no raw key material";
        m_init_params = {};
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    // Catch a key/algorithm length mismatch here rather than letting OpenSSL
    // silently accept a short key later.
    if (key_len != info->key_size)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitializeContext: key length" << key_len
                                   << "does not match algorithm requirement" << info->key_size;
        m_init_params = {};
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmMismatch);
    }

    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslCipherHandler::Reset()
{
    return InitializeContext(m_init_params);
}

// ---------------------------------------------------------------------------
// ScoreCipherHandler interface
// ---------------------------------------------------------------------------

::score::crypto::Expected<std::monostate, DaemonErrorCode> OpenSslCipherHandler::InitCipher(
    std::optional<common::RequestParameter> iv)
{
    if ((m_ctx == nullptr) || (m_cipher == nullptr))
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitCipher: cipher context not allocated";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    const std::uint8_t* key_bytes{nullptr};
    std::size_t key_len{0U};
    if (!GetBoundKeyMaterial(key_bytes, key_len))
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitCipher: no valid key material";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    const std::size_t required_iv_size = GetIvSize();
    const std::uint8_t* iv_bytes{nullptr};
    std::size_t iv_len{0U};

    if (iv.has_value())
    {
        const auto ivSpan = CheckAndGetSpan<const std::uint8_t>(iv.value());
        if (!ivSpan.has_value())
        {
            return ::score::crypto::make_unexpected(ivSpan.error());
        }
        iv_bytes = ivSpan.value().data();
        iv_len = ivSpan.value().size();
    }

    if (iv_len != required_iv_size)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitCipher: IV length" << iv_len << "but algorithm requires"
                                   << required_iv_size;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    const int rv = (GetDirection() == score::crypto::CipherDirection::kEncrypt)
                       ? EVP_EncryptInit_ex2(m_ctx, m_cipher, key_bytes, iv_bytes, nullptr)
                       : EVP_DecryptInit_ex2(m_ctx, m_cipher, key_bytes, iv_bytes, nullptr);
    if (rv != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "InitCipher: EVP cipher init failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmInitializationFailed);
    }

    return std::monostate{};
}

::score::crypto::Expected<std::size_t, DaemonErrorCode> OpenSslCipherHandler::UpdateCipher(
    const common::RequestParameter& input,
    score::cpp::span<std::uint8_t> output)
{
    if (m_ctx == nullptr)
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    const auto inputSpan = CheckAndGetSpan<const std::uint8_t>(input);
    if (!inputSpan.has_value())
    {
        return ::score::crypto::make_unexpected(inputSpan.error());
    }

    // EVP may emit up to one extra block beyond the input length when it flushes
    // a previously buffered partial block, so the caller has to leave room for it.
    const std::size_t block_size = GetBlockSize();
    if (output.size() < inputSpan.value().size() + block_size)
    {
        score::mw::log::LogError() << LOG_PREFIX << "UpdateCipher: output buffer holds" << output.size()
                                   << "bytes, needs" << (inputSpan.value().size() + block_size);
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
    }

    int out_len = 0;
    const int rv =
        (GetDirection() == score::crypto::CipherDirection::kEncrypt)
            ? EVP_EncryptUpdate(
                  m_ctx, output.data(), &out_len, inputSpan.value().data(), static_cast<int>(inputSpan.value().size()))
            : EVP_DecryptUpdate(
                  m_ctx, output.data(), &out_len, inputSpan.value().data(), static_cast<int>(inputSpan.value().size()));
    if (rv != 1)
    {
        score::mw::log::LogError() << LOG_PREFIX << "UpdateCipher: EVP cipher update failed";
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    return static_cast<std::size_t>(out_len);
}

::score::crypto::Expected<std::size_t, DaemonErrorCode> OpenSslCipherHandler::FinalizeCipher(
    score::cpp::span<std::uint8_t> output)
{
    if (m_ctx == nullptr)
    {
        return ::score::crypto::make_unexpected(DaemonErrorCode::kStreamNotInitialized);
    }

    // At most one padded block is emitted here and stream modes emit nothing, so
    // EVP writes into a scratch block first: the caller's remaining space may be
    // shorter than a block and still be exactly right.
    std::array<std::uint8_t, EVP_MAX_BLOCK_LENGTH> scratch{};

    int out_len = 0;
    const int rv = (GetDirection() == score::crypto::CipherDirection::kEncrypt)
                       ? EVP_EncryptFinal_ex(m_ctx, scratch.data(), &out_len)
                       : EVP_DecryptFinal_ex(m_ctx, scratch.data(), &out_len);
    if (rv != 1)
    {
        // For decryption this is the normal signal that the padding is wrong —
        // i.e. the ciphertext or the key does not match.
        score::mw::log::LogError() << LOG_PREFIX << "FinalizeCipher: EVP cipher finalize failed";
        m_state = StreamOperationState::IDLE;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    const auto produced = static_cast<std::size_t>(out_len);
    if (produced > output.size())
    {
        score::mw::log::LogError() << LOG_PREFIX << "FinalizeCipher: output buffer holds" << output.size()
                                   << "bytes, needs" << produced;
        m_state = StreamOperationState::IDLE;
        return ::score::crypto::make_unexpected(DaemonErrorCode::kInsufficientBufferSize);
    }
    if (produced > 0U)
    {
        std::memcpy(output.data(), scratch.data(), produced);
    }

    m_state = StreamOperationState::IDLE;
    return produced;
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
