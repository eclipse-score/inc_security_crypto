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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CIPHER_OPENSSL_CIPHER_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CIPHER_OPENSSL_CIPHER_HANDLER_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/cipher/cipher_executor.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/cipher/score_cipher_handler.hpp"

#include <openssl/evp.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string_view>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

/// @brief OpenSSL symmetric cipher handler built on the EVP_CIPHER interface.
///
/// Supports AES-128/192/256 in CBC — whatever kCipherAlgorithms lists. CBC uses
/// OpenSSL's default PKCS#7 padding, so ciphertext is one block longer than
/// plaintext and Finalize() emits that trailing block.
///
/// The bound key must come from the same provider and carry raw symmetric key
/// material of the length the algorithm requires — a key generated as
/// "AES-256-CBC" or plain "AES-256" both work, a 16-byte key under an AES-256
/// algorithm is rejected at Init time.
class OpenSslCipherHandler final
    : public ::score::crypto::daemon::provider::score_provider::operations::cipher::ScoreCipherHandler
{
  public:
    using Sptr = std::shared_ptr<OpenSslCipherHandler>;

    explicit OpenSslCipherHandler(std::unique_ptr<operations::cipher::CipherExecutor> executor,
                                  const common::AlgorithmId& algorithm);
    ~OpenSslCipherHandler() override;

    OpenSslCipherHandler(const OpenSslCipherHandler&) = delete;
    OpenSslCipherHandler& operator=(const OpenSslCipherHandler&) = delete;
    OpenSslCipherHandler(OpenSslCipherHandler&&) = delete;
    OpenSslCipherHandler& operator=(OpenSslCipherHandler&&) = delete;

    // -----------------------------------------------------------------------
    // Handler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
    InitializeContext(const ::score::crypto::daemon::provider::handler::InitializationParams& init_params) override;

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> Reset()
        override;

    // -----------------------------------------------------------------------
    // ScoreCipherHandler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
    InitCipher(std::optional<common::RequestParameter> iv) override;

    [[nodiscard]] ::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode> UpdateCipher(
        const common::RequestParameter& input,
        score::cpp::span<std::uint8_t> output) override;

    [[nodiscard]] ::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode>
    FinalizeCipher(score::cpp::span<std::uint8_t> output) override;

    /// @brief Check if the given algorithm is supported by this handler.
    [[nodiscard]] static bool IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept;

  private:
    /// @brief Retrieve the bound key's raw bytes.
    /// @return true if key material of the expected length is available.
    [[nodiscard]] bool GetBoundKeyMaterial(const std::uint8_t*& key_bytes, std::size_t& key_len) const noexcept;

    /// @brief Free the EVP cipher context and fetched algorithm.
    void CleanupContext() noexcept;

    EVP_CIPHER* m_cipher{nullptr};
    EVP_CIPHER_CTX* m_ctx{nullptr};
    ::score::crypto::daemon::provider::handler::InitializationParams m_init_params;

    static constexpr std::string_view LOG_PREFIX = "[OPENSSL_CIPHER_HANDLER]";
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_CIPHER_OPENSSL_CIPHER_HANDLER_HPP
