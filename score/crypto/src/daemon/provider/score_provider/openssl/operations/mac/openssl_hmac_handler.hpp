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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_MAC_OPENSSL_HMAC_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_MAC_OPENSSL_HMAC_HANDLER_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/daemon/provider/score_provider/operations/mac/mac_executor.hpp"
#include "score/crypto/daemon/provider/score_provider/operations/mac/score_mac_handler.hpp"

#include <openssl/evp.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

class OpenSslHmacHandler final
    : public ::score::crypto::daemon::provider::score_provider::operations::mac::ScoreMacHandler
{
  public:
    using Sptr = std::shared_ptr<OpenSslHmacHandler>;

    explicit OpenSslHmacHandler(std::unique_ptr<operations::mac::MacExecutor> executor,
                                const common::AlgorithmId& algorithm);
    ~OpenSslHmacHandler() override;

    OpenSslHmacHandler(const OpenSslHmacHandler&) = delete;
    OpenSslHmacHandler& operator=(const OpenSslHmacHandler&) = delete;
    OpenSslHmacHandler(OpenSslHmacHandler&&) = delete;
    OpenSslHmacHandler& operator=(OpenSslHmacHandler&&) = delete;

    // -----------------------------------------------------------------------
    // Handler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
    InitializeContext(const ::score::crypto::daemon::provider::handler::InitializationParams& init_params) override;

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> Reset()
        override;

    // -----------------------------------------------------------------------
    // MacHandler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> InitMac(
        const std::optional<common::RequestParameter> initialDataOrIV) override;

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> UpdateMac(
        const common::RequestParameter& dataToMac) override;

    [[nodiscard]] ::score::crypto::Expected<common::ResponseParameters,
                                            ::score::crypto::daemon::common::DaemonErrorCode>
    FinalizeMac(std::optional<common::RequestParameter> macOutput,
                const std::optional<common::RequestParameter> finalDataToMac) override;

    [[nodiscard]] ::score::crypto::Expected<bool, ::score::crypto::daemon::common::DaemonErrorCode> VerifyMac(
        const common::RequestParameter& expectedTag) override;

    [[nodiscard]] std::size_t GetMacSize() const noexcept override;

    /// @brief Check if the given algorithm is supported by this handler.
    [[nodiscard]] static bool IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept;

  private:
    /// @brief Map HMAC algorithm string (e.g. "HMAC-SHA256") to the underlying digest name
    ///        expected by EVP_MAC (e.g. "SHA256").
    [[nodiscard]] const char* GetDigestName() const noexcept;

    /// @brief Retrieve the bound key's raw bytes.
    /// @return true if key material is available, false if no key is bound.
    [[nodiscard]] bool GetBoundKeyMaterial(const uint8_t*& key_bytes, std::size_t& key_len) const noexcept;

    /// @brief Destroy and zero the EVP_MAC context.
    void CleanupContext() noexcept;

    /// @brief Allocate (or resize) the internal output buffer.
    void AllocateOutputBuffer(std::size_t size);

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
    FinalizeMacInternal(uint8_t* output_buf, std::size_t buf_len, std::size_t& out_len);

    EVP_MAC* m_mac{nullptr};
    EVP_MAC_CTX* m_ctx{nullptr};
    std::vector<uint8_t> m_output_buffer;
    ::score::crypto::daemon::provider::handler::InitializationParams m_init_params;

    static constexpr std::string_view LOG_PREFIX = "[OPENSSL_HMAC_HANDLER]";
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_MAC_OPENSSL_HMAC_HANDLER_HPP
