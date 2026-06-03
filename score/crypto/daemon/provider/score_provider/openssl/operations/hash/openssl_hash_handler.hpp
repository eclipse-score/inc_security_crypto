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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_HASH_OPENSSL_HASH_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_HASH_OPENSSL_HASH_HANDLER_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/provider/score_provider/operations/hash/hash_executor.hpp"
#include "score/crypto/daemon/provider/score_provider/operations/hash/score_hash_handler.hpp"
#include <openssl/evp.h>
#include <memory>
#include <optional>
#include <string>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

class OpenSslHashHandler final
    : public ::score::crypto::daemon::provider::score_provider::operations::hash::ScoreHashHandler
{
  public:
    using Sptr = std::shared_ptr<OpenSslHashHandler>;

    explicit OpenSslHashHandler(
        std::unique_ptr<::score::crypto::daemon::provider::score_provider::operations::hash::HashExecutor> executor,
        common::AlgorithmId algorithm);
    ~OpenSslHashHandler() override;

    // Handler interface overrides (OpenSSL-specific initialization and cleanup)
    Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const ::score::crypto::daemon::provider::handler::InitializationParams& init_params) override;
    Expected<std::monostate, common::DaemonErrorCode> Reset() override;

    // ScoreHashHandler typed method overrides (OpenSSL crypto implementation)
    Expected<std::monostate, common::DaemonErrorCode> InitHash(
        const std::optional<common::RequestParameter> initialDataOrIV) override;
    Expected<std::monostate, common::DaemonErrorCode> UpdateHash(const common::RequestParameter& dataToHash) override;
    Expected<common::ResponseParameters, common::DaemonErrorCode> FinalizeHash(
        std::optional<common::RequestParameter> hashOutput,
        const std::optional<common::RequestParameter> finalDataToHash) override;
    Expected<common::ResponseParameters, common::DaemonErrorCode> SingleShotHash(
        const common::RequestParameter& dataToHash,
        std::optional<common::RequestParameter> outputHash,
        std::optional<common::RequestParameter> initializationVector) override;

    /// @brief Check if the given algorithm is supported by this handler.
    [[nodiscard]] static bool IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept;

  private:
    // OpenSSL-specific stream context management
    EVP_MD_CTX* mCurrentStreamContext;

    // Output buffer - handler owns allocation and lifecycle
    std::vector<uint8_t> mOutputBuffer;

    // Helper methods (OpenSSL provider-specific)
    const EVP_MD* GetEVPMD(const std::string& algorithm) const;
    Expected<std::monostate, common::DaemonErrorCode> ValidateAlgorithm(const std::string& algorithm) const;
    void CleanupStreamContext();
    void AllocateOutputBuffer(size_t size);
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_HASH_OPENSSL_HASH_HANDLER_HPP
