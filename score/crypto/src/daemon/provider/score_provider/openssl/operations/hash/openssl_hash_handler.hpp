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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_HASH_OPENSSL_HASH_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_HASH_OPENSSL_HASH_HANDLER_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/hash/hash_executor.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/hash/score_hash_handler.hpp"
#include <openssl/evp.h>

#include <cstddef>
#include <memory>
#include <string>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

class OpenSslHashHandler final
    : public ::score::crypto::daemon::provider::score_provider::operations::hash::ScoreHashHandler
{
  public:
    using Sptr = std::shared_ptr<OpenSslHashHandler>;
    using DigestUpdateFunction = int (*)(EVP_MD_CTX*, const void*, std::size_t);

    explicit OpenSslHashHandler(
        std::unique_ptr<::score::crypto::daemon::provider::score_provider::operations::hash::HashExecutor> executor,
        common::AlgorithmId algorithm,
        DigestUpdateFunction digestUpdate = &EVP_DigestUpdate);
    ~OpenSslHashHandler() override;

    // Handler interface overrides (OpenSSL-specific initialization and cleanup)
    Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const ::score::crypto::daemon::provider::handler::InitializationParams& init_params) override;
    Expected<std::monostate, common::DaemonErrorCode> Reset() override;

    // ScoreHashHandler typed method overrides (OpenSSL crypto implementation)
    Expected<std::monostate, common::DaemonErrorCode> InitHash() override;
    Expected<std::monostate, common::DaemonErrorCode> UpdateHash(
        score::cpp::span<const std::uint8_t> dataToHash) override;
    Expected<common::ResponseParameters, common::DaemonErrorCode> FinalizeHash(
        score::cpp::span<std::uint8_t> hashOutput) override;
    Expected<common::ResponseParameters, common::DaemonErrorCode> SingleShotHash(
        score::cpp::span<const std::uint8_t> dataToHash,
        score::cpp::span<std::uint8_t> outputHash) override;

    /// @brief Check if the given algorithm is supported by this handler.
    [[nodiscard]] static bool IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept;

  private:
    // OpenSSL-specific stream context management
    EVP_MD_CTX* mCurrentStreamContext;
    DigestUpdateFunction mDigestUpdate;

    // Helper methods (OpenSSL provider-specific)
    const EVP_MD* GetEVPMD(const std::string& algorithm) const;
    Expected<std::monostate, common::DaemonErrorCode> ValidateAlgorithm(const std::string& algorithm) const;
    void CleanupStreamContext();
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_HASH_OPENSSL_HASH_HANDLER_HPP
