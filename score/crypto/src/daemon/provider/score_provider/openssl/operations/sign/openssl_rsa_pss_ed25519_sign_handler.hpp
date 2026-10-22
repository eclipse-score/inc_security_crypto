/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/
#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGN_OPENSSL_RSA_PSS_ED25519_SIGN_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGN_OPENSSL_RSA_PSS_ED25519_SIGN_HANDLER_HPP

#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/ecdsa_common.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/score_sign_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/sign/sign_executor.hpp"
#include "score/span.hpp"
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{
class OpenSslRsaPssEd25519SignHandler final : public operations::sign::ScoreSignHandler
{
  public:
    explicit OpenSslRsaPssEd25519SignHandler(std::unique_ptr<operations::sign::SignExecutor> executor,
                                             const common::AlgorithmId& algorithm);
    ~OpenSslRsaPssEd25519SignHandler() override;
    OpenSslRsaPssEd25519SignHandler(const OpenSslRsaPssEd25519SignHandler&) = delete;
    OpenSslRsaPssEd25519SignHandler& operator=(const OpenSslRsaPssEd25519SignHandler&) = delete;

    Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const ::score::crypto::daemon::provider::handler::InitializationParams&) override;
    Expected<std::monostate, common::DaemonErrorCode> Reset() override;
    std::size_t GetSignatureSize() const noexcept override;
    Expected<std::monostate, common::DaemonErrorCode> InitSign() override;
    Expected<std::monostate, common::DaemonErrorCode> UpdateSign(score::cpp::span<const std::uint8_t>) override;
    Expected<std::size_t, common::DaemonErrorCode> FinalizeSign(score::cpp::span<std::uint8_t>) override;
    Expected<std::size_t, common::DaemonErrorCode> SingleShotSign(score::cpp::span<const std::uint8_t>,
                                                                  score::cpp::span<std::uint8_t>) override;
    static bool IsAlgorithmSupported(const common::AlgorithmId&) noexcept;

  private:
    bool IsEd25519() const noexcept;
    Expected<std::size_t, common::DaemonErrorCode> ResolveBuffer(score::cpp::span<std::uint8_t>) const;

    ecdsa::Stream m_stream;
    std::vector<std::uint8_t> m_buffer;
    bool m_prehashed{false};
    static constexpr std::string_view LOG_PREFIX = "[OPENSSL_RSA_PSS_ED25519_SIGN_HANDLER]";
};
}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
#endif
