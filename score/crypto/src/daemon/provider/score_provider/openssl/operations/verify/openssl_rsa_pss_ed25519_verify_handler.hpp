/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/
#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_VERIFY_OPENSSL_RSA_PSS_ED25519_VERIFY_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_VERIFY_OPENSSL_RSA_PSS_ED25519_VERIFY_HANDLER_HPP
#include "score/crypto/src/daemon/provider/score_provider/openssl/detail/ecdsa_common.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/score_verify_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/verify/verify_executor.hpp"
#include "score/span.hpp"
#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>
namespace score::crypto::daemon::provider::score_provider::openssl::handler
{
class OpenSslRsaPssEd25519VerifyHandler final : public operations::verify::ScoreVerifyHandler
{
  public:
    explicit OpenSslRsaPssEd25519VerifyHandler(std::unique_ptr<operations::verify::VerifyExecutor> executor,
                                               const common::AlgorithmId& algorithm);
    ~OpenSslRsaPssEd25519VerifyHandler() override;
    OpenSslRsaPssEd25519VerifyHandler(const OpenSslRsaPssEd25519VerifyHandler&) = delete;
    OpenSslRsaPssEd25519VerifyHandler& operator=(const OpenSslRsaPssEd25519VerifyHandler&) = delete;
    Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const ::score::crypto::daemon::provider::handler::InitializationParams&) override;
    Expected<std::monostate, common::DaemonErrorCode> Reset() override;
    std::size_t GetSignatureSize() const noexcept override;
    Expected<std::monostate, common::DaemonErrorCode> InitVerify() override;
    Expected<std::monostate, common::DaemonErrorCode> UpdateVerify(score::cpp::span<const std::uint8_t>) override;
    Expected<bool, common::DaemonErrorCode> FinalizeVerify(score::cpp::span<const std::uint8_t>) override;
    Expected<bool, common::DaemonErrorCode> SingleShotVerify(score::cpp::span<const std::uint8_t>,
                                                             score::cpp::span<const std::uint8_t>) override;
    static bool IsAlgorithmSupported(const common::AlgorithmId&) noexcept;

  private:
    bool IsEd25519() const noexcept;
    Expected<std::monostate, common::DaemonErrorCode> ConfigureRsaPss();
    Expected<std::monostate, common::DaemonErrorCode> CheckSignature(score::cpp::span<const std::uint8_t>) const;
    ecdsa::Stream m_stream;
    std::vector<std::uint8_t> m_buffer;
    bool m_prehashed{false};
    static constexpr std::string_view LOG_PREFIX = "[OPENSSL_RSA_PSS_ED25519_VERIFY_HANDLER]";
};
}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler
#endif
