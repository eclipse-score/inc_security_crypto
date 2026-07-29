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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGNATURE_OPENSSL_ECDSA_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGNATURE_OPENSSL_ECDSA_HANDLER_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/signature/score_signature_handler.hpp"
#include "score/crypto/src/daemon/provider/score_provider/operations/signature/signature_executor.hpp"

#include <openssl/evp.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <vector>

namespace score::crypto::daemon::provider::score_provider::openssl::handler
{

/// @brief OpenSSL ECDSA signature handler built on the EVP_DigestSign /
///        EVP_DigestVerify interface.
///
/// Supports ECDSA on P-256, P-384 and P-521 with the NIST-paired digest
/// (SHA-256 / SHA-384 / SHA-512), selectable through algorithm identifiers such
/// as "ECDSA-P256-SHA256". The digest is mandatory: a bare "ECDSA-P256" names
/// a key, not a signature scheme, and is rejected at context creation.
///
/// One class serves both directions: which one this context performs comes from
/// the OperationMode fixed at CTX_CREATE time. The bound key is a single
/// EVP_PKEY carrying the pair, so signing uses its private half and verification
/// its public half without needing two separate key resources.
///
/// @par Signature encoding
/// OpenSSL natively produces and consumes DER-encoded ECDSA-Sig-Value. This
/// handler converts to and from the fixed-length IEEE P1363 form r‖s at its
/// boundary so that signatures interoperate byte-for-byte with the PKCS#11
/// provider, which is natively P1363.
class OpenSslEcdsaHandler final
    : public ::score::crypto::daemon::provider::score_provider::operations::signature::ScoreSignatureHandler
{
  public:
    using Sptr = std::shared_ptr<OpenSslEcdsaHandler>;

    explicit OpenSslEcdsaHandler(std::unique_ptr<operations::signature::SignatureExecutor> executor,
                                 const common::AlgorithmId& algorithm);
    ~OpenSslEcdsaHandler() override;

    OpenSslEcdsaHandler(const OpenSslEcdsaHandler&) = delete;
    OpenSslEcdsaHandler& operator=(const OpenSslEcdsaHandler&) = delete;
    OpenSslEcdsaHandler(OpenSslEcdsaHandler&&) = delete;
    OpenSslEcdsaHandler& operator=(OpenSslEcdsaHandler&&) = delete;

    // -----------------------------------------------------------------------
    // Handler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
    InitializeContext(const ::score::crypto::daemon::provider::handler::InitializationParams& init_params) override;

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode> Reset()
        override;

    // -----------------------------------------------------------------------
    // ScoreSignatureHandler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
    InitSignature() override;

    [[nodiscard]] ::score::crypto::Expected<std::monostate, ::score::crypto::daemon::common::DaemonErrorCode>
    UpdateSignature(const common::RequestParameter& data) override;

    [[nodiscard]] ::score::crypto::Expected<std::size_t, ::score::crypto::daemon::common::DaemonErrorCode> FinalizeSign(
        score::cpp::span<std::uint8_t> signature) override;

    [[nodiscard]] ::score::crypto::Expected<bool, ::score::crypto::daemon::common::DaemonErrorCode> FinalizeVerify(
        const common::RequestParameter& signature) override;

    /// @brief Check if the given algorithm is supported by this handler.
    [[nodiscard]] static bool IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept;

  private:
    /// @brief Retrieve the bound key pair.
    /// @return nullptr when no key is bound or it is not an EC key.
    [[nodiscard]] EVP_PKEY* GetBoundPkey() const noexcept;

    /// @brief Free the message-digest context.
    void CleanupContext() noexcept;

    /// @brief Convert a DER ECDSA-Sig-Value into fixed-length r‖s.
    /// @param field_size Byte length of r and of s.
    [[nodiscard]] static ::score::crypto::Expected<common::OwnedBuffer,
                                                   ::score::crypto::daemon::common::DaemonErrorCode>
    DerToP1363(const std::uint8_t* der, std::size_t der_len, std::size_t field_size);

    /// @brief Convert fixed-length r‖s into a DER ECDSA-Sig-Value.
    [[nodiscard]] static ::score::crypto::Expected<common::OwnedBuffer,
                                                   ::score::crypto::daemon::common::DaemonErrorCode>
    P1363ToDer(const std::uint8_t* raw, std::size_t raw_len, std::size_t field_size);

    EVP_MD_CTX* m_md_ctx{nullptr};
    ::score::crypto::daemon::provider::handler::InitializationParams m_init_params;

    static constexpr std::string_view LOG_PREFIX = "[OPENSSL_ECDSA_HANDLER]";
};

}  // namespace score::crypto::daemon::provider::score_provider::openssl::handler

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_SCORE_PROVIDER_OPENSSL_OPERATIONS_SIGNATURE_OPENSSL_ECDSA_HANDLER_HPP
