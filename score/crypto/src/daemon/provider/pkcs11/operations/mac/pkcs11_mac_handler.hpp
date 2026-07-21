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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_MAC_HANDLER_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_MAC_HANDLER_HPP

#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/provider/handler/i_handler.hpp"
#include "score/crypto/daemon/provider/handler/operations/mac_handler_operations.hpp"
#include "score/crypto/daemon/provider/pkcs11/key_management/pkcs11_key_store.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/mac/pkcs11_mac_context.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/mac/pkcs11_mac_executor.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_module.hpp"

#include <cryptoki.h>
#include <pkcs11.h>

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{

// Forward declarations
class Pkcs11Provider;

/// @brief PKCS#11 MAC handler using C_Sign* / C_Verify* operations.
///
/// All operations are dispatched to Pkcs11MacExecutor which calls the PKCS#11 C API directly.
/// Supports HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 and can be extended for other PKCS#11
/// MAC mechanisms without changes to callers.
///
/// Operation mode (OperationMode::kGenerate vs kVerify) is selected at InitializeContext()
/// time:  kGenerate uses C_Sign*, kVerify uses C_Verify* — allowing keys with
/// CKA_SIGN=false / CKA_VERIFY=true on the verify path.
///
/// Key binding is handled inside InitializeContext(): the daemon opaque_id is resolved
/// to CK_OBJECT_HANDLE via Pkcs11KeyStore; C_SignInit / C_VerifyInit are deferred to the
/// executor and called lazily before the first data operation.
///
/// Each instance owns a dedicated PKCS#11 session (ReadOnly/User tier) acquired
/// at construction via the provider's session pool.  The session is returned on
/// destruction, mirroring the Pkcs11HashHandler lifecycle.
class Pkcs11MacHandler final : public handler::Handler
{
  public:
    /// @brief Session / auth requirements for MAC operations.
    ///
    /// MAC operations require a logged-in session because the key is CKA_SENSITIVE.
    static constexpr Pkcs11HandlerRequirements kRequirements{Pkcs11SessionType::ReadOnly, Pkcs11TokenAuthState::User};

    /// @brief Construct handler.
    /// @param executor     Unique pointer to MAC executor for PKCS#11 operations.
    /// @param module       Reference to the initialised PKCS#11 module (non-owning).
    /// @param session      Session acquired from the provider pool.
    /// @param algorithm    Algorithm ID (e.g. "HMAC-SHA256").
    /// @param provider     Non-owning pointer to parent provider (for session release on destruction).
    explicit Pkcs11MacHandler(std::unique_ptr<Pkcs11MacExecutor> executor,
                              const Pkcs11Module& module,
                              CK_SESSION_HANDLE session,
                              const common::AlgorithmId& algorithm,
                              Pkcs11Provider* provider);

    ~Pkcs11MacHandler() override;

    Pkcs11MacHandler(const Pkcs11MacHandler&) = delete;
    Pkcs11MacHandler& operator=(const Pkcs11MacHandler&) = delete;
    Pkcs11MacHandler(Pkcs11MacHandler&&) = delete;
    Pkcs11MacHandler& operator=(Pkcs11MacHandler&&) = delete;

    // -----------------------------------------------------------------------
    // Handler interface
    // -----------------------------------------------------------------------

    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    InitializeContext(const handler::InitializationParams& init_params) override;

    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
    Execute(const common::OperationIdentifier& operationId, common::RequestParameters& request) override;

    [[nodiscard]] score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Reset()
        override;

    /// @brief Returns static handler configuration for registration in the factory.
    /// @brief Check if the given algorithm is supported by this handler.
    [[nodiscard]] static bool IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept;

  private:
    /// @brief Map algorithm ID → CK_MECHANISM_TYPE for HMAC.
    [[nodiscard]] static CK_MECHANISM_TYPE MapAlgorithm(std::string_view algorithm) noexcept;

    /// @brief MAC output size for the active algorithm (used internally).
    [[nodiscard]] std::size_t GetMacSize() const noexcept;

    std::unique_ptr<Pkcs11MacExecutor> m_executor;
    const Pkcs11Module& m_module;
    CK_SESSION_HANDLE m_session;      ///< handler's own session (used for token keys)
    Pkcs11Provider* m_provider;       ///< non-owning; for ReleaseSession
    Pkcs11MacExecutionContext m_ctx;  ///< stable per-context parameters for executor
    /// Session actually used for C_Sign* calls.  For session-object keys this is
    /// the creating session (from ResolvedKey); for token keys it is m_session.
    CK_SESSION_HANDLE m_op_session{CK_INVALID_HANDLE};
    /// Holds the per-key mutex lock while a session-object key is bound.  Empty
    /// for token keys.  Released (and re-acquired) on Reset().
    Pkcs11KeyStore::ResolvedKey m_resolved_key;
    common::AlgorithmId m_algorithm;
    common::StreamOperationState m_state{common::StreamOperationState::IDLE};
    handler::InitializationParams m_init_params;  ///< saved for Reset()

    static constexpr std::string_view LOG_PREFIX = "[PKCS11_MAC_HANDLER]";
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_MAC_HANDLER_HPP
