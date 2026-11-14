/*******************************************************************************
 *
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
 *******************************************************************************
 */

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_CONTEXT_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_CONTEXT_HANDLER_HPP

#include "score/crypto/src/daemon/cert_management/context/verification/executor.hpp"
#include "score/crypto/src/daemon/cert_management/context/verification/session.hpp"
#include "score/crypto/src/daemon/common/context/handler_init_params.hpp"
#include "score/crypto/src/daemon/common/context/i_handler.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"

#include <memory>

namespace score::crypto::daemon::cert_management
{

/// @brief Handler for one CERT:VERIFICATION context.
///
/// The handler is created by CertVerificationContextFactory for each CTX_CREATE. It holds the verification session,
/// which is created when the identity is recorded by InitializeContext(), and forwards every operation to its executor.
/// Reset() clears the session and keeps the identity. Destroying the handler releases the trust-store reference of the
/// session.
class CertVerificationContextHandler final : public common::Handler
{
  public:
    /// @brief Construct the handler.
    /// @param executor Executor for this context. Must be non-null.
    /// @param services Collaborators of the session created at initialization.
    CertVerificationContextHandler(std::shared_ptr<const CertVerificationExecutor> executor,
                                   CertVerificationSession::Services services);

    /// @brief Record the caller identity and context node and create the session. Called once by the assembler.
    /// @param init_params Runtime context supplied at CTX_CREATE time.
    /// @return Success, or kInvalidOperation if the handler is already initialized.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> InitializeContext(
        const common::InitializationParams& init_params) override;

    /// @brief Execute one operation on behalf of the initialized context.
    /// @param operation_id Actor and action codes of the operation.
    /// @param request Operation parameters.
    /// @return The response parameters, kInvalidOperation if the context is not initialized, or the executor error.
    [[nodiscard]] score::crypto::Expected<common::ResponseParameters, common::DaemonErrorCode> Execute(
        const common::OperationIdentifier& operation_id,
        common::RequestParameters& request) override;

    /// @brief Clear the verification state of the session and release its trust-store reference. The identity is kept.
    /// @return Success.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> Reset() override;

  private:
    std::shared_ptr<const CertVerificationExecutor> m_executor;  ///< Executor for this context, never null.
    CertVerificationSession::Services m_services;                ///< Collaborators for the session.
    std::unique_ptr<CertVerificationSession> m_session;          ///< Created by InitializeContext(); null before.
    bool m_initialized{false};                                   ///< True once InitializeContext() succeeded.
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_CONTEXT_VERIFICATION_CONTEXT_HANDLER_HPP
