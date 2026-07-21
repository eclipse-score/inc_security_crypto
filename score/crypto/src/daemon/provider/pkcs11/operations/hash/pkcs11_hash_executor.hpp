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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_HASH_EXECUTOR_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_HASH_EXECUTOR_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/hash/pkcs11_hash_context.hpp"

#include <pkcs11.h>
#include <variant>

namespace score::crypto::daemon::provider::pkcs11
{

class Pkcs11Module;
struct Pkcs11Capabilities;

/// @brief Executor (visitor) that translates generic operation IDs to PKCS#11 C_Digest* calls.
///
/// Owns no session state — receives the session handle and mechanism from the handler.
/// Reuses handler_utils::ValidateStreamOperationSequence for stream state management.
///
/// Version-aware dispatch:
///   - v2.40 (SoftHSM): uses C_DigestInit + C_Digest for single-shot
///   - v3.0+: uses C_MessageDigestInit + C_MessageDigest (when supportsMessageDigest is true)
///     This avoids occupying the session's active-operation slot for single-shot digests.
class Pkcs11HashExecutor final
{
  public:
    /// @brief Construct executor with reference to the PKCS#11 module.
    /// @param module Non-owning reference to the initialised Pkcs11Module.
    /// Capabilities are cached from the module at construction time.
    explicit Pkcs11HashExecutor(const Pkcs11Module& module) noexcept;

    ~Pkcs11HashExecutor() = default;

    Pkcs11HashExecutor(const Pkcs11HashExecutor&) = delete;
    Pkcs11HashExecutor& operator=(const Pkcs11HashExecutor&) = delete;
    Pkcs11HashExecutor(Pkcs11HashExecutor&&) noexcept = default;
    Pkcs11HashExecutor& operator=(Pkcs11HashExecutor&&) noexcept = default;

    // TODO: Consider reducing the number of parameters
    /// @brief Dispatch the operation to the corresponding C_Digest* call.
    /// @param ctx             Stable per-context parameters (session, mechanism, digest_size).
    /// @param operationAction The operation action (e.g., HASH_INIT, HASH_UPDATE, HASH_FINALIZE, HASH_SS).
    /// @param request         RequestParameters with parameters.
    /// @param currentState    Current streaming state (read/write).
    /// @param nextState       Output: next streaming state on success.
    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Execute(
        Pkcs11HashExecutionContext& ctx,
        common::OperationAction operationAction,
        common::RequestParameters& request,
        common::StreamOperationState currentState,
        common::StreamOperationState& nextState) noexcept;

    /// @brief Abort any active digest operation on the session by calling C_DigestFinal
    ///        with a dummy buffer, returning the session to IDLE state.
    ///
    /// All dispatch goes through the function list cached at construction — not
    /// through direct C-linkage symbols — so this correctly targets the library
    /// that owns the session.
    /// @note Safe to call when the session has no active operation (error is ignored).
    void Abort(CK_SESSION_HANDLE session) noexcept;

    /// @brief Query whether the underlying token supports v3.0 message-based digest.
    [[nodiscard]] bool SupportsMessageDigest() const noexcept;

  private:
    /// @brief Validate a streaming operation action against the current state and compute the next
    ///        state in one step, eliminating the intermediate string representation from call sites.
    ///
    /// Returns an error if the action is not a recognised streaming operation or if the
    /// current state does not permit the transition.
    [[nodiscard]] static Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ValidateStreamTransition(common::OperationAction action,
                             common::StreamOperationState currentState,
                             common::StreamOperationState& nextState) noexcept;

    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ExecuteDigestInit(
        CK_SESSION_HANDLE session,
        CK_MECHANISM& mechanism) noexcept;

    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ExecuteDigestUpdate(
        CK_SESSION_HANDLE session,
        common::RequestParameters& request) noexcept;

    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
    ExecuteDigestFinal(CK_SESSION_HANDLE session, common::RequestParameters& request) noexcept;

    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
    ExecuteDigestSingleShot(CK_SESSION_HANDLE session,
                            CK_MECHANISM& mechanism,
                            common::RequestParameters& request) noexcept;

    const Pkcs11Module& m_module;
    CK_FUNCTION_LIST* m_functionList;  ///< cached at construction from m_module.GetFunctionList()
    bool m_supportsMessageDigest;      ///< cached from Pkcs11Capabilities at construction
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_HASH_EXECUTOR_HPP
