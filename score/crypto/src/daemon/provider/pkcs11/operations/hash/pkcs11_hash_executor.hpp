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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_OPERATIONS_HASH_PKCS11_HASH_EXECUTOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_OPERATIONS_HASH_PKCS11_HASH_EXECUTOR_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/operations/hash/pkcs11_hash_context.hpp"

#include <pkcs11.h>
#include <variant>

namespace score::crypto::daemon::provider::pkcs11
{

class Pkcs11Module;

/// @brief Executor (visitor) that translates generic operation IDs to PKCS#11 C_Digest* calls.
///
/// Owns no session state — receives the session handle and mechanism from the handler.
/// Reuses handler_utils::ValidateStreamOperationSequence for stream state management.
/// Single-shot hashing uses the PKCS#11 v2.40-compatible C_DigestInit + C_Digest sequence.
class Pkcs11HashExecutor final
{
  public:
    /// @brief Construct executor with reference to the PKCS#11 module.
    /// @param module Non-owning reference to the initialised Pkcs11Module.
    explicit Pkcs11HashExecutor(const Pkcs11Module& module) noexcept;

    /// @brief Construct executor from an injected PKCS#11 dispatch table.
    /// @param function_list Non-owning reference to a function list that outlives this executor.
    ///
    /// This overload provides a deterministic seam for testing provider error handling without
    /// requiring a physical token or modifying a process-global PKCS#11 function list.
    explicit Pkcs11HashExecutor(CK_FUNCTION_LIST& function_list) noexcept;

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
    /// @return Success when cleanup completed or no digest operation was active; otherwise
    ///         the mapped provider error.
    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Abort(
        CK_SESSION_HANDLE session) noexcept;

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

    CK_FUNCTION_LIST* m_functionList;  ///< Non-owning PKCS#11 dispatch table.
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_OPERATIONS_HASH_PKCS11_HASH_EXECUTOR_HPP
