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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_MAC_EXECUTOR_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_MAC_EXECUTOR_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/provider/pkcs11/operations/mac/pkcs11_mac_context.hpp"
#include "score/mw/crypto/api/common/types.hpp"  // OperationMode

#ifdef USE_RUST_PKCS11
#include <pkcs11.h>
#else
#include <cryptoki.h>
#endif

#include <cstddef>

namespace score::crypto::daemon::provider::pkcs11
{

class Pkcs11Module;

/// @brief Executor (visitor) that translates generic MAC operation IDs to
///        PKCS#11 C_Sign* / C_Verify* calls.
///
/// ### Operation mapping
///   MAC_INIT    → C_SignInit  (eagerly, moves to STREAM_ACTIVE)
///   MAC_UPDATE  → C_SignUpdate
///   MAC_FINALIZE → C_SignFinal  (returns MAC bytes)
///   MAC_VERIFY  → C_SignFinal  + constant-time compare with expected tag
///   MAC_SS      → C_SignInit + C_SignUpdate + C_SignFinal (single-shot)
///
/// ### Key usage and verify path
///   The current streaming verify path (Init → Update → Verify) feeds data via
///   C_Sign* and finalises with C_SignFinal, then compares. This requires
///   CKA_SIGN=true on the key.
///
///   PKCS#11 also provides symmetric C_Verify* APIs (C_VerifyInit /
///   C_VerifyUpdate / C_VerifyFinal) that require only CKA_VERIFY=true and
///   avoid materialising the computed tag.  Full use of C_Verify* for the
///   streaming path would require knowing at MAC_INIT time whether the
///   operation will end with MAC_FINALIZE or MAC_VERIFY — which in turn requires
///   either a dual-context approach or deferred init.
///
///   ExecuteVerifyInit / ExecuteVerifyFinal are provided as first-class
///   wrappers for the direct-verify (STREAM_INITIALIZED → MAC_VERIFY) path and
///   future dual-context support.
///
/// ### C_SignInit placement
///   C_SignInit is NOT called in InitializeContext(); it is deferred to the
///   first MAC_UPDATE (or MAC_INIT if called explicitly).  All PKCS#11
///   dispatch lives inside this executor.
class Pkcs11MacExecutor final
{
  public:
    /// @brief Construct executor with a reference to the initialised PKCS#11 module.
    explicit Pkcs11MacExecutor(const Pkcs11Module& module) noexcept;

    ~Pkcs11MacExecutor() = default;

    Pkcs11MacExecutor(const Pkcs11MacExecutor&) = delete;
    Pkcs11MacExecutor& operator=(const Pkcs11MacExecutor&) = delete;
    Pkcs11MacExecutor(Pkcs11MacExecutor&&) noexcept = default;
    Pkcs11MacExecutor& operator=(Pkcs11MacExecutor&&) noexcept = default;

    /// @brief Dispatch a MAC operation to the corresponding C_Sign* or C_Verify* call(s).
    ///
    /// @param ctx              Stable per-context parameters (session, mechanism, key, mac_size, mode).
    /// @param operationAction  MAC operation action (MAC_UPDATE, MAC_FINALIZE, etc.).
    /// @param request          Operation config with input/output parameters.
    /// @param currentState     Current streaming state of the handler.
    /// @param nextState        Output: the state the handler should transition to on success.
    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Execute(
        Pkcs11MacExecutionContext& ctx,
        common::OperationAction operationAction,
        common::RequestParameters& request,
        common::StreamOperationState currentState,
        common::StreamOperationState& nextState) noexcept;

    /// @brief Abort any active sign or verify operation.
    ///
    /// For the sign path (kGenerate), calls C_SignFinal with a dummy buffer.
    /// For the verify path (kVerify), calls C_VerifyFinal with a dummy tag.
    /// Safe to call when no operation is active (error ignored).
    void Abort(CK_SESSION_HANDLE session, score::mw::crypto::OperationMode operation_mode) noexcept;

  private:
    /// @brief Validate a streaming action against the current state.
    [[nodiscard]] static Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ValidateStreamTransition(common::OperationAction action,
                             common::StreamOperationState currentState,
                             common::StreamOperationState& nextState) noexcept;

    /// @brief Call C_SignInit or C_VerifyInit depending on use_verify.
    ///        Calls C_SignInit when STREAM_INITIALIZED (deferred init from InitializeContext);
    ///        no-op when STREAM_ACTIVE (already initialised via MAC_INIT).
    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> EnsureInitialized(
        CK_SESSION_HANDLE session,
        CK_MECHANISM& mechanism,
        CK_OBJECT_HANDLE key_object,
        bool use_verify,
        common::StreamOperationState currentState) noexcept;

    // --- Per-action dispatch helpers (called from Execute) ---------------------

    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> HandleInit(
        Pkcs11MacExecutionContext& ctx,
        bool use_verify,
        common::StreamOperationState currentState,
        common::StreamOperationState& nextState) noexcept;

    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> HandleUpdate(
        Pkcs11MacExecutionContext& ctx,
        bool use_verify,
        common::StreamOperationState currentState,
        common::StreamOperationState& nextState,
        common::RequestParameters& request) noexcept;

    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> HandleFinal(
        Pkcs11MacExecutionContext& ctx,
        common::StreamOperationState currentState,
        common::StreamOperationState& nextState,
        common::RequestParameters& request) noexcept;

    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> HandleVerify(
        Pkcs11MacExecutionContext& ctx,
        bool use_verify,
        common::StreamOperationState currentState,
        common::StreamOperationState& nextState,
        common::RequestParameters& request) noexcept;

    /// @brief Call C_SignInit(session, mechanism, key_object).
    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ExecuteSignInit(CK_SESSION_HANDLE session, CK_MECHANISM& mechanism, CK_OBJECT_HANDLE key_object) noexcept;

    /// @brief Call C_SignUpdate with data from request[0].
    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ExecuteSignUpdate(
        CK_SESSION_HANDLE session,
        common::RequestParameters& request) noexcept;

    /// @brief Call C_SignFinal, writing output to request[0].
    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
    ExecuteSignFinal(CK_SESSION_HANDLE session, std::size_t mac_size, common::RequestParameters& request) noexcept;

    /// @brief Perform a complete single-shot sign: C_SignInit + C_SignUpdate + C_SignFinal.
    ///        Data buffer in request[0], output in request[1].
    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
    ExecuteSignSingleShot(CK_SESSION_HANDLE session,
                          CK_MECHANISM& mechanism,
                          CK_OBJECT_HANDLE key_object,
                          std::size_t mac_size,
                          common::RequestParameters& request) noexcept;

    /// @brief Compute MAC over streamed data and compare with expected tag (constant-time).
    ///        MAC_VERIFY always receives exactly one parameter: the expected tag.
    ///        When need_init is true (STREAM_INITIALIZED), C_SignInit is called first
    ///        (HMAC of empty data); when false (STREAM_ACTIVE), data was already
    ///        fed via C_SignUpdate — this call finalises and compares.
    ///
    ///        NOTE: requires CKA_SIGN=true.  For keys with CKA_SIGN=false /
    ///        CKA_VERIFY=true use ExecuteVerifyFinal() after a C_VerifyInit +
    ///        C_VerifyUpdate chain.  See TODO in pkcs11_mac_executor.cpp.
    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
    ExecuteSignVerify(CK_SESSION_HANDLE session,
                      CK_MECHANISM& mechanism,
                      CK_OBJECT_HANDLE key_object,
                      std::size_t mac_size,
                      bool need_init,
                      common::RequestParameters& request) noexcept;

    /// @brief Call C_VerifyInit(session, mechanism, key_object).
    ///        Use when the key has CKA_VERIFY=true.
    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ExecuteVerifyInit(CK_SESSION_HANDLE session, CK_MECHANISM& mechanism, CK_OBJECT_HANDLE key_object) noexcept;

    /// @brief Call C_VerifyUpdate with data from request[0].
    ///        Symmetric counterpart of ExecuteSignUpdate for the verify path.
    [[nodiscard]] Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> ExecuteVerifyUpdate(
        CK_SESSION_HANDLE session,
        common::RequestParameters& request) noexcept;

    /// @brief Call C_VerifyFinal with the expected tag.
    ///        Returns ResponseParameters{uint64: 1=match, 0=mismatch}.
    ///        Must be preceded by ExecuteVerifyInit + zero or more ExecuteVerifyUpdate calls.
    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
    ExecuteVerifyFinal(CK_SESSION_HANDLE session, const uint8_t* expected_tag, std::size_t tag_len) noexcept;

    /// @brief Single-shot verify: C_VerifyInit + C_VerifyUpdate + C_VerifyFinal.
    ///        Symmetric counterpart of ExecuteSignSingleShot for keys with CKA_VERIFY=true.
    ///        Data in request[0], expected tag in request[1].
    [[nodiscard]] Expected<common::ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
    ExecuteVerifySingleShot(CK_SESSION_HANDLE session,
                            CK_MECHANISM& mechanism,
                            CK_OBJECT_HANDLE key_object,
                            std::size_t mac_size,
                            common::RequestParameters& request) noexcept;

    const Pkcs11Module& m_module;
    CK_FUNCTION_LIST* m_functionList;
};

}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PKCS11_MAC_EXECUTOR_HPP
