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

#include "score/crypto/daemon/provider/pkcs11/operations/hash/pkcs11_hash_executor.hpp"
#include "score/crypto/daemon/provider/handler/operations/hash_handler_operations.hpp"
#include "score/crypto/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_module.hpp"

#include "score/crypto/daemon/common/daemon_error.hpp"
#include <string_view>

namespace score::crypto::daemon::provider::pkcs11
{

using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;
using score::crypto::daemon::common::DaemonErrorCode;

Pkcs11HashExecutor::Pkcs11HashExecutor(const Pkcs11Module& module) noexcept
    : m_module{module},
      m_functionList{module.GetFunctionList()},
      m_supportsMessageDigest{module.GetCapabilities().supportsMessageDigest}
{
}

bool Pkcs11HashExecutor::SupportsMessageDigest() const noexcept
{
    return m_supportsMessageDigest;
}

// static
Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11HashExecutor::ValidateStreamTransition(
    const common::OperationAction action,
    const StreamOperationState currentState,
    StreamOperationState& nextState) noexcept
{
    namespace ops = handler::hash_handler_operations;
    handler::handler_utils::StreamOperation op{};
    if (action == ops::HASH_INIT)
    {
        op = handler::handler_utils::StreamOperation::kInit;
    }
    else if (action == ops::HASH_UPDATE)
    {
        op = handler::handler_utils::StreamOperation::kUpdate;
    }
    else if (action == ops::HASH_FINALIZE)
    {
        op = handler::handler_utils::StreamOperation::kFinalize;
    }
    else
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidOperation);
    }
    const auto result = handler::handler_utils::ValidateStreamOperationSequence(currentState, op);
    if (!result.has_value())
    {
        return make_unexpected(result.error());
    }
    nextState = result.value();
    return std::monostate{};
}

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Pkcs11HashExecutor::Execute(
    Pkcs11HashExecutionContext& ctx,
    const common::OperationAction operationAction,
    RequestParameters& request,
    const StreamOperationState currentState,
    StreamOperationState& nextState) noexcept
{
    namespace ops = handler::hash_handler_operations;

    // --- Single-shot: no stream state transition needed ---
    if (operationAction == ops::HASH_SS)
    {
        if (currentState != StreamOperationState::IDLE)
        {
            return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kOperationInProgress);
        }
        nextState = StreamOperationState::IDLE;
        return ExecuteDigestSingleShot(ctx.session, ctx.mechanism, request);
    }

    // Reset operation: HASH_RESET
    if (operationAction == ops::HASH_RESET)
    {
        // TODO: Is this correct for the reset?
        Abort(ctx.session);
        // Reset();
        return {};
    }

    // --- GET_DIGEST_SIZE: handled without PKCS#11 calls ---
    if (operationAction == ops::HASH_GET_DIGEST_SIZE)
    {
        // Digest size is algorithm-dependent; handler resolves this before calling executor.
        // If we reach here, it means the handler delegates — return unsupported to let handler handle it.
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    // --- Streaming operations: validate state transition ---
    const auto sequenceResult = ValidateStreamTransition(operationAction, currentState, nextState);
    if (!sequenceResult.has_value())
    {
        return make_unexpected(sequenceResult.error());
    }

    // --- Dispatch to PKCS#11 call ---
    if (operationAction == ops::HASH_FINALIZE)
    {
        auto result = ExecuteDigestFinal(ctx.session, request);
        if (!result.has_value())
        {
            nextState = currentState;
        }
        return result;
    }

    const auto result = [&]() -> Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> {
        if (operationAction == ops::HASH_INIT)
            return ExecuteDigestInit(ctx.session, ctx.mechanism);
        if (operationAction == ops::HASH_UPDATE)
            return ExecuteDigestUpdate(ctx.session, request);
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidOperation);
    }();

    // Revert state on failure (caller should not advance)
    if (!result.has_value())
    {
        nextState = currentState;
    }

    return {};
}

// ============================================================================
// Private: PKCS#11 Digest Operations
// ============================================================================

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11HashExecutor::ExecuteDigestInit(
    const CK_SESSION_HANDLE session,
    CK_MECHANISM& mechanism) noexcept
{
    const CK_RV rv = m_functionList->C_DigestInit(session, &mechanism);
    if (rv != CKR_OK)
    {
        return make_unexpected(Pkcs11Module::MapErrorReturn(rv));
    }
    return std::monostate{};
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11HashExecutor::ExecuteDigestUpdate(
    const CK_SESSION_HANDLE session,
    RequestParameters& request) noexcept
{
    if (request.empty())
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientParameters);
    }

    auto* bufIn = std::get_if<common::VirtualMemoryBufferConst>(&request[0]);
    if (!bufIn || bufIn->data == nullptr || bufIn->size == 0)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
    }

    // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C API (C_DigestUpdate) requires non-const pPart.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    auto* data = const_cast<CK_BYTE_PTR>(static_cast<const CK_BYTE*>(bufIn->data));
    const CK_RV rv = m_functionList->C_DigestUpdate(session, data, static_cast<CK_ULONG>(bufIn->size));
    if (rv != CKR_OK)
    {
        return make_unexpected(Pkcs11Module::MapErrorReturn(rv));
    }
    return std::monostate{};
}

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Pkcs11HashExecutor::ExecuteDigestFinal(
    const CK_SESSION_HANDLE session,
    RequestParameters& request) noexcept
{
    // For PKCS11, the output buffer comes from the handler's internal buffer
    // passed via parameters
    if (request.empty())
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientParameters);
    }

    auto* bufInOut = std::get_if<common::VirtualMemoryBuffer>(&request[0]);
    if (!bufInOut || bufInOut->data == nullptr || bufInOut->size == 0)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
    }

    // TODO: The OpenSSL HashHandler as well as the general HashHandler operation does support an additional
    // final data chunk. Not sure if this shall / can be supported for PKCS#11

    auto digestLen = static_cast<CK_ULONG>(bufInOut->size);
    const CK_RV rv = m_functionList->C_DigestFinal(session, bufInOut->data, &digestLen);
    if (rv != CKR_OK)
    {
        return make_unexpected(Pkcs11Module::MapErrorReturn(rv));
    }

    // Update size to actual digest length and add to output
    ResponseParameters response;
    response.push_back(common::VirtualMemoryBufferConst{bufInOut->data, static_cast<std::size_t>(digestLen)});
    return response;
}

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11HashExecutor::ExecuteDigestSingleShot(const CK_SESSION_HANDLE session,
                                            CK_MECHANISM& mechanism,
                                            RequestParameters& request) noexcept
{
    if (request.empty())
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientParameters);
    }

    // Extract input buffer
    auto* inputBuf = std::get_if<common::VirtualMemoryBufferConst>(&request[0]);
    if (!inputBuf || inputBuf->data == nullptr || inputBuf->size == 0)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
    }

    // Extract output buffer parameters
    auto* outputBuf = std::get_if<common::VirtualMemoryBuffer>(&request[1]);
    if (!outputBuf || outputBuf->data == nullptr || outputBuf->size == 0)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
    }

    // For PKCS#11 v2.40: C_DigestInit + C_Digest (two-step single-shot)
    // For PKCS#11 v3.0+: C_MessageDigestInit + C_MessageDigest could be used
    //   when m_supportsMessageDigest is true, avoiding the active-operation
    //   slot on the session. Currently not dispatched because SoftHSM is v2.40.
    //   When a v3.0 token is available, add:
    //     if (m_supportsMessageDigest) { return ExecuteMessageDigest(session, mechanism, config); }

    // Defensively abort any leftover operation to ensure session is clean
    // (in case a previous operation on this session was not properly finalised).
    // Dispatch through the function list — not via direct C-linkage — so that
    // the call correctly targets the library that owns this session.
    Abort(session);

    const CK_RV initRv = m_functionList->C_DigestInit(session, &mechanism);
    if (initRv != CKR_OK)
    {
        return make_unexpected(Pkcs11Module::MapErrorReturn(initRv));
    }

    auto digestLen = static_cast<CK_ULONG>(outputBuf->size);
    // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C API (C_Digest) requires non-const pData.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    auto* inputData = const_cast<CK_BYTE_PTR>(static_cast<const CK_BYTE*>(inputBuf->data));
    const CK_RV digestRv = m_functionList->C_Digest(
        session, inputData, static_cast<CK_ULONG>(inputBuf->size), outputBuf->data, &digestLen);
    if (digestRv != CKR_OK)
    {
        return make_unexpected(Pkcs11Module::MapErrorReturn(digestRv));
    }

    // Update size to actual digest length and add to output
    ResponseParameters response;
    response.push_back(common::VirtualMemoryBufferConst{outputBuf->data, static_cast<std::size_t>(digestLen)});
    return response;
}

void Pkcs11HashExecutor::Abort(const CK_SESSION_HANDLE session) noexcept
{
    // Call C_DigestFinal with a dummy buffer to abort any active digest operation
    // and return the session to IDLE state.  Errors are intentionally ignored:
    // if no operation is active, C_DigestFinal returns CKR_OPERATION_NOT_INITIALIZED
    // which is harmless here.
    // Dispatch through the stored function list — never through a direct C-linkage
    // symbol — so that the call correctly targets the library that owns this session.
    std::uint8_t dummyBuf[64U]{0U};  // NOLINT(cppcoreguidelines-pro-bounds-array-init)
    CK_ULONG dummyLen = sizeof(dummyBuf);
    static_cast<void>(m_functionList->C_DigestFinal(session, dummyBuf, &dummyLen));
}

}  // namespace score::crypto::daemon::provider::pkcs11
