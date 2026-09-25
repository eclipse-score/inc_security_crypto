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

#include "score/crypto/src/daemon/provider/pkcs11/operations/hash/pkcs11_hash_executor.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/hash_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_module.hpp"

#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include <string_view>

namespace score::crypto::daemon::provider::pkcs11
{

using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;
using score::crypto::daemon::common::DaemonErrorCode;
using ::score::crypto::daemon::provider::handler::handler_utils::CheckAndGetSpan;
using ::score::crypto::daemon::provider::handler::handler_utils::ValidateParameterCount;

namespace
{

[[nodiscard]] constexpr bool IsRequestValidationError(const DaemonErrorCode error) noexcept
{
    return (error == DaemonErrorCode::kInsufficientParameters) || (error == DaemonErrorCode::kInvalidArgument) ||
           (error == DaemonErrorCode::kInvalidDataType) || (error == DaemonErrorCode::kInsufficientBufferSize);
}

}  // namespace

Pkcs11HashExecutor::Pkcs11HashExecutor(const Pkcs11Module& module) noexcept : m_functionList{module.GetFunctionList()}
{
}

Pkcs11HashExecutor::Pkcs11HashExecutor(CK_FUNCTION_LIST& function_list) noexcept : m_functionList{&function_list} {}

// static
Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11HashExecutor::ValidateStreamTransition(
    const common::OperationAction action,
    const StreamOperationState currentState,
    StreamOperationState& nextState) noexcept
{
    namespace ops = handler::hash_handler_operations;
    handler::handler_utils::StreamOperation streamOperation{};
    if (action == ops::HASH_INIT)
    {
        streamOperation = handler::handler_utils::StreamOperation::kInit;
    }
    else if (action == ops::HASH_UPDATE)
    {
        streamOperation = handler::handler_utils::StreamOperation::kUpdate;
    }
    else if (action == ops::HASH_FINALIZE)
    {
        streamOperation = handler::handler_utils::StreamOperation::kFinalize;
    }
    else
    {
        return make_unexpected(DaemonErrorCode::kInvalidOperation);
    }

    const auto result = handler::handler_utils::ValidateStreamOperationSequence(
        currentState, streamOperation, true, DaemonErrorCode::kStreamNotInitialized);
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
    nextState = currentState;

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
        const auto countResult = ValidateParameterCount(request, 0U);
        if (!countResult.has_value())
        {
            return make_unexpected(countResult.error());
        }
        const auto abortResult = Abort(ctx.session);
        if (!abortResult.has_value())
        {
            nextState = currentState;
            return make_unexpected(abortResult.error());
        }
        nextState = StreamOperationState::IDLE;
        return {};
    }

    // --- GET_DIGEST_SIZE: handled without PKCS#11 calls ---
    if (operationAction == ops::HASH_GET_DIGEST_SIZE)
    {
        // Digest size is algorithm-dependent; handler resolves this before calling executor.
        // If we reach here, it means the handler delegates — return unsupported to let handler handle it.
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
    }

    if (operationAction == ops::HASH_INIT)
    {
        const auto countResult = ValidateParameterCount(request, 0U);
        if (!countResult.has_value())
        {
            return make_unexpected(countResult.error());
        }
    }

    // --- Streaming operations: validate state transition ---
    const auto sequenceResult = ValidateStreamTransition(operationAction, currentState, nextState);
    if (!sequenceResult.has_value())
    {
        return make_unexpected(sequenceResult.error());
    }

    // PKCS#11 does not permit C_DigestInit while another digest operation is
    // active. Implement the public Init()-restarts-stream contract explicitly.
    const bool restartingStream = (operationAction == ops::HASH_INIT) && (currentState != StreamOperationState::IDLE);
    if (restartingStream)
    {
        const auto abortResult = Abort(ctx.session);
        if (!abortResult.has_value())
        {
            nextState = currentState;
            return make_unexpected(abortResult.error());
        }
    }

    // --- Dispatch to PKCS#11 call ---
    if (operationAction == ops::HASH_FINALIZE)
    {
        auto result = ExecuteDigestFinal(ctx.session, request);
        if (!result.has_value())
        {
            // Caller-side validation failures and an undersized output buffer do not
            // consume the token operation, so the caller may correct the request and retry.
            const auto error = result.error();
            if (IsRequestValidationError(error))
            {
                nextState = currentState;
            }
            else
            {
                // PKCS#11 does not guarantee that a digest operation remains active
                // after other errors. Normalize the token state before allowing reuse.
                const auto abortResult = Abort(ctx.session);
                nextState = abortResult.has_value() ? StreamOperationState::IDLE : currentState;
            }
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
        const auto error = result.error();
        if ((operationAction == ops::HASH_UPDATE) && !IsRequestValidationError(error))
        {
            const auto abortResult = Abort(ctx.session);
            nextState = abortResult.has_value() ? StreamOperationState::IDLE : currentState;
        }
        else if (restartingStream)
        {
            // The previous stream was successfully aborted, but the new
            // C_DigestInit failed. The session is therefore idle.
            nextState = StreamOperationState::IDLE;
        }
        else
        {
            nextState = currentState;
        }
        return make_unexpected(result.error());
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
    const auto countResult = ValidateParameterCount(request, 1U);
    if (!countResult.has_value())
    {
        return make_unexpected(countResult.error());
    }

    const auto inputSpan = CheckAndGetSpan<const uint8_t>(request[0], true);
    if (!inputSpan.has_value())
    {
        return make_unexpected(inputSpan.error());
    }

    CK_BYTE emptyInput{0U};
    // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C API (C_DigestUpdate) requires non-const pPart.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    auto* data = inputSpan.value().empty()
                     ? &emptyInput
                     : const_cast<CK_BYTE_PTR>(static_cast<const CK_BYTE*>(inputSpan.value().data()));
    const CK_RV rv = m_functionList->C_DigestUpdate(session, data, static_cast<CK_ULONG>(inputSpan.value().size()));
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
    const auto countResult = ValidateParameterCount(request, 1U);
    if (!countResult.has_value())
    {
        return make_unexpected(countResult.error());
    }

    const auto outputSpan = CheckAndGetSpan<uint8_t>(request[0]);
    if (!outputSpan.has_value())
    {
        return make_unexpected(outputSpan.error());
    }

    auto digestLen = static_cast<CK_ULONG>(outputSpan.value().size());
    const CK_RV rv = m_functionList->C_DigestFinal(session, outputSpan.value().data(), &digestLen);
    if (rv != CKR_OK)
    {
        return make_unexpected(Pkcs11Module::MapErrorReturn(rv));
    }

    ResponseParameters response;
    response.push_back(static_cast<std::uint64_t>(digestLen));
    return response;
}

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11HashExecutor::ExecuteDigestSingleShot(const CK_SESSION_HANDLE session,
                                            CK_MECHANISM& mechanism,
                                            RequestParameters& request) noexcept
{
    const auto countResult = ValidateParameterCount(request, 2U);
    if (!countResult.has_value())
    {
        return make_unexpected(countResult.error());
    }

    // Extract input buffer
    const auto inputSpan = CheckAndGetSpan<const uint8_t>(request[0], true);
    if (!inputSpan.has_value())
    {
        return make_unexpected(inputSpan.error());
    }

    // Extract output buffer parameters
    const auto outputSpan = CheckAndGetSpan<uint8_t>(request[1]);
    if (!outputSpan.has_value())
    {
        return make_unexpected(outputSpan.error());
    }

    // Defensively abort any leftover operation to ensure session is clean
    // (in case a previous operation on this session was not properly finalised).
    // Dispatch through the function list — not via direct C-linkage — so that
    // the call correctly targets the library that owns this session.
    const auto initialCleanupResult = Abort(session);
    if (!initialCleanupResult.has_value())
    {
        return make_unexpected(initialCleanupResult.error());
    }

    const CK_RV initRv = m_functionList->C_DigestInit(session, &mechanism);
    if (initRv != CKR_OK)
    {
        return make_unexpected(Pkcs11Module::MapErrorReturn(initRv));
    }

    auto digestLen = static_cast<CK_ULONG>(outputSpan.value().size());
    CK_BYTE emptyInput{0U};
    // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C API (C_Digest) requires non-const pData.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    auto* inputData = inputSpan.value().empty()
                          ? &emptyInput
                          : const_cast<CK_BYTE_PTR>(static_cast<const CK_BYTE*>(inputSpan.value().data()));
    const CK_RV digestRv = m_functionList->C_Digest(
        session, inputData, static_cast<CK_ULONG>(inputSpan.value().size()), outputSpan.value().data(), &digestLen);
    if (digestRv != CKR_OK)
    {
        // C_Digest may leave the operation active after a retryable error such
        // as CKR_BUFFER_TOO_SMALL. Single-shot is externally stateless, so
        // always restore the session to an idle state before returning.
        const auto cleanupResult = Abort(session);
        if (!cleanupResult.has_value())
        {
            return make_unexpected(cleanupResult.error());
        }
        return make_unexpected(Pkcs11Module::MapErrorReturn(digestRv));
    }

    ResponseParameters response;
    response.push_back(static_cast<std::uint64_t>(digestLen));
    return response;
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11HashExecutor::Abort(
    const CK_SESSION_HANDLE session) noexcept
{
    // Call C_DigestFinal with a dummy buffer to abort any active digest operation
    // and return the session to IDLE state. If no operation is active,
    // C_DigestFinal returns CKR_OPERATION_NOT_INITIALIZED, which is also success
    // from the cleanup caller's perspective.
    // Dispatch through the stored function list — never through a direct C-linkage
    // symbol — so that the call correctly targets the library that owns this session.
    std::uint8_t dummyBuf[64U]{0U};  // NOLINT(cppcoreguidelines-pro-bounds-array-init)
    CK_ULONG dummyLen = sizeof(dummyBuf);
    const CK_RV rv = m_functionList->C_DigestFinal(session, dummyBuf, &dummyLen);
    if ((rv == CKR_OK) || (rv == CKR_OPERATION_NOT_INITIALIZED))
    {
        return std::monostate{};
    }
    return make_unexpected(Pkcs11Module::MapErrorReturn(rv));
}

}  // namespace score::crypto::daemon::provider::pkcs11
