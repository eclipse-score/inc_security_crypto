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

#include "score/crypto/daemon/provider/pkcs11/operations/mac/pkcs11_mac_executor.hpp"
#include "score/crypto/daemon/provider/handler/operations/mac_handler_operations.hpp"
#include "score/crypto/daemon/provider/handler/src/handler_utils.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/mw/crypto/api/common/types.hpp"

#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/mw/log/logging.h"

#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{

using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;
using score::crypto::daemon::common::DaemonErrorCode;

static constexpr std::string_view LOG_PREFIX = "[PKCS11_MAC_EXECUTOR]";

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

Pkcs11MacExecutor::Pkcs11MacExecutor(const Pkcs11Module& module) noexcept
    : m_module{module}, m_functionList{module.GetFunctionList()}
{
}

// ---------------------------------------------------------------------------
// Public entry point
// ---------------------------------------------------------------------------

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::Execute(
    Pkcs11MacExecutionContext& ctx,
    common::OperationAction operationAction,
    RequestParameters& request,
    StreamOperationState currentState,
    StreamOperationState& nextState) noexcept
{
    namespace ops = handler::mac_handler_operations;
    const bool use_verify = (ctx.operation_mode == score::mw::crypto::OperationMode::kVerify);

    if (operationAction == ops::MAC_SS)
    {
        if (currentState != StreamOperationState::STREAM_INITIALIZED)
        {
            return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kOperationInProgress);
        }
        nextState = StreamOperationState::IDLE;
        return use_verify ? ExecuteVerifySingleShot(ctx.session, ctx.mechanism, ctx.key_object, ctx.mac_size, request)
                          : ExecuteSignSingleShot(ctx.session, ctx.mechanism, ctx.key_object, ctx.mac_size, request);
    }
    if (operationAction == ops::MAC_INIT)
    {
        return HandleInit(ctx, use_verify, currentState, nextState);
    }
    if (operationAction == ops::MAC_UPDATE)
    {
        return HandleUpdate(ctx, use_verify, currentState, nextState, request);
    }
    if (operationAction == ops::MAC_FINALIZE)
    {
        return HandleFinal(ctx, currentState, nextState, request);
    }
    if (operationAction == ops::MAC_VERIFY)
    {
        return HandleVerify(ctx, use_verify, currentState, nextState, request);
    }

    return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidOperation);
}

// ---------------------------------------------------------------------------
// Per-action helpers
// ---------------------------------------------------------------------------

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::EnsureInitialized(
    CK_SESSION_HANDLE session,
    CK_MECHANISM& mechanism,
    CK_OBJECT_HANDLE key_object,
    bool use_verify,
    StreamOperationState currentState) noexcept
{
    if (currentState != StreamOperationState::STREAM_INITIALIZED)
    {
        return std::monostate{};  // already initialised via MAC_INIT
    }
    return use_verify ? ExecuteVerifyInit(session, mechanism, key_object)
                      : ExecuteSignInit(session, mechanism, key_object);
}

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::HandleInit(
    Pkcs11MacExecutionContext& ctx,
    bool use_verify,
    StreamOperationState currentState,
    StreamOperationState& nextState) noexcept
{
    if (currentState == StreamOperationState::STREAM_ACTIVE)
    {
        Abort(ctx.session, ctx.operation_mode);
    }
    auto init_res = use_verify ? ExecuteVerifyInit(ctx.session, ctx.mechanism, ctx.key_object)
                               : ExecuteSignInit(ctx.session, ctx.mechanism, ctx.key_object);
    if (!init_res.has_value())
    {
        nextState = currentState;
        return make_unexpected(init_res.error());
    }
    nextState = StreamOperationState::STREAM_ACTIVE;
    return ResponseParameters{};
}

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::HandleUpdate(
    Pkcs11MacExecutionContext& ctx,
    bool use_verify,
    StreamOperationState currentState,
    StreamOperationState& nextState,
    RequestParameters& request) noexcept
{
    const auto validation =
        ValidateStreamTransition(handler::mac_handler_operations::MAC_UPDATE, currentState, nextState);
    if (!validation.has_value())
    {
        return make_unexpected(validation.error());
    }
    auto init_res = EnsureInitialized(ctx.session, ctx.mechanism, ctx.key_object, use_verify, currentState);
    if (!init_res.has_value())
    {
        nextState = currentState;
        return make_unexpected(init_res.error());
    }
    auto result = use_verify ? ExecuteVerifyUpdate(ctx.session, request) : ExecuteSignUpdate(ctx.session, request);
    if (!result.has_value())
    {
        nextState = currentState;
        return make_unexpected(result.error());
    }
    return ResponseParameters{};
}

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::HandleFinal(
    Pkcs11MacExecutionContext& ctx,
    StreamOperationState currentState,
    StreamOperationState& nextState,
    RequestParameters& request) noexcept
{
    // MAC_FINALIZE produces tag bytes — only valid on the sign (kGenerate) path.
    // The verify path (kVerify) has no equivalent; use MAC_VERIFY instead.
    if (ctx.operation_mode == score::mw::crypto::OperationMode::kVerify)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidOperation);
    }
    const auto validation =
        ValidateStreamTransition(handler::mac_handler_operations::MAC_FINALIZE, currentState, nextState);
    if (!validation.has_value())
    {
        return make_unexpected(validation.error());
    }
    auto result = ExecuteSignFinal(ctx.session, ctx.mac_size, request);
    if (!result.has_value())
    {
        nextState = currentState;
    }
    return result;
}

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::HandleVerify(
    Pkcs11MacExecutionContext& ctx,
    bool use_verify,
    StreamOperationState currentState,
    StreamOperationState& nextState,
    RequestParameters& request) noexcept
{
    if (currentState == StreamOperationState::IDLE)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kStreamNotInitialized);
    }
    nextState = StreamOperationState::IDLE;

    if (use_verify)
    {
        // C_Verify* path: perform deferred init if MAC_INIT was skipped, then finalise.
        if (request.empty())
        {
            return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientParameters);
        }
        const uint8_t* expected_tag{nullptr};
        std::size_t tag_len{0U};
        const auto e = handler::handler_utils::ExtractBufferData(request[0], expected_tag, tag_len);
        if (!e.has_value())
        {
            return make_unexpected(e.error());
        }
        auto init_res = EnsureInitialized(ctx.session, ctx.mechanism, ctx.key_object, true, currentState);
        if (!init_res.has_value())
        {
            return make_unexpected(init_res.error());
        }
        return ExecuteVerifyFinal(ctx.session, expected_tag, tag_len);
    }

    // C_Sign* path: compute tag via C_SignFinal then constant-time compare.
    const bool need_init = (currentState == StreamOperationState::STREAM_INITIALIZED);
    return ExecuteSignVerify(ctx.session, ctx.mechanism, ctx.key_object, ctx.mac_size, need_init, request);
}

// ---------------------------------------------------------------------------
// Abort
// ---------------------------------------------------------------------------

void Pkcs11MacExecutor::Abort(CK_SESSION_HANDLE session, score::mw::crypto::OperationMode operation_mode) noexcept
{
    if (m_functionList == nullptr)
    {
        return;
    }

    if (operation_mode == score::mw::crypto::OperationMode::kVerify)
    {
        // Abort an active C_Verify* operation by calling C_VerifyFinal with a dummy tag.
        // C_VerifyFinal terminates the active operation regardless of whether the tag
        // matches; CKR_SIGNATURE_INVALID or CKR_OK are both acceptable — the goal is
        // to return the session to IDLE state.
        constexpr CK_ULONG kDummyTagLen{64U};
        CK_BYTE dummy_tag[kDummyTagLen]{};
        (void)m_functionList->C_VerifyFinal(session, dummy_tag, kDummyTagLen);
        return;
    }

    // Abort an active C_Sign* operation by calling C_SignFinal with a real output buffer
    // and discarding the result.  See original Abort() comment for rationale.
    constexpr CK_ULONG kMaxHmacOutputBytes{64U};
    CK_BYTE output[kMaxHmacOutputBytes]{};
    CK_ULONG sig_len{kMaxHmacOutputBytes};
    (void)m_functionList->C_SignFinal(session, output, &sig_len);
}

// ---------------------------------------------------------------------------
// State-machine helper
// ---------------------------------------------------------------------------

// static
Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::ValidateStreamTransition(
    common::OperationAction action,
    StreamOperationState currentState,
    StreamOperationState& nextState) noexcept
{
    namespace ops = handler::mac_handler_operations;
    handler::handler_utils::StreamOperation op{};
    if (action == ops::MAC_UPDATE)
    {
        op = handler::handler_utils::StreamOperation::kUpdate;
    }
    else if (action == ops::MAC_FINALIZE)
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

// ---------------------------------------------------------------------------
// PKCS#11 C API wrappers
// ---------------------------------------------------------------------------

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::ExecuteSignInit(
    CK_SESSION_HANDLE session,
    CK_MECHANISM& mechanism,
    CK_OBJECT_HANDLE key_object) noexcept
{
    const CK_RV rv = m_functionList->C_SignInit(session, &mechanism, key_object);
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "C_SignInit failed: rv=" << static_cast<unsigned long>(rv);
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAlgorithmInitializationFailed);
    }
    return std::monostate{};
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::ExecuteSignUpdate(
    CK_SESSION_HANDLE session,
    RequestParameters& request) noexcept
{
    if (request.empty())
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientParameters);
    }

    const uint8_t* data{nullptr};
    std::size_t data_len{0U};
    const auto extract = handler::handler_utils::ExtractBufferData(request[0], data, data_len);
    if (!extract.has_value())
    {
        return make_unexpected(extract.error());
    }

    // MISRA C++:2023 Rule 8.2.3 deviation — C_SignUpdate requires non-const pPart;
    // PKCS#11 spec guarantees it will not modify the data.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    CK_BYTE_PTR p = const_cast<CK_BYTE_PTR>(static_cast<const CK_BYTE*>(static_cast<const void*>(data)));
    const CK_RV rv = m_functionList->C_SignUpdate(session, p, static_cast<CK_ULONG>(data_len));
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "C_SignUpdate failed: rv=" << static_cast<unsigned long>(rv);
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    return std::monostate{};
}

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::ExecuteSignFinal(
    CK_SESSION_HANDLE session,
    std::size_t mac_size,
    RequestParameters& request) noexcept
{
    uint8_t* out_buf{nullptr};
    std::size_t out_buf_len{0U};
    // When no output buffer is provided by the caller, allocate internally and return an
    // OwnedBuffer - mirroring the OpenSSL OpenSslHmacHandler::FinalizeMac() allocation path.
    common::OwnedBuffer internal_buf;

    if (request.empty())
    {
        internal_buf.resize(mac_size);
        out_buf = internal_buf.data();
        out_buf_len = mac_size;
    }
    else
    {
        const auto extract = handler::handler_utils::ExtractOutputBufferData(request[0], out_buf, out_buf_len);
        if (!extract.has_value())
        {
            return make_unexpected(extract.error());
        }

        if (out_buf_len < mac_size)
        {
            return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
        }
    }

    CK_ULONG sig_len = static_cast<CK_ULONG>(out_buf_len);
    const CK_RV rv = m_functionList->C_SignFinal(session, static_cast<CK_BYTE_PTR>(out_buf), &sig_len);
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "C_SignFinal failed: rv=" << static_cast<unsigned long>(rv);
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    ResponseParameters response;
    if (!internal_buf.empty())
    {
        // Trim to actual output size and return as owned heap buffer.
        internal_buf.resize(static_cast<std::size_t>(sig_len));
        response.push_back(std::move(internal_buf));
    }
    else
    {
        response.push_back(static_cast<std::uint64_t>(sig_len));
    }
    return response;
}

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::ExecuteSignSingleShot(
    CK_SESSION_HANDLE session,
    CK_MECHANISM& mechanism,
    CK_OBJECT_HANDLE key_object,
    std::size_t mac_size,
    RequestParameters& request) noexcept
{
    if (request.size() < 2U)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientParameters);
    }

    const uint8_t* data{nullptr};
    std::size_t data_len{0U};
    auto e1 = handler::handler_utils::ExtractBufferData(request[0], data, data_len);
    if (!e1.has_value())
    {
        return make_unexpected(e1.error());
    }

    uint8_t* out_buf{nullptr};
    std::size_t out_buf_len{0U};
    auto e2 = handler::handler_utils::ExtractOutputBufferData(request[1], out_buf, out_buf_len);
    if (!e2.has_value())
    {
        return make_unexpected(e2.error());
    }

    if (out_buf_len < mac_size)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
    }

    auto init_res = ExecuteSignInit(session, mechanism, key_object);
    if (!init_res.has_value())
    {
        return make_unexpected(init_res.error());
    }

    // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C API (C_SignUpdate) requires non-const pPart.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    CK_BYTE_PTR p = const_cast<CK_BYTE_PTR>(static_cast<const CK_BYTE*>(static_cast<const void*>(data)));
    CK_RV rv = m_functionList->C_SignUpdate(session, p, static_cast<CK_ULONG>(data_len));
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX
                                   << "C_SignUpdate (single-shot) failed: rv=" << static_cast<unsigned long>(rv);
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    CK_ULONG sig_len = static_cast<CK_ULONG>(out_buf_len);
    rv = m_functionList->C_SignFinal(session, static_cast<CK_BYTE_PTR>(out_buf), &sig_len);
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX
                                   << "C_SignFinal (single-shot) failed: rv=" << static_cast<unsigned long>(rv);
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    ResponseParameters response;
    response.push_back(static_cast<std::uint64_t>(sig_len));
    return response;
}

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::ExecuteSignVerify(
    CK_SESSION_HANDLE session,
    CK_MECHANISM& mechanism,
    CK_OBJECT_HANDLE key_object,
    std::size_t mac_size,
    bool need_init,
    RequestParameters& request) noexcept
{
    // MAC_VERIFY always carries exactly one parameter: the expected tag.
    // The data to authenticate has already been submitted via MAC_UPDATE
    // (C_SignUpdate) calls when need_init is false (STREAM_ACTIVE).
    // When need_init is true (STREAM_INITIALIZED, i.e. MAC_INIT was skipped),
    // this executes a verify of the empty message.
    if (request.empty())
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientParameters);
    }

    const uint8_t* expected_tag{nullptr};
    std::size_t tag_len{0U};
    const auto e = handler::handler_utils::ExtractBufferData(request[0], expected_tag, tag_len);
    if (!e.has_value())
    {
        return make_unexpected(e.error());
    }

    if (tag_len != mac_size)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
    }

    if (need_init)
    {
        // Direct path (STREAM_INITIALIZED): C_SignInit was never called (MAC_INIT was skipped).
        // Initialise the sign context now; no data precedes this verify.
        auto init_res = ExecuteSignInit(session, mechanism, key_object);
        if (!init_res.has_value())
        {
            return make_unexpected(init_res.error());
        }
    }

    // Finalise the ongoing C_Sign* operation (all data was fed via C_SignUpdate)
    // and compare the computed tag against the expected one using constant-time.
    // This path is only reached when operation_mode == kGenerate (use_verify == false),
    // so the key is guaranteed to have CKA_SIGN=true; C_SignFinal will not fail on that basis.
    std::vector<uint8_t> computed(mac_size, 0U);
    CK_ULONG sig_len = static_cast<CK_ULONG>(mac_size);
    const CK_RV rv = m_functionList->C_SignFinal(session, computed.data(), &sig_len);
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX
                                   << "C_SignFinal (verify) failed: rv=" << static_cast<unsigned long>(rv);
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    // Constant-time comparison.
    uint8_t diff{0U};
    for (std::size_t i = 0U; i < static_cast<std::size_t>(sig_len); ++i)
    {
        diff |= computed[i] ^ expected_tag[i];
    }
    ResponseParameters response;
    response.push_back(diff == 0U);
    return response;
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::ExecuteVerifyInit(
    CK_SESSION_HANDLE session,
    CK_MECHANISM& mechanism,
    CK_OBJECT_HANDLE key_object) noexcept
{
    const CK_RV rv = m_functionList->C_VerifyInit(session, &mechanism, key_object);
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "C_VerifyInit failed: rv=" << static_cast<unsigned long>(rv);
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAlgorithmInitializationFailed);
    }
    return std::monostate{};
}

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::ExecuteVerifyUpdate(
    CK_SESSION_HANDLE session,
    RequestParameters& request) noexcept
{
    if (request.empty())
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientParameters);
    }

    const uint8_t* data{nullptr};
    std::size_t data_len{0U};
    const auto extract = handler::handler_utils::ExtractBufferData(request[0], data, data_len);
    if (!extract.has_value())
    {
        return make_unexpected(extract.error());
    }

    // MISRA C++:2023 Rule 8.2.3 deviation — C_VerifyUpdate requires non-const pPart;
    // PKCS#11 spec guarantees it will not modify the data.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    CK_BYTE_PTR p = const_cast<CK_BYTE_PTR>(static_cast<const CK_BYTE*>(static_cast<const void*>(data)));
    const CK_RV rv = m_functionList->C_VerifyUpdate(session, p, static_cast<CK_ULONG>(data_len));
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "C_VerifyUpdate failed: rv=" << static_cast<unsigned long>(rv);
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    return std::monostate{};
}

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::ExecuteVerifyFinal(
    CK_SESSION_HANDLE session,
    const uint8_t* expected_tag,
    std::size_t tag_len) noexcept
{
    // C_VerifyFinal takes the expected signature directly and returns CKR_OK
    // if it matches or CKR_SIGNATURE_INVALID otherwise — no tag materialisation
    // on the daemon side and no timing side-channel via heap comparison.
    // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C_VerifyFinal pSignature is non-const by spec.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    CK_BYTE_PTR tag_ptr = const_cast<CK_BYTE_PTR>(static_cast<const CK_BYTE*>(static_cast<const void*>(expected_tag)));
    const CK_RV rv = m_functionList->C_VerifyFinal(session, tag_ptr, static_cast<CK_ULONG>(tag_len));
    if (rv == CKR_SIGNATURE_INVALID)
    {
        ResponseParameters response;
        response.push_back(static_cast<std::uint64_t>(0U));  // mismatch
        return response;
    }
    if (rv != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "C_VerifyFinal failed: rv=" << static_cast<unsigned long>(rv);
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }
    ResponseParameters response;
    response.push_back(static_cast<std::uint64_t>(1U));  // match
    return response;
}

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacExecutor::ExecuteVerifySingleShot(
    CK_SESSION_HANDLE session,
    CK_MECHANISM& mechanism,
    CK_OBJECT_HANDLE key_object,
    std::size_t mac_size,
    RequestParameters& request) noexcept
{
    // Symmetric counterpart of ExecuteSignSingleShot for keys with CKA_VERIFY=true.
    // Uses C_VerifyInit + C_VerifyUpdate + C_VerifyFinal so the comparison is performed
    // inside the HSM — no tag materialisation on the daemon side.
    if (request.size() < 2U)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientParameters);
    }

    const uint8_t* data{nullptr};
    std::size_t data_len{0U};
    const auto e1 = handler::handler_utils::ExtractBufferData(request[0], data, data_len);
    if (!e1.has_value())
    {
        return make_unexpected(e1.error());
    }

    const uint8_t* expected_tag{nullptr};
    std::size_t tag_len{0U};
    const auto e2 = handler::handler_utils::ExtractBufferData(request[1], expected_tag, tag_len);
    if (!e2.has_value())
    {
        return make_unexpected(e2.error());
    }

    if (tag_len != mac_size)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInsufficientBufferSize);
    }

    auto init_res = ExecuteVerifyInit(session, mechanism, key_object);
    if (!init_res.has_value())
    {
        return make_unexpected(init_res.error());
    }

    // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C API (C_VerifyUpdate) requires non-const pPart.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    CK_BYTE_PTR p = const_cast<CK_BYTE_PTR>(static_cast<const CK_BYTE*>(static_cast<const void*>(data)));
    const CK_RV rv_upd = m_functionList->C_VerifyUpdate(session, p, static_cast<CK_ULONG>(data_len));
    if (rv_upd != CKR_OK)
    {
        score::mw::log::LogError() << LOG_PREFIX << "C_VerifyUpdate (single-shot verify) failed: rv="
                                   << static_cast<unsigned long>(rv_upd);
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kAlgorithmExecutionFailed);
    }

    return ExecuteVerifyFinal(session, expected_tag, tag_len);
}

}  // namespace score::crypto::daemon::provider::pkcs11
