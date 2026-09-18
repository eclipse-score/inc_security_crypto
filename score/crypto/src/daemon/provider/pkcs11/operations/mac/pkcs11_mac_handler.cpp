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
#include "score/crypto/src/daemon/provider/pkcs11/operations/mac/pkcs11_mac_handler.hpp"

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/handler_init_params.hpp"
#include "score/crypto/src/daemon/provider/handler/i_handler.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/mac_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/detail/pkcs11_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/key_management/pkcs11_key_handler.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/operations/key_management/pkcs11_key_management_handler.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/operations/mac/pkcs11_mac_executor.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider.hpp"

#include "score/mw/log/logging.h"

#include <pkcs11.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>
#include <utility>
#include <variant>

namespace score::crypto::daemon::provider::pkcs11
{

using namespace score::crypto::daemon::provider::handler::mac_handler_operations;  // NOLINT
using common::OperationIdentifier;
using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;

// ---------------------------------------------------------------------------
// Supported algorithms
// ---------------------------------------------------------------------------
static constexpr std::array<const char*, 3> kSupportedAlgorithms = {
    "HMAC-SHA256",
    "HMAC-SHA384",
    "HMAC-SHA512",
};
static constexpr std::size_t kOperationModeParameterIndex = 4U;
static constexpr std::size_t kMinimumContextCreationParameters = kOperationModeParameterIndex + 1U;

// ---------------------------------------------------------------------------
// Algorithm mapping
// ---------------------------------------------------------------------------
CK_MECHANISM_TYPE Pkcs11MacHandler::MapAlgorithm(const std::string_view algorithm) noexcept
{
    return detail::LookupMacMechanism(algorithm);
}

// ---------------------------------------------------------------------------
// Construction / destruction
// ---------------------------------------------------------------------------
Pkcs11MacHandler::Pkcs11MacHandler(std::unique_ptr<Pkcs11MacExecutor> executor,
                                   const Pkcs11Module& module,
                                   CK_SESSION_HANDLE session,
                                   const common::AlgorithmId& algorithm,
                                   Pkcs11Provider* provider)
    : Handler{},
      m_executor{std::move(executor)},
      m_module{module},
      m_session{session},
      m_provider{provider},
      m_ctx{},
      m_algorithm{algorithm}
{
    m_ctx.mechanism = {MapAlgorithm(algorithm), nullptr, 0U};
}

Pkcs11MacHandler::~Pkcs11MacHandler()
{
    // Abort any in-progress operation on the operational session before releasing.
    if (m_state != common::StreamOperationState::IDLE && m_op_session != CK_INVALID_HANDLE)
    {
        m_executor->Abort(m_op_session, m_ctx.operation_mode);
    }
    m_resolved_key = {};  // destructor clears the in-use flag automatically
    if (m_provider != nullptr && m_session != CK_INVALID_HANDLE)
    {
        m_provider->ReleaseSession(m_session, kRequirements);
    }
}

// ---------------------------------------------------------------------------
// Static helpers
// ---------------------------------------------------------------------------
bool Pkcs11MacHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    return std::find(std::begin(kSupportedAlgorithms), std::end(kSupportedAlgorithms), algorithm) !=
           std::end(kSupportedAlgorithms);
}

std::size_t Pkcs11MacHandler::GetMacSize() const noexcept
{
    return score::crypto::daemon::common::LookupMacSize(std::string_view{m_algorithm.data(), m_algorithm.size()})
        .value_or(0U);
}

// ---------------------------------------------------------------------------
// Handler interface
// ---------------------------------------------------------------------------
score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
Pkcs11MacHandler::InitializeContext(const handler::InitializationParams& init_params)
{
    bool found{false};
    for (const char* algo : kSupportedAlgorithms)
    {
        if (m_algorithm == algo)
        {
            found = true;
            break;
        }
    }
    if (!found)
    {
        score::mw::log::LogError() << LOG_PREFIX << "Unsupported algorithm:" << m_algorithm;
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }

    m_ctx.mechanism.mechanism = MapAlgorithm(m_algorithm);
    m_ctx.mechanism.pParameter = nullptr;
    m_ctx.mechanism.ulParameterLen = 0U;
    m_state = StreamOperationState::IDLE;
    m_ctx.key_object = CK_INVALID_HANDLE;

    // Bind key if provided via InitializationParams.
    if (init_params.bound_key_handler != nullptr)
    {
        // Downcast to the PKCS#11-specific key handler for direct session key access.
        // Provider-id check validates the key comes from the same provider (no dynamic_cast/RTTI).
        if (init_params.bound_key_handler->GetProviderId() != init_params.provider_id)
        {
            score::mw::log::LogError() << LOG_PREFIX << "Bound key provider ID "
                                       << init_params.bound_key_handler->GetProviderId()
                                       << " does not match expected provider ID" << init_params.provider_id;
            score::mw::log::LogError() << LOG_PREFIX << "InitializeContext: bound key is not a PKCS#11 key handler";
            return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
        }

        // NOLINTNEXTLINE(cppcoreguidelines-pro-type-static-cast-downcast) - type tag verified above
        const auto* pkcs11_key = static_cast<const Pkcs11KeyHandler*>(init_params.bound_key_handler);

        // Resolve the key: for session objects acquires the exclusive in-use flag
        // (non-blocking); returns kResourceBusy if the key is already held by another
        // handler.  For token objects runs C_FindObjects on m_session.
        auto resolved = pkcs11_key->ResolveObject(m_session);
        if (!resolved.has_value())
        {
            if (resolved.error() == score::crypto::daemon::common::DaemonErrorCode::kResourceBusy)
            {
                score::mw::log::LogError()
                    << LOG_PREFIX << "InitializeContext: key is already in use by another handler";
            }
            else
            {
                score::mw::log::LogError() << LOG_PREFIX << "InitializeContext: failed to resolve key object handle";
            }
            return score::crypto::make_unexpected(resolved.error());
        }

        // Store the resolved session and object.  C_SignInit/C_VerifyInit is deferred to the
        // executor and called lazily before the first sign/verify operation.
        m_op_session = resolved->session();
        m_ctx.session = resolved->session();
        m_ctx.key_object = resolved->object();
        m_ctx.mac_size = GetMacSize();

        // operation_mode is MAC-specific: read from param[4] of the CTX_CREATE wire call.
        if (init_params.context_creation_params.size() >= kMinimumContextCreationParameters)
        {
            const auto* mode_val =
                std::get_if<std::uint8_t>(&init_params.context_creation_params[kOperationModeParameterIndex]);
            if (mode_val != nullptr)
            {
                m_ctx.operation_mode = static_cast<score::crypto::OperationMode>(*mode_val);
            }
        }

        m_resolved_key = std::move(*resolved);  // holds in-use flag for session objects
        m_state = StreamOperationState::STREAM_INITIALIZED;
        m_init_params = init_params;  // Saved so Reset() can restore the key binding.
    }

    return std::monostate{};
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacHandler::Reset()
{
    if (m_state != StreamOperationState::IDLE)
    {
        m_executor->Abort(m_op_session, m_ctx.operation_mode);
    }
    m_resolved_key = {};  // move-assigns empty key; operator= clears the flag before replacing
    m_op_session = CK_INVALID_HANDLE;
    m_ctx.key_object = CK_INVALID_HANDLE;
    m_ctx.session = CK_INVALID_HANDLE;
    m_state = StreamOperationState::IDLE;

    // Re-run InitializeContext with the saved params to restore the key binding.
    return InitializeContext(m_init_params);
}

// ---------------------------------------------------------------------------
// Generic Execute dispatch
// ---------------------------------------------------------------------------
score::crypto::Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Pkcs11MacHandler::Execute(
    const OperationIdentifier& operationId,
    RequestParameters& request)
{
    namespace ops = handler::mac_handler_operations;

    // Validate session is still open before any PKCS#11 call.
    if ((m_provider != nullptr) && !m_provider->ValidateSession(m_session))
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kSessionInvalid);
    }

    // MAC_GET_SIZE is a stateless size query; no PKCS#11 call needed.
    if (operationId.operationAction == ops::MAC_GET_SIZE)
    {
        ResponseParameters response;
        response.push_back(static_cast<std::uint64_t>(GetMacSize()));
        return response;
    }

    // MAC_RESET - abort any in-progress sign/verify operation and restore key binding.
    if (operationId.operationAction == ops::MAC_RESET)
    {
        auto res = Reset();
        if (!res.has_value())
        {
            return score::crypto::make_unexpected(res.error());
        }
        return ResponseParameters{};
    }

    if (m_ctx.key_object == CK_INVALID_HANDLE)
    {
        score::mw::log::LogError() << LOG_PREFIX
                                   << "Execute: no key bound - call InitializeContext with keyOpaqueId first";
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kStreamNotInitialized);
    }

    StreamOperationState nextState{m_state};
    auto result = m_executor->Execute(m_ctx, operationId.operationAction, request, m_state, nextState);
    if (result.has_value())
    {
        m_state = nextState;
    }
    return result;
}

}  // namespace score::crypto::daemon::provider::pkcs11
