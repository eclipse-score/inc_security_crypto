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

// Full Pkcs11Provider definition required for ReleaseSession call in destructor.
#include "score/crypto/src/daemon/provider/pkcs11/operations/hash/pkcs11_hash_handler.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/common/types.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/hash_handler_operations.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/detail/pkcs11_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider.hpp"

#include <cstring>
#include <string_view>

namespace score::crypto::daemon::provider::pkcs11
{

using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;
using score::crypto::daemon::common::DaemonErrorCode;

// --- Algorithm → CKM_* mapping ---

CK_MECHANISM_TYPE Pkcs11HashHandler::MapAlgorithm(const std::string_view algorithm) noexcept
{
    return detail::LookupHashMechanism(algorithm);
}

std::optional<std::uint64_t> Pkcs11HashHandler::GetDigestSize() const noexcept
{
    const auto size =
        score::crypto::daemon::common::LookupDigestSize(std::string_view{m_algorithm.data(), m_algorithm.size()});
    return size.has_value() ? std::optional<std::uint64_t>{static_cast<std::uint64_t>(size.value())} : std::nullopt;
}

// --- Construction / destruction ---

Pkcs11HashHandler::Pkcs11HashHandler(std::unique_ptr<Pkcs11HashExecutor> executor,
                                     const CK_SESSION_HANDLE session,
                                     const common::AlgorithmId& algorithm,
                                     Pkcs11Provider* provider)
    : m_executor{std::move(executor)},
      m_ctx{},
      m_provider{provider},
      m_algorithm{algorithm},
      m_state{StreamOperationState::IDLE}
{
    m_ctx.session = session;
    m_ctx.mechanism.mechanism = MapAlgorithm(m_algorithm);
    m_ctx.mechanism.pParameter = nullptr;
    m_ctx.mechanism.ulParameterLen = 0U;
    m_ctx.digest_size = static_cast<std::size_t>(GetDigestSize().value_or(0U));
}

Pkcs11HashHandler::~Pkcs11HashHandler()
{
    if (m_ctx.session == CK_INVALID_HANDLE)
    {
        return;
    }

    // Abort any active PKCS#11 operation before returning the session to the pool.
    // This ensures the session is in IDLE state when released for reuse by the next handler.
    // If streaming was not completed (e.g. early destruction), C_DigestFinal is called
    // with a dummy buffer to cleanly abort the operation state.
    const auto cleanupResult = m_executor->Abort(m_ctx.session);

    // Return the dedicated session to the provider pool.
    // Guard against nullptr provider (e.g. unit tests that mock without a provider).
    if (m_provider != nullptr)
    {
        // A failed abort leaves the token operation state unspecified. Never
        // return such a session to a soft-cleanup pool; closing it guarantees
        // that the next handler receives a fresh PKCS#11 session.
        const auto disposition =
            cleanupResult.has_value() ? Pkcs11SessionDisposition::kReusable : Pkcs11SessionDisposition::kDiscard;
        m_provider->ReleaseSession(m_ctx.session, kRequirements, disposition);
        m_ctx.session = CK_INVALID_HANDLE;
    }
}

// --- Static algorithm check ---

bool Pkcs11HashHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    const std::string_view algorithmView{algorithm.data(), algorithm.size()};
    return score::crypto::daemon::common::LookupDigestSize(algorithmView).has_value() &&
           (MapAlgorithm(algorithmView) != CK_UNAVAILABLE_INFORMATION);
}

// --- Handler interface: InitializeContext ---

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11HashHandler::InitializeContext(
    const handler::InitializationParams& /*init_params*/)
{
    // Validate algorithm (m_algorithm is set at construction).
    const auto digestSize = GetDigestSize();
    const auto mechanism = MapAlgorithm(m_algorithm);
    if (!digestSize.has_value() || (mechanism == CK_UNAVAILABLE_INFORMATION))
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }

    m_ctx.mechanism.mechanism = mechanism;
    m_ctx.mechanism.pParameter = nullptr;
    m_ctx.mechanism.ulParameterLen = 0U;
    m_ctx.digest_size = static_cast<std::size_t>(digestSize.value());
    m_state = StreamOperationState::IDLE;

    return std::monostate{};
}

// --- Handler interface: Execute ---

Expected<ResponseParameters, score::crypto::daemon::common::DaemonErrorCode> Pkcs11HashHandler::Execute(
    const common::OperationIdentifier& operationId,
    RequestParameters& request)
{
    namespace ops = handler::hash_handler_operations;

    // Validate session is still open before any PKCS#11 call.
    if ((m_provider != nullptr) && !m_provider->ValidateSession(m_ctx.session))
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kSessionInvalid);
    }

    // Handle GET_DIGEST_SIZE locally — no PKCS#11 call needed.
    if (operationId.operationAction == ops::HASH_GET_DIGEST_SIZE)
    {
        if (!request.empty())
        {
            return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
        }
        const auto digestSize = GetDigestSize();
        if (!digestSize.has_value())
        {
            return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
        }
        ResponseParameters response;
        response.push_back(digestSize.value());
        return response;
    }

    StreamOperationState nextState{m_state};
    const auto response = m_executor->Execute(m_ctx, operationId.operationAction, request, m_state, nextState);

    // The executor may complete cleanup after a provider failure. Apply the
    // resulting state even when the requested operation itself failed.
    m_state = nextState;

    if (!response.has_value())
    {
        return response;
    }

    return response.value();
}

// --- Handler interface: Reset ---

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11HashHandler::Reset()
{
    // Delegate the abort to the executor so that all PKCS#11 dispatch is
    // centralised there and goes through the function list, not direct C-linkage.
    const auto abortResult = m_executor->Abort(m_ctx.session);
    if (!abortResult.has_value())
    {
        return make_unexpected(abortResult.error());
    }

    m_state = StreamOperationState::IDLE;
    return std::monostate{};
}

}  // namespace score::crypto::daemon::provider::pkcs11
