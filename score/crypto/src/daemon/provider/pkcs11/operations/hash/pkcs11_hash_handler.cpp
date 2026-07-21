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
#include "score/crypto/daemon/provider/pkcs11/operations/hash/pkcs11_hash_handler.hpp"
#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/algorithm_info.hpp"
#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/provider/handler/operations/hash_handler_operations.hpp"
#include "score/crypto/daemon/provider/pkcs11/detail/pkcs11_algorithm_info.hpp"
#include "score/crypto/daemon/provider/pkcs11/pkcs11_provider.hpp"

#include <cstring>
#include <string_view>

namespace score::crypto::daemon::provider::pkcs11
{

using common::RequestParameters;
using common::ResponseParameters;
using common::StreamOperationState;
using score::crypto::daemon::common::DaemonErrorCode;

// --- Supported algorithms (same set as OpenSSL HashHandler) ---
static constexpr const char* kSupportedAlgorithms[] = {"SHA256", "SHA384", "SHA512", "SHA224", "SHA1", "MD5"};

// --- Algorithm → CKM_* mapping ---

CK_MECHANISM_TYPE Pkcs11HashHandler::MapAlgorithm(const std::string_view algorithm) noexcept
{
    return detail::LookupHashMechanism(algorithm);
}

std::uint64_t Pkcs11HashHandler::GetDigestSize() const noexcept
{
    return static_cast<std::uint64_t>(
        score::crypto::daemon::common::LookupDigestSize(std::string_view{m_algorithm.data(), m_algorithm.size()})
            .value_or(64U));  // safe default (largest supported)
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
      m_state{StreamOperationState::IDLE},
      m_outputBuffer{}
{
    m_ctx.session = session;
    m_ctx.mechanism.mechanism = MapAlgorithm(m_algorithm);
    m_ctx.mechanism.pParameter = nullptr;
    m_ctx.mechanism.ulParameterLen = 0U;
    m_ctx.digest_size = static_cast<std::size_t>(GetDigestSize());
}

Pkcs11HashHandler::~Pkcs11HashHandler()
{
    // Abort any active PKCS#11 operation before returning the session to the pool.
    // This ensures the session is in IDLE state when released for reuse by the next handler.
    // If streaming was not completed (e.g. early destruction), C_DigestFinal is called
    // with a dummy buffer to cleanly abort the operation state.
    m_executor->Abort(m_ctx.session);

    // Return the dedicated session to the provider pool.
    // Guard against nullptr provider (e.g. unit tests that mock without a provider).
    if ((m_provider != nullptr) && (m_ctx.session != CK_INVALID_HANDLE))
    {
        m_provider->ReleaseSession(m_ctx.session, kRequirements);
        m_ctx.session = CK_INVALID_HANDLE;
    }
}

// --- Static algorithm check ---

bool Pkcs11HashHandler::IsAlgorithmSupported(const common::AlgorithmId& algorithm) noexcept
{
    for (const char* supported : kSupportedAlgorithms)
    {
        if (algorithm == supported)
        {
            return true;
        }
    }
    return false;
}

// --- Handler interface: InitializeContext ---

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11HashHandler::InitializeContext(
    const handler::InitializationParams& /*init_params*/)
{
    // Validate algorithm (m_algorithm is set at construction).
    bool found{false};
    for (const char* supported : kSupportedAlgorithms)
    {
        if (m_algorithm == supported)
        {
            found = true;
            break;
        }
    }
    if (!found)
    {
        return make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedAlgorithm);
    }

    m_ctx.mechanism.mechanism = MapAlgorithm(m_algorithm);
    m_ctx.mechanism.pParameter = nullptr;
    m_ctx.mechanism.ulParameterLen = 0U;
    m_ctx.digest_size = static_cast<std::size_t>(GetDigestSize());
    m_state = StreamOperationState::IDLE;
    m_outputBuffer.clear();

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
        ResponseParameters response;
        response.push_back(GetDigestSize());
        return response;
    }

    // All other operations delegated to the executor.
    m_outputBuffer.clear();

    // TODO: When mediator is refactored, this needs to be revisted
    //  Inject an internal output buffer for HASH_SS and HASH_FINALIZE when the
    //  caller has not supplied one.  This mirrors the OpenSSL handler's behaviour
    //  of using an internal buffer and populating response.parameter on return.
    auto allocate_out_buffer = false;
    if ((operationId.operationAction == ops::HASH_SS) && request.size() < 2)
    {
        allocate_out_buffer = true;
    }
    else if ((operationId.operationAction == ops::HASH_FINALIZE) && request.empty())
    {
        allocate_out_buffer = true;
    }
    if (allocate_out_buffer)
    {
        m_outputBuffer.assign(GetDigestSize(), 0U);
        common::VirtualMemoryBuffer outputMapped{m_outputBuffer.data(), m_outputBuffer.size()};
        request.push_back(outputMapped);
    }

    StreamOperationState nextState{m_state};
    const auto response = m_executor->Execute(m_ctx, operationId.operationAction, request, m_state, nextState);

    if (!response.has_value())
    {
        return response;
    }

    auto response_value = response.value();
    common::VirtualMemoryBufferConst* non_owning_buffer_ptr = nullptr;
    if (!response_value.empty())
    {
        non_owning_buffer_ptr = std::get_if<common::VirtualMemoryBufferConst>(&response_value.back());
    }

    // TODO: Rework and harmonize who is responsible for:
    // - Allocation of Buffer if not provided (Handler vs Executor)
    // - Construction of Response including the correct type when a buffer is allocated
    if (allocate_out_buffer && non_owning_buffer_ptr)
    {
        response_value.pop_back();
        response_value.push_back(common::OwnedBuffer{m_outputBuffer});
    }

    m_state = nextState;

    return response_value;
}

// --- Handler interface: Reset ---

Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> Pkcs11HashHandler::Reset()
{
    // Delegate the abort to the executor so that all PKCS#11 dispatch is
    // centralised there and goes through the function list, not direct C-linkage.
    if (m_state != StreamOperationState::IDLE)
    {
        m_executor->Abort(m_ctx.session);
    }

    m_state = StreamOperationState::IDLE;
    m_outputBuffer.clear();
    return std::monostate{};
}

}  // namespace score::crypto::daemon::provider::pkcs11
