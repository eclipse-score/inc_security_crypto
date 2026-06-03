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

#include "score/mw/crypto/api/src/crypto_stack_impl.hpp"

#include "score/mw/crypto/api/common/error_domain.hpp"
#include "score/mw/crypto/api/common/i_memory_allocator.hpp"
#include "score/mw/crypto/api/crypto_stack_factory.hpp"
#include "score/mw/crypto/api/i_crypto_context.hpp"
#include "score/mw/crypto/api/src/crypto_context_impl.hpp"

#include "score/crypto/api/control_plane/i_connection.hpp"

#include "score/result/result.h"

#include "score/mw/log/logging.h"

#include <memory>
#include <utility>

namespace score
{
namespace mw
{
namespace crypto
{

CryptoStackImpl::CryptoStackImpl(const CryptoStackConfig& config,
                                 std::shared_ptr<score::crypto::api::control_plane::IConnection> connection)
    : m_config(config), m_connection(std::move(connection))
{
}

CryptoStackImpl::~CryptoStackImpl()
{
    // No cleanup needed - connection is managed by shared_ptr
    // If this is the last reference, the connection will be destroyed
    // CONNECTION_CLOSE is caller's responsibility
}

score::Result<ICryptoContext::Uptr> CryptoStackImpl::CreateCryptoContext()
{
    // Create a context with the established connection.
    // The connection is managed by the stack and was established during CreateCryptoStack.

    if (!m_connection)
    {
        score::mw::log::LogError() << "[API][CryptoStackImpl] ERROR: Connection is not initialized";
        return score::Result<ICryptoContext::Uptr>{
            score::unexpect, MakeError(CryptoErrorCode::kConnectionFailed, "Connection is not initialized")};
    }

    auto ctx = std::make_unique<CryptoContextImpl>(m_connection);
    return ctx;
}

score::Result<IMemoryAllocator::Uptr> CryptoStackImpl::GetMemoryAllocator()
{
    // TODO: Implement shared-memory allocator for data-plane zero-copy path.
    //       For now, this is not needed by the hash example test.
    score::mw::log::LogError() << "[API][CryptoStackImpl] ERROR: GetMemoryAllocator not yet implemented";
    return score::Result<IMemoryAllocator::Uptr>{
        score::unexpect, MakeError(CryptoErrorCode::kInternalError, "GetMemoryAllocator not yet implemented")};
}

}  // namespace crypto
}  // namespace mw
}  // namespace score
