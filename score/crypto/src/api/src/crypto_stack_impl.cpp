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

#include "score/crypto/src/api/src/crypto_stack_impl.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/api/common/i_memory_allocator.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/data_plane/i_pool_allocator.hpp"
#include "score/crypto/src/api/data_plane/i_read_write_memory_factory.hpp"
#include "score/crypto/src/api/data_plane/i_shm_region_registry.hpp"
#include "score/crypto/src/api/data_plane/src/buffer_shm_transcoder.hpp"
#include "score/crypto/src/api/data_plane/src/shm_memory_allocator.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/src/crypto_context_impl.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"

#include "score/result/result.h"

#include <memory>
#include <utility>

namespace score
{

namespace crypto
{

CryptoStackImpl::CryptoStackImpl(const CryptoStackConfig& config,
                                 std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                                 IReadWriteMemoryFactory::Sptr factory,
                                 std::shared_ptr<IPoolAllocator> pool_allocator,
                                 std::shared_ptr<IShmRegionRegistry> registry)
    : m_config(config), m_connection(std::move(connection)), m_shm_factory(std::move(factory)), m_shm_registry(registry)
{
    m_transcoder = std::make_shared<BufferShmTranscoder>(std::move(pool_allocator), std::move(registry));
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
        return score::Result<ICryptoContext::Uptr>{
            score::unexpect, MakeError(CryptoErrorCode::kConnectionFailed, "Connection is not initialized")};
    }

    auto ctx = std::make_unique<CryptoContextImpl>(m_connection, m_transcoder);
    return ctx;
}

score::Result<IMemoryAllocator::Uptr> CryptoStackImpl::GetMemoryAllocator()
{
    if (!m_connection)
    {
        return score::Result<IMemoryAllocator::Uptr>{
            score::unexpect, MakeError(CryptoErrorCode::kConnectionFailed, "Connection is not initialized")};
    }

    auto allocator_result = ShmMemoryAllocator::Create(m_connection, m_shm_factory, m_shm_registry);
    if (!allocator_result.has_value())
    {
        return score::Result<IMemoryAllocator::Uptr>{score::unexpect, allocator_result.error()};
    }
    return std::move(allocator_result).value();
}

}  // namespace crypto

}  // namespace score
