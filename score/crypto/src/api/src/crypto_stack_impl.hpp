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

#ifndef SCORE_CRYPTO_SRC_API_SRC_CRYPTO_STACK_IMPL_HPP
#define SCORE_CRYPTO_SRC_API_SRC_CRYPTO_STACK_IMPL_HPP

#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/data_plane/i_buffer_transcoder.hpp"
#include "score/crypto/src/api/data_plane/i_pool_allocator.hpp"
#include "score/crypto/src/api/data_plane/i_read_write_memory_factory.hpp"
#include "score/crypto/src/api/data_plane/i_shm_region_registry.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"

#include "score/crypto/src/api/control_plane/i_connection.hpp"

#include <memory>

namespace score
{

namespace crypto
{

/// @brief Concrete ICryptoStack implementation connected to the crypto daemon.
///
/// Each instance is associated with a single connection.
/// Construction receives the established connection; destruction releases
/// all associated resources including the node.
class CryptoStackImpl final : public ICryptoStack
{
  public:
    /// @brief Constructs a crypto stack with an established connection.
    /// @param config         Stack configuration with connection endpoint.
    /// @param connection     Established connection to the crypto daemon.
    /// @param factory        SHM read-write memory factory (bulk path).
    /// @param pool_allocator Pre-built pool allocator (created by the factory via SHM_SETUP).
    /// @param registry       Shared SHM region registry (seeded with total_quota by the factory).
    explicit CryptoStackImpl(const CryptoStackConfig& config,
                             std::shared_ptr<score::crypto::api::control_plane::IConnection> connection,
                             IReadWriteMemoryFactory::Sptr factory,
                             std::shared_ptr<IPoolAllocator> pool_allocator,
                             std::shared_ptr<IShmRegionRegistry> registry);

    ~CryptoStackImpl() override;

    CryptoStackImpl(const CryptoStackImpl&) = delete;
    CryptoStackImpl& operator=(const CryptoStackImpl&) = delete;
    CryptoStackImpl(CryptoStackImpl&&) = delete;
    CryptoStackImpl& operator=(CryptoStackImpl&&) = delete;

    // -- ICryptoStack --
    score::Result<ICryptoContext::Uptr> CreateCryptoContext() override;
    score::Result<IMemoryAllocator::Uptr> GetMemoryAllocator() override;

  private:
    CryptoStackConfig m_config;
    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
    std::shared_ptr<IBufferTranscoder> m_transcoder;
    IReadWriteMemoryFactory::Sptr m_shm_factory;
    std::shared_ptr<IShmRegionRegistry> m_shm_registry;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_SRC_CRYPTO_STACK_IMPL_HPP
