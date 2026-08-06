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

#ifndef SCORE_CRYPTO_API_DATA_PLANE_SHM_MEMORY_FACTORY_HPP
#define SCORE_CRYPTO_API_DATA_PLANE_SHM_MEMORY_FACTORY_HPP

#include "score/crypto/src/api/control_plane/i_connection.hpp"
#include "score/crypto/src/api/data_plane/i_read_write_memory_factory.hpp"
#include "score/crypto/src/api/data_plane/i_shm_region_registry.hpp"

#include <memory>

namespace score
{

namespace crypto
{

/// @brief Default implementation of IReadWriteMemoryFactory using score::baselibs.
class ShmMemoryFactory final : public IReadWriteMemoryFactory
{
  public:
    explicit ShmMemoryFactory(std::shared_ptr<IShmRegionRegistry> registry,
                              std::shared_ptr<score::crypto::api::control_plane::IConnection> connection);

    ~ShmMemoryFactory() override = default;

    ShmMemoryFactory(const ShmMemoryFactory&) = delete;
    ShmMemoryFactory& operator=(const ShmMemoryFactory&) = delete;
    ShmMemoryFactory(ShmMemoryFactory&&) = delete;
    ShmMemoryFactory& operator=(ShmMemoryFactory&&) = delete;

    score::crypto::Expected<ShmCreateResult, CryptoErrorCode> Create(const ShmRegionParams& region_params) override;

  private:
    std::shared_ptr<IShmRegionRegistry> m_registry;
    std::shared_ptr<score::crypto::api::control_plane::IConnection> m_connection;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_API_DATA_PLANE_SHM_MEMORY_FACTORY_HPP
