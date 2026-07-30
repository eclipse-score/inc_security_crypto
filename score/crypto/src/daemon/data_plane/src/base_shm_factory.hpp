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

#ifndef SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_BASE_SHM_FACTORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_BASE_SHM_FACTORY_HPP

#include "score/crypto/src/daemon/data_plane/i_shm_factory.hpp"

namespace score::crypto::daemon::data_plane
{

/// @brief Default IShmFactory implementation backed by score::memory::shared (POSIX SHM).
class BaseShmFactory final : public IShmFactory
{
  public:
    BaseShmFactory() noexcept = default;
    ~BaseShmFactory() override = default;

    BaseShmFactory(const BaseShmFactory&) = delete;
    BaseShmFactory& operator=(const BaseShmFactory&) = delete;
    BaseShmFactory(BaseShmFactory&&) = delete;
    BaseShmFactory& operator=(BaseShmFactory&&) = delete;

    Expected<ShmResource, common::DaemonErrorCode> Create(std::string_view name,
                                                          std::uint32_t uid,
                                                          std::size_t size) override;

  private:
    static constexpr std::string_view LOG_PREFIX = "[BASELIBS_SHM_FACTORY] ";
};

}  // namespace score::crypto::daemon::data_plane

#endif  // SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_BASE_SHM_FACTORY_HPP
