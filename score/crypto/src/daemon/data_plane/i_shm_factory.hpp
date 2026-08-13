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

#ifndef SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_I_SHM_FACTORY_HPP
#define SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_I_SHM_FACTORY_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/mediator/mediator_operations.hpp"
#include "score/memory/shared/i_shared_memory_resource.h"
#include <cstddef>
#include <memory>
#include <string_view>

namespace score::crypto::daemon::data_plane
{
using ShmTransportType = score::crypto::daemon::mediator::operations::ShmTransportType;

/// @brief Result of a successful IShmFactory::Create call.
struct ShmResource
{
    std::shared_ptr<score::memory::shared::ISharedMemoryResource>
        handle;        ///< Mapped region (RAII cleanup via shared_ptr).
    std::size_t size;  ///< Usable region size in bytes.
    // TODO: Consider removing transport_type if it can be queried from handle.
    ShmTransportType transport_type{ShmTransportType::kPosixNamed};  ///< Transport backend.
};

/// @brief Abstract factory for creating OS-level shared-memory objects.
class IShmFactory
{
  public:
    using Sptr = std::shared_ptr<IShmFactory>;

    virtual ~IShmFactory() = default;

    IShmFactory(const IShmFactory&) = delete;
    IShmFactory& operator=(const IShmFactory&) = delete;
    IShmFactory(IShmFactory&&) = delete;
    IShmFactory& operator=(IShmFactory&&) = delete;

    /// @brief Create a new SHM region with the given name and size.
    ///
    /// @param name  OS-level SHM object name (caller is responsible for uniqueness).
    /// @param uid   UID of the client.
    /// @param size  Requested size in bytes; must be > 0.
    /// @return ShmResource (handle + size) on success, or error code.
    virtual Expected<ShmResource, common::DaemonErrorCode> Create(std::string_view name,
                                                                  std::uint32_t uid,
                                                                  std::size_t size) = 0;

  protected:
    IShmFactory() = default;
};

}  // namespace score::crypto::daemon::data_plane

#endif  // SCORE_CRYPTO_SRC_DAEMON_DATA_PLANE_I_SHM_FACTORY_HPP
