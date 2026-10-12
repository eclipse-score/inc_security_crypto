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

#include "score/crypto/src/daemon/data_plane/src/base_shm_factory.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/data_plane/i_shm_factory.hpp"
#include "score/memory/shared/shared_memory_factory.h"

#include <cstddef>
#include <cstdint>
#include <utility>

namespace score::crypto::daemon::data_plane
{

namespace
{
using ShmFactory = score::memory::shared::SharedMemoryFactory;
using UserPermMap = score::memory::shared::ISharedMemoryResource::UserPermissionsMap;
}  // namespace

Expected<ShmResource, common::DaemonErrorCode> BaseShmFactory::Create(std::string_view name,
                                                                      std::uint32_t uid,
                                                                      std::size_t size)
{
    if (size == 0U)
    {
        return make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    UserPermMap perm_map;
    perm_map[score::os::Acl::Permission::kRead] = {uid};
    perm_map[score::os::Acl::Permission::kWrite] = {uid};

    auto handle = ShmFactory::Create(std::string(name), [](const auto&) noexcept {}, size, perm_map);
    if (!handle)
    {
        return make_unexpected(common::DaemonErrorCode::kAllocationFailed);
    }

    return ShmResource{std::move(handle), size};
}

}  // namespace score::crypto::daemon::data_plane
