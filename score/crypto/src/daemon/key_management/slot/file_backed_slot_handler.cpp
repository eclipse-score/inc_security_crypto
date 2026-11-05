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

#include "score/crypto/src/daemon/key_management/slot/file_backed_slot_handler.hpp"

#include "score/crypto/src/api/types/algorithm.hpp"
#include "score/crypto/src/daemon/common/secure_memory.hpp"
#include "score/crypto/src/daemon/common/storage/deployment_path_utils.hpp"
#include "score/crypto/src/daemon/common/storage/file_io.hpp"
#include "score/crypto/src/daemon/key_management/detail/slot_info_builder.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/src/daemon/key_management/slot/deployment_loader.hpp"

#include "score/mw/log/logging.h"

#include <cstdint>
#include <string_view>
#include <vector>

namespace score::crypto::daemon::key_management
{
namespace
{
namespace file_io = common::storage;
using Error = common::DaemonErrorCode;
constexpr std::string_view kLogPrefix = "[FILE_BACKED_KEY_SLOT] ";
}  // namespace

FileBackedSlotHandler::FileBackedSlotHandler(IKeyFactory::Sptr factory) : m_factory{std::move(factory)} {}

score::crypto::Expected<IKeyHandler::Sptr, Error> FileBackedSlotHandler::LoadKey(const KeySlotConfig& slot)
{
    auto deploy_result = DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
        return score::crypto::make_unexpected(deploy_result.error());

    const auto& deploy_info = deploy_result.value();
    const auto path_it = deploy_info.key_properties.find(std::string{deployment_keys::kKeyPath});
    if (path_it == deploy_info.key_properties.end() || path_it->second.empty())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    auto read_result = file_io::ReadFile(path_it->second, kMaxKeyFileSize);
    if (!read_result.has_value())
    {
        const auto file_io_err = read_result.error();
        return score::crypto::make_unexpected(file_io_err == Error::kResourceNotAllocated ? Error::kKeySlotEmpty
                                                                                          : file_io_err);
    }

    auto& buffer = read_result.value();

    const auto algorithm = ::score::crypto::GetAlgorithmDescriptor(slot.algorithm);
    if (!algorithm.has_value())
    {
        common::SecureZeroizeAndClear(buffer);
        return score::crypto::make_unexpected(Error::kUnsupportedAlgorithm);
    }

    KeyImportRequest req{};
    req.key_data = buffer.data();
    req.key_data_size = buffer.size();
    req.algorithm = algorithm.value();
    req.permissions = slot.allowed_operations;

    auto import_result = m_factory->ImportKey(req);
    common::SecureZeroizeAndClear(buffer);
    return import_result;
}

score::crypto::Expected<score::crypto::KeySlotState, Error> FileBackedSlotHandler::GetSlotState(
    const KeySlotConfig& slot)
{
    auto deploy_result = DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
    {
        if (deploy_result.error() == Error::kResourceNotAllocated)
            return score::crypto::KeySlotState::kEmpty;
        return score::crypto::make_unexpected(deploy_result.error());
    }

    const auto& deploy_info = deploy_result.value();
    const auto path_it = deploy_info.key_properties.find(std::string{deployment_keys::kKeyPath});
    if (path_it == deploy_info.key_properties.end() || path_it->second.empty())
        return score::crypto::KeySlotState::kEmpty;

    const auto exists = file_io::FileExists(path_it->second);
    if (!exists)
        return score::crypto::make_unexpected(exists.error());
    return exists.value() ? score::crypto::KeySlotState::kOccupied : score::crypto::KeySlotState::kEmpty;
}

score::crypto::Expected<score::crypto::KeySlotInfo, Error> FileBackedSlotHandler::GetSlotInfo(const KeySlotConfig& slot)
{
    auto state_result = GetSlotState(slot);
    if (!state_result.has_value())
        return score::crypto::make_unexpected(state_result.error());
    return detail::BuildKeySlotInfo(slot, state_result.value());
}

score::crypto::Expected<std::monostate, Error> FileBackedSlotHandler::ClearSlot(const KeySlotConfig& slot)
{
    auto deploy_result = DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
    {
        // No deployment descriptor means no key file: the slot is already empty.
        if (deploy_result.error() == Error::kResourceNotAllocated)
        {
            return std::monostate{};
        }
        return score::crypto::make_unexpected(deploy_result.error());
    }

    const auto& deploy_info = deploy_result.value();
    const auto path_it = deploy_info.key_properties.find(std::string{deployment_keys::kKeyPath});
    if (path_it == deploy_info.key_properties.end() || path_it->second.empty())
    {
        return std::monostate{};
    }

    // The erase is permanent, so the key path gets the same check as the descriptor path:
    // a relative path would resolve against the daemon's working directory.
    const auto& key_path = path_it->second;
    if (!file_io::IsDeploymentPathSafe(key_path))
    {
        score::mw::log::LogError() << kLogPrefix << "ClearSlot: unsafe key path rejected for slot " << slot.slot_name;
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    auto erase_result = file_io::SecureEraseFile(key_path, kMaxKeyFileSize);
    if (!erase_result.has_value())
    {
        // kInvalidArgument here means the path holds a symbolic link, a non-regular file or a
        // file too large to be a key; LoadKey would follow a link, but an erase never does.
        score::mw::log::LogError() << kLogPrefix << "ClearSlot: erasing the key file failed for slot " << slot.slot_name
                                   << " (error " << static_cast<int>(erase_result.error()) << ")";
        return erase_result;
    }
    score::mw::log::LogInfo() << kLogPrefix << "ClearSlot: key material erased for slot " << slot.slot_name;
    return std::monostate{};
}

}  // namespace score::crypto::daemon::key_management
