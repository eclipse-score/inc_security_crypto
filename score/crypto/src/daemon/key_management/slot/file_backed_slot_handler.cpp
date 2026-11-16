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

#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
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

score::crypto::Expected<std::monostate, Error> FileBackedSlotHandler::StoreKey(const KeySlotConfig& slot,
                                                                               IKeyHandler& handler)
{
    auto deploy_result = DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "StoreKey: no usable deployment descriptor for slot "
                                   << slot.slot_name;
        return score::crypto::make_unexpected(
            deploy_result.error() == Error::kResourceNotAllocated ? Error::kInvalidArgument : deploy_result.error());
    }

    const auto& deploy_info = deploy_result.value();
    const auto path_it = deploy_info.key_properties.find(std::string{deployment_keys::kKeyPath});
    if (path_it == deploy_info.key_properties.end() || !file_io::IsDeploymentPathSafe(path_it->second))
    {
        score::mw::log::LogError() << kLogPrefix << "StoreKey: missing or unsafe key path for slot " << slot.slot_name;
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }
    const auto& key_path = path_it->second;

    // A slot holds one key. Replacing it takes an explicit ClearSlot first, so the old key
    // material is securely erased rather than silently overwritten.
    const auto state = GetSlotState(slot);
    if (!state.has_value())
    {
        return score::crypto::make_unexpected(state.error());
    }
    if (state.value() != score::crypto::KeySlotState::kEmpty)
    {
        score::mw::log::LogError() << kLogPrefix << "StoreKey: slot " << slot.slot_name << " is occupied";
        return score::crypto::make_unexpected(Error::kKeySlotOccupied);
    }

    // The key must be one the slot's LoadKey can import again.
    const auto slot_algorithm = ::score::crypto::GetAlgorithmDescriptor(slot.algorithm);
    if (!slot_algorithm.has_value())
    {
        return score::crypto::make_unexpected(Error::kUnsupportedAlgorithm);
    }
    const auto& key_algorithm = handler.GetHandle().algorithm;
    if ((key_algorithm.key_type != slot_algorithm->key_type) || (key_algorithm.key_bits != slot_algorithm->key_bits) ||
        (key_algorithm.curve != slot_algorithm->curve))
    {
        score::mw::log::LogError() << kLogPrefix << "StoreKey: key does not fit slot " << slot.slot_name;
        return score::crypto::make_unexpected(Error::kAlgorithmMismatch);
    }

    const auto serialized = handler.SerializeForStorage();
    if (!serialized.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "StoreKey: the provider cannot serialize the key for slot "
                                   << slot.slot_name;
        return score::crypto::make_unexpected(serialized.error());
    }
    const auto& bytes = serialized.value().bytes;
    if (bytes.empty() || (bytes.size() > kMaxKeyFileSize))
    {
        return score::crypto::make_unexpected(Error::kInvalidArgument);
    }

    // CreateSecretFile refuses an existing file atomically, which also covers a store that
    // races with another one between the state check above and the write.
    auto created =
        file_io::CreateSecretFile(key_path, score::crypto::span<const std::uint8_t>{bytes.data(), bytes.size()});
    if (!created.has_value())
    {
        score::mw::log::LogError() << kLogPrefix << "StoreKey: writing the key file failed for slot " << slot.slot_name
                                   << " (error " << static_cast<int>(created.error()) << ")";
        return created;
    }
    score::mw::log::LogInfo() << kLogPrefix << "StoreKey: key stored in slot " << slot.slot_name;
    return std::monostate{};
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
