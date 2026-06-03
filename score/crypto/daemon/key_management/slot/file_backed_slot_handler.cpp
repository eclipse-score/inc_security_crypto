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

#include "score/crypto/daemon/key_management/slot/file_backed_slot_handler.hpp"

#include "score/crypto/daemon/common/secure_memory.hpp"
#include "score/crypto/daemon/key_management/detail/slot_info_builder.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/daemon/key_management/slot/deployment_loader.hpp"

#include <cstdint>
#include <fstream>
#include <ios>
#include <iterator>
#include <vector>

namespace score::crypto::daemon::key_management
{

FileBackedSlotHandler::FileBackedSlotHandler(IKeyFactory::Sptr factory) : m_factory{std::move(factory)} {}

score::crypto::Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode>
FileBackedSlotHandler::LoadKey(const KeySlotConfig& slot)
{
    // Load deployment info to get the key file path.
    auto deploy_result = DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
    {
        return score::crypto::make_unexpected(deploy_result.error());
    }

    const auto& deploy_info = deploy_result.value();
    const auto path_it = deploy_info.key_properties.find(std::string{deployment_keys::kKeyPath});
    if ((path_it == deploy_info.key_properties.end()) || path_it->second.empty())
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    auto read_result = ReadKeyFile(path_it->second);
    if (!read_result.has_value())
    {
        return score::crypto::make_unexpected(read_result.error());
    }

    auto& buffer = read_result.value();

    KeyImportRequest req{};
    req.key_data = buffer.data();
    req.key_data_size = buffer.size();
    req.algorithm = slot.algorithm;
    req.permissions = slot.allowed_operations;

    auto import_result = m_factory->ImportKey(req);

    // Securely zeroize regardless of import outcome.
    common::SecureZeroizeAndClear(buffer);

    return import_result;
}

score::crypto::Expected<score::mw::crypto::KeySlotState, score::crypto::daemon::common::DaemonErrorCode>
FileBackedSlotHandler::GetSlotState(const KeySlotConfig& slot)
{
    auto deploy_result = DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!deploy_result.has_value())
    {
        return score::mw::crypto::KeySlotState::kEmpty;
    }

    const auto& deploy_info = deploy_result.value();
    const auto path_it = deploy_info.key_properties.find(std::string{deployment_keys::kKeyPath});
    if ((path_it == deploy_info.key_properties.end()) || path_it->second.empty())
    {
        return score::mw::crypto::KeySlotState::kEmpty;
    }

    std::ifstream file(path_it->second, std::ios::binary);
    if (file.good())
    {
        return score::mw::crypto::KeySlotState::kOccupied;
    }

    return score::mw::crypto::KeySlotState::kEmpty;
}

score::crypto::Expected<score::mw::crypto::KeySlotInfo, score::crypto::daemon::common::DaemonErrorCode>
FileBackedSlotHandler::GetSlotInfo(const KeySlotConfig& slot)
{
    auto state_result = GetSlotState(slot);
    if (!state_result.has_value())
    {
        return score::crypto::make_unexpected(state_result.error());
    }
    return detail::BuildKeySlotInfo(slot, state_result.value());
}

score::crypto::Expected<std::vector<std::uint8_t>, score::crypto::daemon::common::DaemonErrorCode>
FileBackedSlotHandler::ReadKeyFile(const std::string& file_path) const
{
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open())
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kKeySlotEmpty);
    }

    std::vector<std::uint8_t> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    if (buffer.empty())
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    if (buffer.size() > kMaxKeyFileSize)
    {
        common::SecureZeroizeAndClear(buffer);
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    return buffer;
}

}  // namespace score::crypto::daemon::key_management
