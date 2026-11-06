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
#include "score/crypto/src/daemon/common/storage/file_io.hpp"
#include "score/crypto/src/daemon/key_management/detail/slot_info_builder.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_management_operations.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/src/daemon/key_management/slot/deployment_loader.hpp"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace score::crypto::daemon::key_management
{
namespace
{
namespace file_io = common::storage;
using Error = common::DaemonErrorCode;

/// Map the deployment "key_format" property to a format. Without the property
/// the factory picks the key type's native format.
score::crypto::Expected<std::optional<::score::crypto::FormatType>, Error> ResolveKeyFormat(
    const SlotDeploymentInfo& deploy_info)
{
    const auto it = deploy_info.key_properties.find(std::string{deployment_keys::kKeyFormat});
    if (it == deploy_info.key_properties.end())
        return std::optional<::score::crypto::FormatType>{};
    if (it->second == "raw")
        return std::optional<::score::crypto::FormatType>{::score::crypto::FormatType::kRaw};
    if (it->second == "der")
        return std::optional<::score::crypto::FormatType>{::score::crypto::FormatType::kDer};
    if (it->second == "pem")
        return std::optional<::score::crypto::FormatType>{::score::crypto::FormatType::kPem};
    return score::crypto::make_unexpected(Error::kInvalidFormat);
}
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

    const auto format = ResolveKeyFormat(deploy_info);
    if (!format.has_value())
    {
        common::SecureZeroizeAndClear(buffer);
        return score::crypto::make_unexpected(format.error());
    }

    KeyImportRequest req{};
    req.format = format.value();
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

}  // namespace score::crypto::daemon::key_management
