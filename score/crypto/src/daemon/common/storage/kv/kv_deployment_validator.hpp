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

#ifndef SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_KV_KV_DEPLOYMENT_VALIDATOR_HPP
#define SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_KV_KV_DEPLOYMENT_VALIDATOR_HPP

#include "score/crypto/src/daemon/common/storage/deployment_descriptor.hpp"

#include <string_view>

namespace score::crypto::daemon::common::storage
{

/// @brief Validation rules for the key=value deployment descriptor format.
class KvDeploymentValidator final
{
  public:
    /// @brief Checks whether a section name is valid in the KV format.
    /// @param section Section name to validate.
    /// @return True if the name is non-empty, has no boundary whitespace, and contains no line break.
    [[nodiscard]] bool IsValidSection(std::string_view section) const noexcept;

    /// @brief Checks whether a section, key, and value form a valid KV entry.
    /// @param section Section name containing the entry.
    /// @param key Key to validate; it must be non-empty, must not start with '#', and must not contain '='.
    /// @param value Value to validate; it may be empty.
    /// @return True if all fields satisfy their KV format constraints.
    [[nodiscard]] bool IsValidEntry(std::string_view section,
                                    std::string_view key,
                                    std::string_view value) const noexcept;

    /// @brief Checks every section name and entry in a descriptor.
    /// @param sections Sections to validate.
    /// @return True if all sections and entries are valid; an empty descriptor is valid.
    [[nodiscard]] bool Validate(const DeploymentDescriptor::Sections& sections) const noexcept;
};

}  // namespace score::crypto::daemon::common::storage

#endif  // SCORE_CRYPTO_SRC_DAEMON_COMMON_STORAGE_KV_KV_DEPLOYMENT_VALIDATOR_HPP
