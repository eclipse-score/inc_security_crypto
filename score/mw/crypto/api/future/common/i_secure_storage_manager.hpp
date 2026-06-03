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

#ifndef SCORE_MW_CRYPTO_API_FUTURE_COMMON_I_SECURE_STORAGE_MANAGER_HPP
#define SCORE_MW_CRYPTO_API_FUTURE_COMMON_I_SECURE_STORAGE_MANAGER_HPP

#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Future API for application-level secret storage.
///
/// This interface is planned for a later release and is not part of the
/// current public API surface. It defines AEAD-encrypted per-application
/// storage for secrets, credentials, and other sensitive data.
///
/// Each application has an isolated namespace — keys are scoped to the
/// calling application's identity (uid).
///
/// @par Example
/// @code
///   auto storage = stack->GetSecureStorageManager();
///   if (!storage) return handle_error();
///   std::vector<uint8_t> secret = {0x01, 0x02, 0x03};
///   storage.value()->Store("my_secret", score::cpp::span<const uint8_t>{secret});
///
///   std::vector<uint8_t> output(256);
///   auto bytes = storage.value()->Retrieve("my_secret", score::cpp::span<uint8_t>{output});
/// @endcode
class ISecureStorageManager
{
  public:
    using Uptr = std::unique_ptr<ISecureStorageManager>;

    virtual ~ISecureStorageManager() = default;

    ISecureStorageManager(const ISecureStorageManager&) = delete;
    ISecureStorageManager& operator=(const ISecureStorageManager&) = delete;
    ISecureStorageManager(ISecureStorageManager&&) = default;
    ISecureStorageManager& operator=(ISecureStorageManager&&) = default;

    /// @brief Stores data under a named key, encrypted per-application.
    /// @param key Named key to store under (application-scoped)
    /// @param data Data to store (will be AEAD-encrypted)
    /// @return std::monostate on success, error if storage limit exceeded or key is invalid
    virtual score::Result<std::monostate> Store(std::string_view key, score::cpp::span<const uint8_t> data) = 0;

    /// @brief Retrieves and decrypts stored data.
    /// @param key Named key to retrieve
    /// @param output Buffer to receive the decrypted data
    /// @return Number of bytes written on success, error if key not found
    virtual score::Result<std::size_t> Retrieve(std::string_view key, score::cpp::span<uint8_t> output) = 0;

    /// @brief Deletes a stored entry.
    /// @param key Named key to delete
    /// @return std::monostate on success, error if key not found
    virtual score::Result<std::monostate> Delete(std::string_view key) = 0;

    /// @brief Lists all stored keys for the current application.
    /// @return Vector of key names, or error on failure
    virtual score::Result<std::vector<std::string>> List() = 0;

  protected:
    ISecureStorageManager() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_FUTURE_COMMON_I_SECURE_STORAGE_MANAGER_HPP
