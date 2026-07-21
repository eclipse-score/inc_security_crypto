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

#ifndef SCORE_MW_CRYPTO_API_OBJECTS_I_SECURE_OBJECT_HPP
#define SCORE_MW_CRYPTO_API_OBJECTS_I_SECURE_OBJECT_HPP

#include "score/mw/crypto/api/objects/i_crypto_object.hpp"
#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Typed view of a secure storage entry.
///
/// Provides read access to opaque data stored in a secure element
/// or provider-managed area.  Resource type is kSecureObject.
class ISecureObject : public ICryptoObject
{
  public:
    using Uptr = std::unique_ptr<ISecureObject>;

    ~ISecureObject() override = default;

    ISecureObject(const ISecureObject&) = delete;
    ISecureObject& operator=(const ISecureObject&) = delete;
    ISecureObject(ISecureObject&&) = default;
    ISecureObject& operator=(ISecureObject&&) = default;

    /// @brief Reads the secure object data into the provided buffer.
    /// @param output Destination buffer
    /// @return Number of bytes written, or error if buffer is too small
    virtual score::Result<std::size_t> GetData(score::cpp::span<uint8_t> output) const = 0;

    /// @brief Returns the size of the stored data in bytes.
    virtual std::size_t GetSize() const noexcept = 0;

  protected:
    ISecureObject() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_OBJECTS_I_SECURE_OBJECT_HPP
