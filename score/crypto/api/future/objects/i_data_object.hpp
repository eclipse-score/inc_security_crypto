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

#ifndef SCORE_MW_CRYPTO_API_OBJECTS_I_DATA_OBJECT_HPP
#define SCORE_MW_CRYPTO_API_OBJECTS_I_DATA_OBJECT_HPP

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

/// @brief Typed view of a generic data blob resource.
///
/// Provides read access to arbitrary data stored within the
/// crypto daemon.  Resource type is kDataObject.
class IDataObject : public ICryptoObject
{
  public:
    using Uptr = std::unique_ptr<IDataObject>;

    ~IDataObject() override = default;

    IDataObject(const IDataObject&) = delete;
    IDataObject& operator=(const IDataObject&) = delete;
    IDataObject(IDataObject&&) = default;
    IDataObject& operator=(IDataObject&&) = default;

    /// @brief Reads the data object contents into the provided buffer.
    /// @param output Destination buffer
    /// @return Number of bytes written, or error if buffer is too small
    virtual score::Result<std::size_t> GetData(score::cpp::span<uint8_t> output) const = 0;

    /// @brief Returns the size of the stored data in bytes.
    virtual std::size_t GetSize() const noexcept = 0;

  protected:
    IDataObject() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_OBJECTS_I_DATA_OBJECT_HPP
