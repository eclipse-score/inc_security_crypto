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

#ifndef SCORE_MW_CRYPTO_API_OBJECTS_I_CRYPTO_OBJECT_HPP
#define SCORE_MW_CRYPTO_API_OBJECTS_I_CRYPTO_OBJECT_HPP

#include "score/mw/crypto/api/common/types.hpp"

#include <memory>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Root base for all typed crypto objects.
///
/// Provides the common identity and type accessors shared by every
/// specialised object interface.  Objects are lightweight proxies
/// into daemon state, not owned data copies.
///
/// Obtain typed objects via ICryptoContext accessor methods
/// (e.g., GetKeyObject(), GetKeySlotObject()).
class ICryptoObject
{
  public:
    using Uptr = std::unique_ptr<ICryptoObject>;

    virtual ~ICryptoObject() = default;

    ICryptoObject(const ICryptoObject&) = delete;
    ICryptoObject& operator=(const ICryptoObject&) = delete;
    ICryptoObject(ICryptoObject&&) = default;
    ICryptoObject& operator=(ICryptoObject&&) = default;

    /// @brief Returns the underlying CryptoResourceId handle.
    virtual CryptoResourceId GetId() const noexcept = 0;

    /// @brief Returns the resource type (kKey, kKeySlot, kCertificate, etc.).
    virtual ResourceType GetType() const noexcept = 0;

  protected:
    ICryptoObject() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_OBJECTS_I_CRYPTO_OBJECT_HPP
