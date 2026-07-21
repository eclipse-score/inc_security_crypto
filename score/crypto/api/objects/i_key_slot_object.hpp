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

#ifndef SCORE_MW_CRYPTO_API_OBJECTS_I_KEY_SLOT_OBJECT_HPP
#define SCORE_MW_CRYPTO_API_OBJECTS_I_KEY_SLOT_OBJECT_HPP

#include "score/mw/crypto/api/objects/i_crypto_object.hpp"

#include <cstdint>
#include <memory>
#include <vector>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Typed view of a persistent key storage location.
///
/// Provides state, algorithm constraint, and provider binding queries
/// for a resource whose type is kKeySlot.  Key slots represent only
/// logical persistent storage; ephemeral keys have no slot.
///
/// Obtained via ICryptoContext::GetKeySlotObject().
class IKeySlotObject : public ICryptoObject
{
  public:
    using Uptr = std::unique_ptr<IKeySlotObject>;

    ~IKeySlotObject() override = default;

    IKeySlotObject(const IKeySlotObject&) = delete;
    IKeySlotObject& operator=(const IKeySlotObject&) = delete;
    IKeySlotObject(IKeySlotObject&&) = default;
    IKeySlotObject& operator=(IKeySlotObject&&) = default;

    /// @brief Returns full slot metadata.
    virtual KeySlotInfo GetInfo() const = 0;

    /// @brief Returns the current slot state (kEmpty, kOccupied, kLocked).
    virtual KeySlotState GetState() const noexcept = 0;

    /// @brief Returns the algorithm constraint for this slot.
    virtual AlgorithmId GetAllowedAlgorithm() const noexcept = 0;

    /// @brief Returns the owning provider's numeric ID.
    virtual uint16_t GetPrimaryProvider() const noexcept = 0;

    /// @brief Returns providers that can also use keys in this slot.
    virtual std::vector<uint16_t> GetCompatibleProviders() const = 0;

    /// @brief Returns the permitted operations for keys in this slot.
    ///
    /// The daemon enforces these permissions at context creation time.
    /// If a key from this slot is used in a context that requires an
    /// operation not included in the returned permission set, the
    /// daemon returns CryptoErrorCode::kKeyOperationNotPermitted.
    ///
    /// @return Bitmask of KeyOperationPermission values.
    virtual KeyOperationPermission GetPermittedOperations() const noexcept = 0;

  protected:
    IKeySlotObject() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_OBJECTS_I_KEY_SLOT_OBJECT_HPP
