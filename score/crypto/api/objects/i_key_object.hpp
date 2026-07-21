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

#ifndef SCORE_MW_CRYPTO_API_OBJECTS_I_KEY_OBJECT_HPP
#define SCORE_MW_CRYPTO_API_OBJECTS_I_KEY_OBJECT_HPP

#include "score/mw/crypto/api/objects/i_crypto_object.hpp"

#include <cstddef>
#include <memory>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Typed view of key material (symmetric or asymmetric).
///
/// Provides algorithm, persistence, exportability, and length queries
/// for a resource whose type is kKey.  Obtained via
/// ICryptoContext::GetKeyObject().
///
/// Sub-types ISymmetricKeyObject, IPublicKeyObject, and
/// IPrivateKeyObject add role-specific queries.
class IKeyObject : public ICryptoObject
{
  public:
    using Uptr = std::unique_ptr<IKeyObject>;

    ~IKeyObject() override = default;

    IKeyObject(const IKeyObject&) = delete;
    IKeyObject& operator=(const IKeyObject&) = delete;
    IKeyObject(IKeyObject&&) = default;
    IKeyObject& operator=(IKeyObject&&) = default;

    /// @brief Returns the algorithm bound to this key.
    virtual AlgorithmId GetAlgorithm() const noexcept = 0;

    /// @brief Returns the persistence model (kPersistent or kEphemeral).
    virtual ResourcePersistence GetPersistence() const noexcept = 0;

    /// @brief Whether the key material can be exported / unwrapped.
    virtual bool IsExportable() const noexcept = 0;

    /// @brief Returns the key length in bits.
    virtual std::size_t GetKeyLength() const noexcept = 0;

    /// @brief Returns the operations this key is permitted to perform.
    ///
    /// For keys loaded from a slot, this reflects the slot's provisioned
    /// permissions. For ephemeral keys generated with explicit permissions,
    /// this reflects the requested permission set. For ephemeral keys
    /// generated without explicit permissions, returns kAll.
    ///
    /// @return Bitmask of KeyOperationPermission values.
    virtual KeyOperationPermission GetPermittedOperations() const noexcept = 0;

  protected:
    IKeyObject() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_OBJECTS_I_KEY_OBJECT_HPP
