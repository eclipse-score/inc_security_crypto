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

#ifndef SCORE_MW_CRYPTO_API_OBJECTS_I_SYMMETRIC_KEY_OBJECT_HPP
#define SCORE_MW_CRYPTO_API_OBJECTS_I_SYMMETRIC_KEY_OBJECT_HPP

#include "score/mw/crypto/api/objects/i_key_object.hpp"

#include <memory>
#include <string>
#include <vector>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Typed view of symmetric key material.
///
/// Extends IKeyObject with symmetric-specific queries such as
/// allowed cipher modes.  Obtained by down-casting an IKeyObject
/// whose algorithm is symmetric.
class ISymmetricKeyObject : public IKeyObject
{
  public:
    using Uptr = std::unique_ptr<ISymmetricKeyObject>;

    ~ISymmetricKeyObject() override = default;

    ISymmetricKeyObject(const ISymmetricKeyObject&) = delete;
    ISymmetricKeyObject& operator=(const ISymmetricKeyObject&) = delete;
    ISymmetricKeyObject(ISymmetricKeyObject&&) = default;
    ISymmetricKeyObject& operator=(ISymmetricKeyObject&&) = default;

    /// @brief Returns the cipher modes allowed for this key (e.g., "CBC", "GCM").
    virtual std::vector<std::string> GetAllowedModes() const = 0;

  protected:
    ISymmetricKeyObject() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_OBJECTS_I_SYMMETRIC_KEY_OBJECT_HPP
