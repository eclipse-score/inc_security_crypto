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

#ifndef SCORE_MW_CRYPTO_API_OBJECTS_I_CERT_SLOT_OBJECT_HPP
#define SCORE_MW_CRYPTO_API_OBJECTS_I_CERT_SLOT_OBJECT_HPP

#include "score/mw/crypto/api/objects/i_crypto_object.hpp"

#include <memory>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Typed view of a persistent certificate storage location.
///
/// Provides occupancy query for a resource whose type is kCertSlot.
/// Obtained via ICryptoContext::GetCertSlotObject().
class ICertSlotObject : public ICryptoObject
{
  public:
    using Uptr = std::unique_ptr<ICertSlotObject>;

    ~ICertSlotObject() override = default;

    ICertSlotObject(const ICertSlotObject&) = delete;
    ICertSlotObject& operator=(const ICertSlotObject&) = delete;
    ICertSlotObject(ICertSlotObject&&) = default;
    ICertSlotObject& operator=(ICertSlotObject&&) = default;

    /// @brief Whether the certificate slot currently holds a certificate.
    virtual bool IsOccupied() const noexcept = 0;

  protected:
    ICertSlotObject() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_OBJECTS_I_CERT_SLOT_OBJECT_HPP
