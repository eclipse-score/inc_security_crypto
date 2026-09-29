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

#ifndef SCORE_CRYPTO_SRC_API_OBJECTS_I_CERT_SLOT_OBJECT_HPP
#define SCORE_CRYPTO_SRC_API_OBJECTS_I_CERT_SLOT_OBJECT_HPP

#include "score/crypto/src/api/objects/i_crypto_object.hpp"
#include "score/crypto/src/api/types/certificate.hpp"

#include <memory>

namespace score
{

namespace crypto
{

/// @brief Typed view of a persistent certificate storage location.
///
/// Provides state and CRL-presence queries for a resource whose type is kCertSlot.
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

    /// @brief Returns the certificate slot state and whether it stores a CRL.
    virtual CertificateSlotInfo GetInfo() const = 0;

    /// @brief Returns the current state of the certificate slot.
    virtual CertificateSlotState GetState() const noexcept = 0;

    /// @brief Whether the slot currently stores a persistent CRL.
    virtual bool HasCrl() const noexcept = 0;

  protected:
    ICertSlotObject() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_OBJECTS_I_CERT_SLOT_OBJECT_HPP
