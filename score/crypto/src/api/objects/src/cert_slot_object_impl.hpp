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

#ifndef SCORE_CRYPTO_SRC_API_OBJECTS_SRC_CERT_SLOT_OBJECT_IMPL_HPP
#define SCORE_CRYPTO_SRC_API_OBJECTS_SRC_CERT_SLOT_OBJECT_IMPL_HPP

#include "score/crypto/src/api/objects/i_cert_slot_object.hpp"
#include "score/crypto/src/api/types/certificate.hpp"
#include "score/crypto/src/api/types/common.hpp"

namespace score
{

namespace crypto
{

/// @brief Concrete ICertSlotObject returned by ICryptoContext::GetCertSlotObject().
///
/// View-only; does not send any release IPC on destruction.
class CertSlotObjectImpl final : public ICertSlotObject
{
  public:
    CertSlotObjectImpl(CryptoResourceId id, bool is_occupied, bool has_crl);
    ~CertSlotObjectImpl() override = default;

    CertSlotObjectImpl(const CertSlotObjectImpl&) = delete;
    CertSlotObjectImpl& operator=(const CertSlotObjectImpl&) = delete;
    CertSlotObjectImpl(CertSlotObjectImpl&&) = delete;
    CertSlotObjectImpl& operator=(CertSlotObjectImpl&&) = delete;

    CryptoResourceId GetId() const noexcept override;
    ResourceType GetType() const noexcept override;
    bool IsOccupied() const noexcept override;
    bool HasCrl() const noexcept override;

  private:
    CryptoResourceId m_id;
    bool m_is_occupied;
    bool m_has_crl;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_OBJECTS_SRC_CERT_SLOT_OBJECT_IMPL_HPP
