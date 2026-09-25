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

#include "score/crypto/src/api/objects/src/cert_slot_object_impl.hpp"

namespace score
{

namespace crypto
{

CertSlotObjectImpl::CertSlotObjectImpl(CryptoResourceId id, bool is_occupied, bool has_crl)
    : m_id(id), m_is_occupied(is_occupied), m_has_crl(has_crl)
{
}

CryptoResourceId CertSlotObjectImpl::GetId() const noexcept
{
    return m_id;
}

ResourceType CertSlotObjectImpl::GetType() const noexcept
{
    return ResourceType::kCertSlot;
}

bool CertSlotObjectImpl::IsOccupied() const noexcept
{
    return m_is_occupied;
}

bool CertSlotObjectImpl::HasCrl() const noexcept
{
    return m_has_crl;
}

}  // namespace crypto

}  // namespace score
