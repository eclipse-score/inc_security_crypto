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

CertSlotObjectImpl::CertSlotObjectImpl(CryptoResourceId id, CertificateSlotInfo info) : m_id(id), m_info(info) {}

CryptoResourceId CertSlotObjectImpl::GetId() const noexcept
{
    return m_id;
}

ResourceType CertSlotObjectImpl::GetType() const noexcept
{
    return ResourceType::kCertSlot;
}

CertificateSlotInfo CertSlotObjectImpl::GetInfo() const
{
    return m_info;
}

CertificateSlotState CertSlotObjectImpl::GetState() const noexcept
{
    return m_info.state;
}

bool CertSlotObjectImpl::HasCrl() const noexcept
{
    return m_info.has_crl;
}

}  // namespace crypto

}  // namespace score
