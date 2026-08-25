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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_DETAIL_SLOT_INFO_BUILDER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_DETAIL_SLOT_INFO_BUILDER_HPP

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_slot_config.hpp"

namespace score::crypto::daemon::cert_management::detail
{

inline score::crypto::CertificateSlotInfo BuildCertSlotInfo(const CertSlotConfig& /*slot*/,
                                                            score::crypto::CertificateSlotState state,
                                                            bool has_crl) noexcept
{
    score::crypto::CertificateSlotInfo info{};
    info.state = state;
    info.has_crl = has_crl;
    return info;
}

}  // namespace score::crypto::daemon::cert_management::detail

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_DETAIL_SLOT_INFO_BUILDER_HPP
