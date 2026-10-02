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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_CONFIG_DRIVEN_SLOT_CATALOG_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_CONFIG_DRIVEN_SLOT_CATALOG_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_catalog.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"

#include <string_view>

namespace score::crypto::daemon::cert_management
{

/// @brief ICertSlotCatalog that reads certificate slot definitions from CertificateConfig.
///
/// Production catalog: converts each CertificateConfig::CertSlotEntry into a
/// CertSlotConfig and registers it with the CertSlotRegistry.
class ConfigDrivenSlotCatalog final : public ICertSlotCatalog
{
  public:
    explicit ConfigDrivenSlotCatalog(const config::CertificateConfig& cert_config);
    ~ConfigDrivenSlotCatalog() override = default;

    /// @copydoc ICertSlotCatalog::Load
    void Load(CertSlotRegistry& registry) override;

  private:
    const config::CertificateConfig& m_cert_config;

    static constexpr std::string_view kLogPrefix = "[CERT_CONFIG_DRIVEN_CATALOG] ";
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_CONFIG_DRIVEN_SLOT_CATALOG_HPP
