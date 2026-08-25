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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TRUSTSTORE_CONFIG_DRIVEN_TRUST_STORE_CATALOG_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TRUSTSTORE_CONFIG_DRIVEN_TRUST_STORE_CATALOG_HPP

#include "score/crypto/src/daemon/cert_management/slot/slot_registry.hpp"
#include "score/crypto/src/daemon/cert_management/truststore/trust_store_manager.hpp"
#include "score/crypto/src/daemon/config/inc/config.hpp"

#include <string_view>

namespace score::crypto::daemon::cert_management
{

/// @brief One-shot loader that populates a TrustStoreManager from CertificateConfig.
///
/// Mirrors the role of ConfigDrivenSlotCatalog for cert slots: converts each
/// CertificateConfig::TrustStoreEntry into a TrustStoreConfig and delegates to
/// TrustStoreManager::Load(). Must be called after CertSlotRegistry is fully
/// populated (slot name resolution happens inside TrustStoreManager::Load()).
class ConfigDrivenTrustStoreCatalog final
{
  public:
    explicit ConfigDrivenTrustStoreCatalog(const config::CertificateConfig& config);

    /// @brief Adapt config entries and populate the trust store manager.
    ///
    /// @param manager   The TrustStoreManager to populate.
    /// @param registry  Fully-populated CertSlotRegistry for member slot resolution.
    /// @param factory   Certificate factory for loading static anchor files (may be null).
    void Load(TrustStoreManager& manager,
              CertSlotRegistry::Sptr registry,
              CertSlotHandlerFactory slot_handler_factory = {});

  private:
    const config::CertificateConfig& m_config;

    static constexpr std::string_view kLogPrefix = "[CERT_TRUST_STORE_CATALOG] ";
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TRUSTSTORE_CONFIG_DRIVEN_TRUST_STORE_CATALOG_HPP
