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

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TRUSTSTORE_TRUST_STORE_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TRUSTSTORE_TRUST_STORE_HANDLER_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/i_trust_store_handler.hpp"

#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

namespace score::crypto::daemon::cert_management
{

class TrustStoreHandler final : public ITrustStoreHandler
{
  public:
    /// Called by TrustStoreManager to populate this handler's anchor cache on demand.
    /// The callee receives a reference to the handler and must call NotifySlotUpdate()
    /// for every member slot.
    using AnchorLoader = std::function<void(TrustStoreHandler&)>;

    TrustStoreHandler(TrustStoreHandle handle, AnchorLoader loader);

    TrustStoreHandle GetHandle() const noexcept override;

    score::crypto::Expected<std::vector<CertObject::Sptr>, common::DaemonErrorCode> GetAnchors() override;
    void NotifySlotUpdate(CertSlotHandle slot, CertObject::Sptr cert) override;

    CertObject::Sptr FindBySubject(const std::string& subject) const override;
    CertObject::Sptr FindBySkid(score::crypto::span<const uint8_t> skid) const override;

    /// Remove one slot's cached cert and force a full reload on the next GetAnchors() call.
    /// Called by TrustStoreManager when a member slot's content changes externally.
    void InvalidateSlot(CertSlotHandle slot);

    /// Drop all cached anchor strong-refs and reset the loaded flag.
    /// Called by TrustStoreManager when the last DataNode for this store is released,
    /// so that the CertObject memory is freed when no other store holds it.
    void ClearAnchorCache();

  private:
    void EnsureLoaded();
    std::vector<CertObject::Sptr> All() const;

    TrustStoreHandle m_handle{};
    std::unordered_map<uint32_t, CertObject::Sptr> m_slots;
    AnchorLoader m_loader;
    bool m_loaded{false};
};

}  // namespace score::crypto::daemon::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TRUSTSTORE_TRUST_STORE_HANDLER_HPP
