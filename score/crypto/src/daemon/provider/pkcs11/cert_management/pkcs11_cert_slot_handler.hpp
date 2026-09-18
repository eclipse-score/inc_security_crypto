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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_CERT_MANAGEMENT_PKCS11_CERT_SLOT_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_CERT_MANAGEMENT_PKCS11_CERT_SLOT_HANDLER_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/slot/crl_handler.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"

#include <pkcs11.h>

#include <memory>

namespace score::crypto::daemon::provider::pkcs11
{
namespace daemon_cert_management = ::score::crypto::daemon::cert_management;

class Pkcs11Module;
class Pkcs11Provider;

/// Certificate-slot handler for X.509 objects stored on a PKCS#11 token.
///
/// The deployment descriptor contains stable token locators (`pkcs11.label`
/// and/or `pkcs11.object_id`); session-specific object handles are never stored.
/// Certificate bytes are written to and read from CKA_VALUE and parsed by the
/// injected provider-neutral certificate parser.
class Pkcs11CertSlotHandler final : public daemon_cert_management::ICertSlotHandler
{
  public:
    Pkcs11CertSlotHandler(std::shared_ptr<Pkcs11Provider> provider,
                          std::weak_ptr<Pkcs11Module> module,
                          provider::cert_management::ICertParser::Sptr parser);
    ~Pkcs11CertSlotHandler() override = default;

    Pkcs11CertSlotHandler(const Pkcs11CertSlotHandler&) = delete;
    Pkcs11CertSlotHandler& operator=(const Pkcs11CertSlotHandler&) = delete;
    Pkcs11CertSlotHandler(Pkcs11CertSlotHandler&&) = delete;
    Pkcs11CertSlotHandler& operator=(Pkcs11CertSlotHandler&&) = delete;

    [[nodiscard]] score::crypto::Expected<daemon_cert_management::CertObject::Sptr, common::DaemonErrorCode>
    LoadCertificate(const daemon_cert_management::CertSlotConfig&) override;

    [[nodiscard]] score::crypto::Expected<score::crypto::CertificateSlotState, common::DaemonErrorCode> GetSlotState(
        const daemon_cert_management::CertSlotConfig&) override;

    [[nodiscard]] score::crypto::Expected<score::crypto::CertificateSlotInfo, common::DaemonErrorCode> GetSlotInfo(
        const daemon_cert_management::CertSlotConfig&) override;

    // CRL data for a PKCS#11-backed cert slot is stored on the filesystem
    // via the deployment descriptor's [crl] section — tokens lack a native CRL type.
    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> StoreCertificate(
        const daemon_cert_management::CertSlotConfig&,
        const daemon_cert_management::CertObject&) override;

    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> ClearSlot(
        const daemon_cert_management::CertSlotConfig&) override;

    [[nodiscard]] score::crypto::Expected<bool, common::DaemonErrorCode> HasCrl(
        const daemon_cert_management::CertSlotConfig&) override;

    [[nodiscard]] score::crypto::Expected<std::vector<uint8_t>, common::DaemonErrorCode> LoadCrl(
        const daemon_cert_management::CertSlotConfig&) override;

    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> StoreCrl(
        const daemon_cert_management::CertSlotConfig&,
        score::crypto::span<const uint8_t>,
        score::crypto::FormatType,
        std::optional<score::crypto::CrlMetadata> metadata = std::nullopt) override;

    [[nodiscard]] score::crypto::Expected<std::monostate, common::DaemonErrorCode> ClearCrl(
        const daemon_cert_management::CertSlotConfig&) override;

    [[nodiscard]] score::crypto::Expected<int64_t, common::DaemonErrorCode> GetCrlNextUpdate(
        const daemon_cert_management::CertSlotConfig&) override;

    [[nodiscard]] score::crypto::FormatType GetCrlFormat(const daemon_cert_management::CertSlotConfig&) override;
    [[nodiscard]] std::optional<score::crypto::CrlMetadata> GetCrlMetadata(
        const daemon_cert_management::CertSlotConfig&) override;

  private:
    struct LocatedCertificate
    {
        CK_SESSION_HANDLE session{CK_INVALID_HANDLE};
        CK_OBJECT_HANDLE object{CK_INVALID_HANDLE};
    };

    [[nodiscard]] score::crypto::Expected<LocatedCertificate, common::DaemonErrorCode> Locate(
        const daemon_cert_management::CertSlotConfig&);

    using Handler = daemon_cert_management::CrlHandler;
    std::shared_ptr<Pkcs11Provider> m_provider;
    std::weak_ptr<Pkcs11Module> m_module;
    provider::cert_management::ICertParser::Sptr m_parser;
    Handler m_crl;
};
}  // namespace score::crypto::daemon::provider::pkcs11

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_PKCS11_CERT_MANAGEMENT_PKCS11_CERT_SLOT_HANDLER_HPP
