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
/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/
#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_FILE_BACKED_SLOT_HANDLER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_SLOT_FILE_BACKED_SLOT_HANDLER_HPP

#include "score/crypto/src/daemon/cert_management/interfaces/i_cert_slot_handler.hpp"
#include "score/crypto/src/daemon/cert_management/slot/crl_handler.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_loader.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_writer.hpp"
#include "score/crypto/src/daemon/provider/cert_management/i_cert_parser.hpp"

#include <memory>
#include <string_view>

namespace score::crypto::daemon::cert_management
{
class FileBackedSlotHandler final : public ICertSlotHandler
{
  public:
    static constexpr std::size_t kMaxCertSize = 64U * 1024U;  // 64 KiB — ample for any X.509 cert or chain

    explicit FileBackedSlotHandler(provider::cert_management::ICertParser::Sptr parser) : m_parser{std::move(parser)} {}
    ~FileBackedSlotHandler() override = default;

    FileBackedSlotHandler(const FileBackedSlotHandler&) = delete;
    FileBackedSlotHandler& operator=(const FileBackedSlotHandler&) = delete;

    score::crypto::Expected<CertObject::Sptr, common::DaemonErrorCode> LoadCertificate(const CertSlotConfig&) override;
    score::crypto::Expected<score::crypto::CertificateSlotState, common::DaemonErrorCode> GetSlotState(
        const CertSlotConfig&) override;
    score::crypto::Expected<score::crypto::CertificateSlotInfo, common::DaemonErrorCode> GetSlotInfo(
        const CertSlotConfig&) override;
    bool HasCrl(const CertSlotConfig&) override;
    score::crypto::Expected<std::monostate, common::DaemonErrorCode> StoreCertificate(const CertSlotConfig&,
                                                                                      const CertObject&) override;
    score::crypto::Expected<std::monostate, common::DaemonErrorCode> ClearSlot(const CertSlotConfig&) override;
    score::crypto::Expected<std::vector<uint8_t>, common::DaemonErrorCode> LoadCrl(const CertSlotConfig&) override;
    score::crypto::Expected<std::monostate, common::DaemonErrorCode> StoreCrl(const CertSlotConfig&,
                                                                              score::crypto::span<const uint8_t>,
                                                                              score::crypto::FormatType) override;
    score::crypto::Expected<std::monostate, common::DaemonErrorCode> ClearCrl(const CertSlotConfig&) override;
    score::crypto::Expected<int64_t, common::DaemonErrorCode> GetCrlNextUpdate(const CertSlotConfig&) override;

  private:
    using Handler = CrlHandler;
    provider::cert_management::ICertParser::Sptr m_parser;
    Handler m_crl;
};
}  // namespace score::crypto::daemon::cert_management
#endif
