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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_I_CERT_PARSER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_I_CERT_PARSER_HPP

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <vector>

namespace score::crypto::daemon::cert_management
{
class CertObject;
}

namespace score::crypto::daemon::provider::cert_management
{

/// Narrow provider capability: parse certificate bytes into a provider-neutral
/// CertObject. This is the only cross-boundary cert interface on IProvider —
/// used exclusively by FileBackedSlotHandler at startup to reconstruct a
/// CertObject from persisted bytes. All other cert operations (verification,
/// CSR generation, format conversion, public-key extraction) are performed
/// inside certificate context handlers created by ICryptoHandlerFactory.
class ICertParser
{
  public:
    using Sptr = std::shared_ptr<ICertParser>;
    virtual ~ICertParser() = default;

    /// Parse a single DER/PEM certificate into a neutral CertObject.
    [[nodiscard]] virtual score::crypto::Expected<std::shared_ptr<score::crypto::daemon::cert_management::CertObject>,
                                                  common::DaemonErrorCode>
    ParseCertificate(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format) = 0;

    /// Parse one or more concatenated certificates (e.g. a PEM bundle).
    [[nodiscard]] virtual score::crypto::Expected<
        std::vector<std::shared_ptr<score::crypto::daemon::cert_management::CertObject>>,
        common::DaemonErrorCode>
    ParseCertificates(const std::uint8_t* bytes, std::size_t size, score::crypto::FormatType format) = 0;
};

}  // namespace score::crypto::daemon::provider::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_I_CERT_PARSER_HPP
