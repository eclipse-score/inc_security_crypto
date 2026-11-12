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

#ifndef SCORE_CRYPTO_SRC_API_CERTIFICATE_I_CSR_EXPORT_HPP
#define SCORE_CRYPTO_SRC_API_CERTIFICATE_I_CSR_EXPORT_HPP

#include "score/result/result.h"
#include "score/span.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string_view>

namespace score::crypto
{
/// Owns the public DER PKCS#10 request independently of its generating context.
/// No signing key material is returned. Submission is the application's responsibility.
class ICsrExport
{
  public:
    using Uptr = std::unique_ptr<ICsrExport>;
    virtual ~ICsrExport() = default;
    virtual std::size_t GetEncodedCsrLength() const noexcept = 0;
    /// A short buffer fails without writing any bytes.
    virtual score::Result<std::size_t> GetEncodedCsr(score::cpp::span<uint8_t> output) const = 0;
    /// Borrowed view valid for this export's lifetime; never sent to the daemon.
    virtual std::string_view GetSubmissionUrl() const noexcept = 0;
};
}  // namespace score::crypto
#endif  // SCORE_CRYPTO_SRC_API_CERTIFICATE_I_CSR_EXPORT_HPP
