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

#ifndef SCORE_CRYPTO_SRC_COMMON_CSR_WIRE_HPP
#define SCORE_CRYPTO_SRC_COMMON_CSR_WIRE_HPP

#include "score/crypto/src/api/csr/csr_template.hpp"
#include "score/crypto/src/common/csr_wire_generated.h"

#include <memory>

namespace score::crypto::csr::wire
{
using Action = fb::Action;
using Document = fb::DocumentT;
using Bytes = std::vector<std::uint8_t>;
inline constexpr std::size_t kMaxWireBytes = 262144U;
// Wire overhead is independent of the original 16 KiB request / 64 KiB DER
// document limits, which the native processing bodies still enforce.
score::Result<Bytes> Encode(const Document& value);
score::Result<Document> Decode(score::cpp::span<const std::uint8_t> bytes);
bool ResponseShape(const Document& value) noexcept;
Document Request(Action action, const CsrRequest& request);
CsrRequest ReadRequest(const Document& value);
Document Template(Action action, const CsrTemplate& value);
CsrTemplate ReadTemplate(const Document& value);
Document Prepared(Action action, const PreparedCsrTemplate& value);
PreparedCsrTemplate ReadPrepared(const Document& value);
struct Access
{
    static CsrSubject Subject(const std::vector<std::unique_ptr<fb::EntryT>>& entries);
};
}  // namespace score::crypto::csr::wire
#endif  // SCORE_CRYPTO_SRC_COMMON_CSR_WIRE_HPP
