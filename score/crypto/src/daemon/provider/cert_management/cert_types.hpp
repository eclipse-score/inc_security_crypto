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
#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_CERT_TYPES_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_CERT_TYPES_HPP

#include "score/crypto/src/api/common/types.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_object.hpp"
#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/key_types.hpp"

#include <cstddef>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>

namespace score::crypto::daemon::provider::cert_management
{
using ::score::crypto::daemon::cert_management::CertObject;
using ::score::crypto::daemon::cert_management::CertSlotHandle;
using ::score::crypto::daemon::cert_management::TrustStoreHandle;

enum class ChainTerminationPolicy : std::uint8_t
{
    kRootRequired = 0,
    kTrustStoreTerminated = 1
};
enum class CertVerifyErrorCode : std::uint16_t
{
    kNone = 0,
    kExpired,
    kNotYetValid,
    kRevoked,
    kNoRootFound,
    kChainIncomplete,
    kSignatureInvalid,
    kInvalidPurpose,
    kUnknownAlgorithm,
    kUnknownError
};

/// Verification result. The established chain is returned as neutral CertObjects
/// (leaf-first, terminating anchor last), never as provider-bound handles.
struct CertVerifyResult
{
    bool is_valid{false};
    CertVerifyErrorCode error_code{CertVerifyErrorCode::kNone};
    std::vector<CertObject::Sptr> verified_chain;
};

struct CrlImportRequest
{
    const std::uint8_t* crl_data{nullptr};
    std::size_t crl_data_size{0};
    score::crypto::FormatType format{score::crypto::FormatType::kDer};
    CertSlotHandle cert_slot;
};
struct CsrGenerationRequest
{
    score::crypto::daemon::key_management::ProviderKeyHandle subject_key;
    std::string signature_algorithm;
    std::string subject_dn;
};

/// Chain-verification inputs. All certificates are provider-neutral CertObjects;
/// the service resolves client CryptoResourceIds to CertObjects before calling
/// the provider, so the provider surface never sees provider-bound cert handles.
struct VerificationRequest
{
    std::vector<CertObject::Sptr> chain;
    std::optional<TrustStoreHandle> trust_store;
    std::vector<CertObject::Sptr> standalone_trusted_certs;
    ChainTerminationPolicy chain_termination{ChainTerminationPolicy::kRootRequired};
    std::vector<CertObject::Sptr> additional_certificates;
    std::optional<std::vector<std::uint8_t>> ephemeral_crl;
    std::optional<CertSlotHandle> crl_slot;
    std::optional<std::vector<std::uint8_t>> ocsp_response;
    std::optional<std::int64_t> verification_time_epoch_s;
    score::crypto::RevocationCheckPolicy revocation_policy{score::crypto::RevocationCheckPolicy::kNone};
};
}  // namespace score::crypto::daemon::provider::cert_management

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_CERT_MANAGEMENT_CERT_TYPES_HPP
