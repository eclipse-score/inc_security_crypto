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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_ALGORITHM_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_ALGORITHM_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/pqc_provider/include/pqc_provider_ffi.h"

namespace score::crypto::daemon::provider::score_provider::pqc_provider
{
/// @brief Map a PQC algorithm identifier to the PQC Provider enum value.
///
/// @return The corresponding PQC Provider algorithm, or
///         kUnsupportedAlgorithm if the identifier is unknown.
inline Expected<pqc_provider_algorithm, common::DaemonErrorCode> Algorithm(const AlgorithmDescriptor& algorithm)
{
    switch (algorithm.id)
    {
        case ::score::crypto::Algorithm::kMlDsa44:
            return PqcProviderAlgorithmMlDsa44;
        case ::score::crypto::Algorithm::kMlDsa65:
            return PqcProviderAlgorithmMlDsa65;
        case ::score::crypto::Algorithm::kMlDsa87:
            return PqcProviderAlgorithmMlDsa87;
        case ::score::crypto::Algorithm::kMlKem512:
            return PqcProviderAlgorithmMlKem512;
        case ::score::crypto::Algorithm::kMlKem768:
            return PqcProviderAlgorithmMlKem768;
        case ::score::crypto::Algorithm::kMlKem1024:
            return PqcProviderAlgorithmMlKem1024;
        default:
            return make_unexpected(common::DaemonErrorCode::kUnsupportedAlgorithm);
    }
}

/// @brief Return whether the provider maps this signature algorithm to its backend.
[[nodiscard]] inline bool IsSignatureSupported(const AlgorithmDescriptor& algorithm) noexcept
{
    return algorithm.key_type == ::score::crypto::KeyType::kMlDsa && algorithm.output_size != 0U &&
           Algorithm(algorithm).has_value();
}
}  // namespace score::crypto::daemon::provider::score_provider::pqc_provider

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_PQC_PROVIDER_ALGORITHM_HPP
