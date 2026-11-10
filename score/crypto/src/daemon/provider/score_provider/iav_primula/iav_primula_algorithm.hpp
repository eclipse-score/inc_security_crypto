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

#ifndef SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_ALGORITHM_HPP
#define SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_ALGORITHM_HPP

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/algorithm_catalog.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"
#include "score/iav_primula/include/iav_primula_ffi.h"

namespace score::crypto::daemon::provider::score_provider::iav_primula
{
/// @brief Map a PQC algorithm identifier to the IAV-Primula enum value.
///
/// @return The corresponding IAV-Primula algorithm, or
///         kUnsupportedAlgorithm if the identifier is unknown.
inline Expected<iav_algorithm, common::DaemonErrorCode> Algorithm(const AlgorithmDescriptor& algorithm)
{
    switch (algorithm.id)
    {
        case ::score::crypto::Algorithm::kMlDsa44:
            return IavAlgorithmMlDsa44;
        case ::score::crypto::Algorithm::kMlDsa65:
            return IavAlgorithmMlDsa65;
        case ::score::crypto::Algorithm::kMlDsa87:
            return IavAlgorithmMlDsa87;
        case ::score::crypto::Algorithm::kMlKem512:
            return IavAlgorithmMlKem512;
        case ::score::crypto::Algorithm::kMlKem768:
            return IavAlgorithmMlKem768;
        case ::score::crypto::Algorithm::kMlKem1024:
            return IavAlgorithmMlKem1024;
        default:
            return make_unexpected(common::DaemonErrorCode::kUnsupportedAlgorithm);
    }
}
}  // namespace score::crypto::daemon::provider::score_provider::iav_primula

#endif  // SCORE_CRYPTO_DAEMON_PROVIDER_IAV_PRIMULA_ALGORITHM_HPP
