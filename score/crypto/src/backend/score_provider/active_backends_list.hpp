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

#ifndef SCORE_CRYPTO_SRC_BACKEND_SCORE_PROVIDER_ACTIVE_BACKENDS_LIST_HPP
#define SCORE_CRYPTO_SRC_BACKEND_SCORE_PROVIDER_ACTIVE_BACKENDS_LIST_HPP

#include "score/crypto/src/daemon/provider/score_provider/score_backend_adapter.hpp"

#include <memory>
#include <vector>

// Include enabled backend adapters (controlled by BUILD file defines)
#ifdef SCORE_BACKEND_OPENSSL_ENABLED
#include "score/crypto/src/backend/score_provider/openssl/openssl_backend_adapter.hpp"
#endif

#ifdef SCORE_BACKEND_PRIMULA_ENABLED
#include "score/crypto/src/backend/score_provider/iav_primula/primula_backend_adapter.hpp"
#endif

namespace score::crypto::backend::score_provider
{

/// @brief Get list of active score provider backends
///
/// Returns a vector of backend adapters for all backends enabled in
/// backend/score_provider/BUILD. Backends are enabled via preprocessor defines set
/// in the BUILD file (e.g., SCORE_BACKEND_OPENSSL_ENABLED).
///
/// Each backend adapter provides factory creation metadata (backend_id,
/// backend_name, create_provider function) that ScoreProviderFactory
/// uses to instantiate provider factories.
///
/// @return Vector of IBackendProviderAdapter instances (one per enabled backend)
///
/// @note This function creates new adapter instances on each call.
///       No global state is maintained.
inline std::vector<std::unique_ptr<daemon::provider::score_provider::IBackendProviderAdapter>> GetActiveBackends()
{
    std::vector<std::unique_ptr<daemon::provider::score_provider::IBackendProviderAdapter>> backends;

// Reserve space if we know how many backends are enabled
#ifdef SCORE_BACKEND_OPENSSL_ENABLED
    backends.reserve(backends.capacity() + 1);
#endif
#ifdef SCORE_BACKEND_PRIMULA_ENABLED
    backends.reserve(backends.capacity() + 1);
#endif

// Instantiate enabled backend adapters
#ifdef SCORE_BACKEND_OPENSSL_ENABLED
    backends.push_back(std::make_unique<openssl::OpenSSLBackendAdapter>());
#endif

#ifdef SCORE_BACKEND_PRIMULA_ENABLED
    backends.push_back(std::make_unique<primula::PrimulaBackendAdapter>());
#endif

    return backends;
}

}  // namespace score::crypto::backend::score_provider

#endif  // SCORE_CRYPTO_SRC_BACKEND_SCORE_PROVIDER_ACTIVE_BACKENDS_LIST_HPP
