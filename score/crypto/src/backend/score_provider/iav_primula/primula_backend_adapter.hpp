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

/// @file primula_backend_adapter.hpp
/// @brief Backend adapter for the IAV-Primula score provider.

#ifndef SCORE_CRYPTO_SRC_BACKEND_PROVIDER_IAV_PRIMULA_ADAPTER_HPP
#define SCORE_CRYPTO_SRC_BACKEND_PROVIDER_IAV_PRIMULA_ADAPTER_HPP

#include "score/crypto/src/daemon/provider/score_provider/score_backend_adapter.hpp"

namespace score::crypto::backend::score_provider::primula
{

/// @brief IAV-Primula backend adapter for the score provider family.
///
/// Provides factory creation metadata for the IAV-Primula post-quantum
/// crypto backend. This adapter is included at compile time via
/// backend/score_provider/active_backends_list.hpp when the Primula backend
/// is enabled in the Bazel configuration.
///
/// The IAV-Primula backend implementation lives in:
///   - daemon/provider/score_provider/iav_primula/iav_primula_provider.*
///   - daemon/provider/score_provider/iav_primula/operations/*
///
/// This adapter provides backend metadata and creates the corresponding
/// provider instance. Cryptographic operations are implemented by the
/// IAV-Primula provider and its handlers.
class PrimulaBackendAdapter final : public daemon::provider::score_provider::IBackendProviderAdapter
{
  public:
    PrimulaBackendAdapter() = default;
    ~PrimulaBackendAdapter() override = default;

    PrimulaBackendAdapter(const PrimulaBackendAdapter&) = delete;
    PrimulaBackendAdapter& operator=(const PrimulaBackendAdapter&) = delete;
    PrimulaBackendAdapter(PrimulaBackendAdapter&&) = delete;
    PrimulaBackendAdapter& operator=(PrimulaBackendAdapter&&) = delete;

    /// @brief Get the provider creator for the IAV-Primula backend.
    ///
    /// Returns:
    ///   - backend_id:    "primula"
    ///   - backend_name:  "PRIMULA"
    ///   - provider_type: "SPECIALIZED"
    ///   - create_provider: constructs and returns an IavPrimulaProvider
    [[nodiscard]] daemon::provider::score_provider::ProviderCreator GetProviderCreator() const override;
};

}  // namespace score::crypto::backend::score_provider::primula

#endif  // SCORE_CRYPTO_SRC_BACKEND_PROVIDER_IAV_PRIMULA_ADAPTER_HPP
