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

/// @file pqc_provider_backend_adapter.hpp
/// @brief Backend adapter for the PQC Provider score provider.

#ifndef SCORE_CRYPTO_SRC_BACKEND_PROVIDER_PQC_PROVIDER_ADAPTER_HPP
#define SCORE_CRYPTO_SRC_BACKEND_PROVIDER_PQC_PROVIDER_ADAPTER_HPP

#include "score/crypto/src/daemon/provider/score_provider/score_backend_adapter.hpp"

namespace score::crypto::backend::score_provider::pqc_provider
{

/// @brief PQC Provider backend adapter for the score provider family.
///
/// Provides factory creation metadata for the PQC Provider post-quantum
/// crypto backend. This adapter is included at compile time via
/// backend/score_provider/active_backends_list.hpp when the PqcProvider backend
/// is enabled in the Bazel configuration.
///
/// The PQC Provider backend implementation lives in:
///   - daemon/provider/score_provider/pqc_provider/pqc_provider.*
///   - daemon/provider/score_provider/pqc_provider/operations/*
///
/// This adapter provides backend metadata and creates the corresponding
/// provider instance. Cryptographic operations are implemented by the
/// PQC Provider provider and its handlers.
class PqcProviderBackendAdapter final : public daemon::provider::score_provider::IBackendProviderAdapter
{
  public:
    PqcProviderBackendAdapter() = default;
    ~PqcProviderBackendAdapter() override = default;

    PqcProviderBackendAdapter(const PqcProviderBackendAdapter&) = delete;
    PqcProviderBackendAdapter& operator=(const PqcProviderBackendAdapter&) = delete;
    PqcProviderBackendAdapter(PqcProviderBackendAdapter&&) = delete;
    PqcProviderBackendAdapter& operator=(PqcProviderBackendAdapter&&) = delete;

    /// @brief Get the provider creator for the PQC Provider backend.
    ///
    /// Returns:
    ///   - backend_id:    "pqc_provider"
    ///   - backend_name:  "PQC_PROVIDER"
    ///   - provider_type: "SPECIALIZED"
    ///   - create_provider: constructs and returns an PqcProvider
    [[nodiscard]] daemon::provider::score_provider::ProviderCreator GetProviderCreator() const override;
};

}  // namespace score::crypto::backend::score_provider::pqc_provider

#endif  // SCORE_CRYPTO_SRC_BACKEND_PROVIDER_PQC_PROVIDER_ADAPTER_HPP
