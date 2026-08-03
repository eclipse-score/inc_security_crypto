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

#ifndef SCORE_CRYPTO_SRC_BACKEND_SCORE_PROVIDER_OPENSSL_OPENSSL_BACKEND_ADAPTER_HPP
#define SCORE_CRYPTO_SRC_BACKEND_SCORE_PROVIDER_OPENSSL_OPENSSL_BACKEND_ADAPTER_HPP

#include "score/crypto/src/daemon/provider/score_provider/score_backend_adapter.hpp"

namespace score::crypto::backend::score_provider::openssl
{

/// @brief OpenSSL backend adapter for score provider family
///
/// Provides factory creation metadata for the OpenSSL crypto backend.
/// This adapter is discovered at compile-time via
/// backend/score_provider/active_backends_list.hpp.
///
/// The OpenSSL backend implementation lives in:
///   - daemon/provider/score_provider/openssl/provider_openssl.*
///   - daemon/provider/score_provider/openssl/operations/*
///
/// This adapter serves as the registration/enablement layer only.
class OpenSSLBackendAdapter final : public daemon::provider::score_provider::IBackendProviderAdapter
{
  public:
    OpenSSLBackendAdapter() = default;
    ~OpenSSLBackendAdapter() override = default;

    OpenSSLBackendAdapter(const OpenSSLBackendAdapter&) = delete;
    OpenSSLBackendAdapter& operator=(const OpenSSLBackendAdapter&) = delete;
    OpenSSLBackendAdapter(OpenSSLBackendAdapter&&) = delete;
    OpenSSLBackendAdapter& operator=(OpenSSLBackendAdapter&&) = delete;

    /// @brief Get provider creator for the OpenSSL backend.
    ///
    /// Returns:
    ///   - backend_id:    "openssl"
    ///   - backend_name:  "OPENSSL"
    ///   - provider_type: "SOFTWARE"
    ///   - create_provider: constructs and returns a unique_ptr<OpenSSL>
    [[nodiscard]] daemon::provider::score_provider::ProviderCreator GetProviderCreator() const override;
};

}  // namespace score::crypto::backend::score_provider::openssl

#endif  // SCORE_CRYPTO_SRC_BACKEND_SCORE_PROVIDER_OPENSSL_OPENSSL_BACKEND_ADAPTER_HPP
