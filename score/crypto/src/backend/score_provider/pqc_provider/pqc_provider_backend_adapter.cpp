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

#include "pqc_provider_backend_adapter.hpp"

#include "score/crypto/src/daemon/provider/score_provider/pqc_provider/pqc_provider.hpp"

#include <string>
#include <string_view>

namespace score::crypto::backend::score_provider::pqc_provider
{

namespace
{

constexpr std::string_view kProviderName{"PQC_PROVIDER"};

}  // namespace

daemon::provider::score_provider::ProviderCreator PqcProviderBackendAdapter::GetProviderCreator() const
{
    using namespace daemon::provider::score_provider;

    return ProviderCreator{
        .backend_id = "pqc_provider",
        .backend_name = std::string{kProviderName},
        // PQC Provider provides post-quantum algorithms only. Mark it as SPECIALIZED
        // so that it is not selected for generic SOFTWARE algorithms such as SHA-256
        // or HMAC, which are provided by OpenSSL.
        .provider_type = "SPECIALIZED",
        .create_provider = []() -> std::unique_ptr<daemon::provider::IProvider> {
            return std::make_unique<daemon::provider::score_provider::pqc_provider::PqcProvider>();
        }};
}

}  // namespace score::crypto::backend::score_provider::pqc_provider
