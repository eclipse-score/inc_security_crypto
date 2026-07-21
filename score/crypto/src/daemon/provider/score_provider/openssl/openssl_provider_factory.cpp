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

#include "score/crypto/daemon/provider/score_provider/openssl/openssl_provider_factory.hpp"

#include <memory>

#include "score/crypto/daemon/common/types.hpp"
#include "score/crypto/daemon/provider/provider_manager.hpp"
#include "score/crypto/daemon/provider/score_provider/openssl/provider_openssl.hpp"

namespace score::crypto::daemon::provider::score_provider::openssl
{

bool OpenSSLProviderFactory::CreateAndRegister(ProviderManager& manager)
{
    auto openSSLProvider = std::make_shared<OpenSSL>();
    return manager.RegisterProvider(
        common::kProviderNameOpenSSL, openSSLProvider, common::CryptoProviderType::SOFTWARE);
}

}  // namespace score::crypto::daemon::provider::score_provider::openssl
