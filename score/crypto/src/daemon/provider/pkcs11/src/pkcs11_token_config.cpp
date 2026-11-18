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

#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_token_config.hpp"

#include "score/crypto/src/daemon/common/secure_memory.hpp"

#include <utility>

namespace score::crypto::daemon::provider::pkcs11
{

void SecureClearPins(Pkcs11ProviderFactoryConfig& config) noexcept
{
    for (auto& token : config.tokens)
    {
        common::SecureZeroizeAndClear(token.userPin);
    }
}

Pkcs11Config::~Pkcs11Config()
{
    SecureClearPins(m_config);
}

const Pkcs11ProviderFactoryConfig& Pkcs11Config::GetConfig() const
{
    return m_config;
}

Pkcs11ProviderFactoryConfig Pkcs11Config::TakeConfig()
{
    auto result = std::move(m_config);
    SecureClearPins(m_config);
    m_config = Pkcs11ProviderFactoryConfig{};
    return result;
}

}  // namespace score::crypto::daemon::provider::pkcs11
