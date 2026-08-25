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

namespace score::crypto::daemon::provider::pkcs11
{

score::crypto::Expected<std::monostate, common::DaemonErrorCode> Pkcs11Config::ParseConfig(config::Config& config)
{
    (void)config;

    if (!m_config.tokens.empty())
    {
        return std::monostate{};
    }
    Pkcs11TokenEntry entry{};
#if USE_RUST_PKCS11
    entry.tokenLabel = "ValeoCryptokiToken";
    entry.userPin = "1234";
    entry.providerName = "PKCS11_ENGINE";
#else
    entry.tokenLabel = "SoftHSM";
    entry.userPin = "1234";
    entry.providerName = "PKCS11_ENGINE";
#endif
    entry.useHardCleanup = true;
    m_config.tokens.push_back(std::move(entry));

    return std::monostate{};
}

}  // namespace score::crypto::daemon::provider::pkcs11
