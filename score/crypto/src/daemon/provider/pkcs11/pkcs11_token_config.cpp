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

#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider_factory.hpp"

namespace score::crypto::daemon::provider::pkcs11
{

void Pkcs11Config::Configure(Pkcs11ProviderFactory& factory) const
{
    factory.SetTokenConfigs(m_tokens);
}

}  // namespace score::crypto::daemon::provider::pkcs11
