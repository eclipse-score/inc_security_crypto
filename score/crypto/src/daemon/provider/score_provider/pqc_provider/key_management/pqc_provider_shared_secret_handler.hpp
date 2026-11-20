/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 * See the NOTICE file(s) distributed with this work for additional information.
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0:
 * https://www.apache.org/licenses/LICENSE-2.0
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#ifndef SCORE_CRYPTO_PQC_PROVIDER_SHARED_SECRET_HANDLER_HPP
#define SCORE_CRYPTO_PQC_PROVIDER_SHARED_SECRET_HANDLER_HPP

#include "score/crypto/src/daemon/key_management/interfaces/i_key_handler.hpp"

namespace score::crypto::daemon::provider::score_provider::pqc_provider
{

/// Owns ephemeral KEM output in daemon memory. This material can only be used
/// as provider-side KDF input: it cannot be exported or used as an asymmetric key.
class PqcProviderSharedSecretHandler final : public key_management::IKeyHandler
{
  public:
    PqcProviderSharedSecretHandler(key_management::SecureKeyBytes secret, common::ProviderId provider_id);
    ~PqcProviderSharedSecretHandler() override;

    [[nodiscard]] const key_management::ProviderKeyHandle& GetHandle() const noexcept override;
    [[nodiscard]] common::ProviderId GetProviderId() const noexcept override;
    [[nodiscard]] Expected<std::monostate, common::DaemonErrorCode> Release() override;
    [[nodiscard]] Expected<key_management::SecureKeyBytes, common::DaemonErrorCode> Export() const override;

  private:
    key_management::SecureKeyBytes m_secret;
    key_management::ProviderKeyHandle m_handle;
};

}  // namespace score::crypto::daemon::provider::score_provider::pqc_provider
#endif
