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

#ifndef SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXPORTS_KEY_EXPORTER_HPP
#define SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXPORTS_KEY_EXPORTER_HPP

#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"

#include <memory>

namespace score::crypto::daemon::provider
{

/// Provider export policy used by the generic key-management executor.
/// The caller retains the owning KeyEntry and checks access and permissions.
class IKeyExporter
{
  public:
    virtual ~IKeyExporter() = default;

    [[nodiscard]] virtual Expected<key_management::SecureKeyBytes, common::DaemonErrorCode> ExportKey(
        const key_management::IKeyHandler& key,
        score::crypto::FormatType format) const = 0;

    [[nodiscard]] virtual Expected<std::size_t, common::DaemonErrorCode> GetExportKeySize(
        const key_management::IKeyHandler& key,
        score::crypto::FormatType format) const = 0;
};

/// Adapts existing key handlers and handle-based provider factories.
///
/// RAW material is exported by the handler when supported. Otherwise the
/// provider's existing formatted export is used, which may export public
/// material even when the handler refuses raw private-key material.
/// Other formats always use the provider factory. No key family is hardcoded.
class KeyExporter final : public IKeyExporter
{
  public:
    explicit KeyExporter(std::shared_ptr<key_management::IKeyFactory> factory);

    [[nodiscard]] Expected<key_management::SecureKeyBytes, common::DaemonErrorCode> ExportKey(
        const key_management::IKeyHandler& key,
        score::crypto::FormatType format) const override;

    [[nodiscard]] Expected<std::size_t, common::DaemonErrorCode> GetExportKeySize(
        const key_management::IKeyHandler& key,
        score::crypto::FormatType format) const override;

  private:
    std::shared_ptr<key_management::IKeyFactory> m_factory;
};

}  // namespace score::crypto::daemon::provider

#endif  // SCORE_CRYPTO_SRC_DAEMON_PROVIDER_EXPORTS_KEY_EXPORTER_HPP
