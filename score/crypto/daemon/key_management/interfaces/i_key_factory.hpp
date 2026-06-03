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

#ifndef SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_I_KEY_FACTORY_HPP
#define SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_I_KEY_FACTORY_HPP

#include "score/crypto/common/types.hpp"
#include "score/crypto/daemon/common/daemon_error.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_handler.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_slot_config.hpp"
#include "score/crypto/daemon/key_management/interfaces/key_types.hpp"
#include "score/mw/crypto/api/common/types.hpp"

#include <cstddef>
#include <memory>

namespace score::crypto::daemon::key_management
{

class IKeySlotHandler;

/// Provider-side factory for creating and importing key material.
///
/// Each provider backend (OpenSSL, PKCS#11, TEE) implements this interface.
/// The factory is a long-lived singleton per provider: it is constructed once
/// during provider initialization and shared across all daemon operations.
///
/// Every successful method returns an IKeyHandler::Sptr. The caller transfers
/// ownership to a KeyDataNode via KeyManagementService::RegisterKeyMaterial().
///
/// Methods other than GenerateKey have default implementations that return
/// kNotSupported, so providers implement only what they support.
class IKeyFactory
{
  public:
    using Sptr = std::shared_ptr<IKeyFactory>;

    IKeyFactory() = default;

    virtual ~IKeyFactory() = default;

    IKeyFactory(const IKeyFactory&) = delete;
    IKeyFactory& operator=(const IKeyFactory&) = delete;
    IKeyFactory(IKeyFactory&&) = delete;
    IKeyFactory& operator=(IKeyFactory&&) = delete;

    /// Generate a new symmetric or asymmetric key.
    ///
    /// The provider determines key size from request.algorithm.
    ///
    /// Default: returns kNotSupported.
    [[nodiscard]] virtual score::crypto::Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode>
    GenerateKey(const KeyGenerationRequest& request);

    /// Import raw key material.
    ///
    /// request.key_data is caller-owned and valid only for the duration of the
    /// call. The implementation must copy the bytes immediately.
    ///
    /// Default: returns kNotSupported.
    [[nodiscard]] virtual score::crypto::Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode>
    ImportKey(const KeyImportRequest& request);

    /// Derive a child key using the specified KDF.
    ///
    /// Default: returns kNotSupported.
    [[nodiscard]] virtual score::crypto::Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode>
    DeriveKey(const KeyDeriveRequest& request);

    /// Perform key agreement and optionally apply a KDF in one atomic step.
    ///
    /// Default: returns kNotSupported.
    [[nodiscard]] virtual score::crypto::Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode>
    AgreeKey(const KeyAgreeRequest& request);

    /// Wrap a key under a wrapping key and return the ciphertext blob.
    ///
    /// Both handles must belong to this provider.
    /// Default: returns kNotSupported.
    [[nodiscard]] virtual score::crypto::Expected<SecureKeyBytes, score::crypto::daemon::common::DaemonErrorCode>
    WrapKey(const WrapKeyRequest& request);

    /// Return the byte length the wrapped blob will occupy.
    ///
    /// Default: returns kNotSupported.
    [[nodiscard]] virtual score::crypto::Expected<std::size_t, score::crypto::daemon::common::DaemonErrorCode>
    GetWrapKeySize(const WrapKeyRequest& request);

    /// Unwrap a wrapped key blob and return a live key handler.
    ///
    /// Default: returns kNotSupported.
    [[nodiscard]] virtual score::crypto::Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode>
    UnwrapKey(const UnwrapKeyRequest& request);

    /// Export formatted key material (DER / PEM / RAW).
    ///
    /// Used for asymmetric keys where formatting is provider-specific.
    /// For raw symmetric bytes, prefer IKeyHandler::Export().
    /// Default: returns kNotSupported.
    [[nodiscard]] virtual score::crypto::Expected<SecureKeyBytes, score::crypto::daemon::common::DaemonErrorCode>
    ExportKey(const ProviderKeyHandle& handle, score::mw::crypto::FormatType format);

    /// Return the byte length of the exported key in the given format.
    ///
    /// Default: returns kNotSupported.
    [[nodiscard]] virtual score::crypto::Expected<std::size_t, score::crypto::daemon::common::DaemonErrorCode>
    GetExportKeySize(const ProviderKeyHandle& handle, score::mw::crypto::FormatType format);

    /// Generate a key atomically into a persistent slot.
    ///
    /// The default implementation composes GenerateKey() + slot_handler.StoreKey().
    /// Providers that can generate non-exportable keys directly on hardware
    /// (e.g., PKCS#11 C_GenerateKey with CKA_TOKEN=TRUE) should override this
    /// to keep the key material inside the secure boundary.
    ///
    /// Default: GenerateKey(request) + slot_handler.StoreKey(slot, *handler).
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    GenerateKeyToSlot(const KeySlotConfig& slot, const KeyGenerationRequest& request, IKeySlotHandler& slot_handler);

    /// Import raw key material directly into a persistent slot.
    ///
    /// Default: ImportKey(request) + slot_handler.StoreKey(slot, *handler).
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    ImportKeyToSlot(const KeySlotConfig& slot, const KeyImportRequest& request, IKeySlotHandler& slot_handler);

    /// Derive a key and store it directly into a persistent slot.
    ///
    /// Default: DeriveKey(request) + slot_handler.StoreKey(slot, *handler).
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    DeriveKeyToSlot(const KeySlotConfig& slot, const KeyDeriveRequest& request, IKeySlotHandler& slot_handler);

    /// Perform key agreement and store the resulting key directly into a persistent slot.
    ///
    /// Default: AgreeKey(request) + slot_handler.StoreKey(slot, *handler).
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    AgreeKeyToSlot(const KeySlotConfig& slot, const KeyAgreeRequest& request, IKeySlotHandler& slot_handler);

    /// Unwrap a key and store it directly into a persistent slot.
    ///
    /// Default: UnwrapKey(request) + slot_handler.StoreKey(slot, *handler).
    [[nodiscard]] virtual score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
    UnwrapKeyToSlot(const KeySlotConfig& slot, const UnwrapKeyRequest& request, IKeySlotHandler& slot_handler);
};

}  // namespace score::crypto::daemon::key_management

#endif  // SCORE_CRYPTO_DAEMON_KEY_MANAGEMENT_I_KEY_FACTORY_HPP
