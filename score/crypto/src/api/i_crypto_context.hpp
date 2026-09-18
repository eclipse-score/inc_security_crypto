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

#ifndef SCORE_CRYPTO_SRC_API_I_CRYPTO_CONTEXT_HPP
#define SCORE_CRYPTO_SRC_API_I_CRYPTO_CONTEXT_HPP

#include "score/crypto/src/api/types/common.hpp"
#include "score/result/result.h"

#include <cstdint>
#include <memory>

namespace score
{

namespace crypto
{

// ---- Forward declarations ----
// Consumers include the specific headers they need; this header only
// requires forward declarations for parameter and return types.

// Config types (used as const& parameters)
class HashContextConfig;
class KeyManagementContextConfig;
class MacContextConfig;
class CertificateContextConfig;
class CertificateVerificationContextConfig;
class TrustStoreManagementContextConfig;

// Operation contexts (returned as std::unique_ptr)
class IHashContext;
class IKeyManagementContext;
class IMacContext;
class ICertificateManagementContext;
class ICertificateVerificationContext;
class ITrustStoreManagementContext;

// Typed object interfaces (returned as std::unique_ptr)
class IKeyObject;
class IKeySlotObject;
class ICertificateObject;
class ICertSlotObject;
class ITrustStoreObject;

// The following forward declarations are for contexts not yet active (IPC implementation pending).
// class AeadContextConfig;
// class CipherContextConfig;
// class CsrGenerationContextConfig;
// class RandomContextConfig;
// class SignContextConfig;
// class VerifySignatureContextConfig;
// class IAeadContext;
// class ICipherContext;
// class ICsrGenerationContext;
// class IRandomContext;
// class ISignContext;
// class IVerifySignatureContext;
// class IProviderObject;

// TODO: Consider splitting this interface into multiple smaller interfaces (e.g. IContextFactory, ICapabilityQuerier).
/// @brief Factory, resource resolution, and typed object access for the crypto stack.
///
/// ICryptoContext serves three purposes:
/// 1. **Resource resolution**: Convert app-defined string ResourceId to
///    daemon-assigned CryptoResourceId handles via ResolveResource().
/// 2. **Context factory**: Create operation-specific contexts configured
///    with the resolved resource handles.
/// 3. **Typed object access**: Obtain specialized interfaces for
///    resource-type-specific queries (e.g., IKeyObject, IKeySlotObject).
///
/// CryptoResourceId is the sole runtime handle for all resources.
/// Each context resolves incoming CryptoResourceId according to its own
/// requirements within its scope.
///
/// Typical usage:
/// @code
///   auto slot = ctx->ResolveResource("MyMacKey", ResourceType::kKeySlot);
///   MacContextConfig config;
///   config.SetAlgorithm("HMAC-SHA-256");
///   config.SetKeySlot(slot.value());
///   auto mac_ctx = ctx->CreateMacContext(config);
///   // Context internally loads key material from the key slot; releases on destruction.
/// @endcode
///
/// Typical usage (key management):
/// @code
///   auto slot = ctx->ResolveResource("MyAesKey", ResourceType::kKeySlot);
///   KeyManagementContextConfig cfg;
///   auto key_mgmt = ctx->CreateKeyManagementContext(cfg).value();
///   auto guard = key_mgmt->LoadKey(slot.value()); // CryptoResourceGuard
///   // guard releases transient key material when it goes out of scope.
/// @endcode
class ICryptoContext
{
  public:
    using Uptr = std::unique_ptr<ICryptoContext>;

    virtual ~ICryptoContext() = default;

    ICryptoContext(const ICryptoContext&) = delete;
    ICryptoContext& operator=(const ICryptoContext&) = delete;
    ICryptoContext(ICryptoContext&&) = default;
    ICryptoContext& operator=(ICryptoContext&&) = default;

    // TODO: Consider moving to the crypto stack interface, as the CryptoResouceId is also used by memory allocator as
    // well.
    //  ---- Resource Resolution ----

    /// @brief Resolves an app-defined resource name to a daemon handle.
    /// @param resource_id Application-defined resource identifier (from config)
    /// @param type Expected resource type for validation
    /// @return CryptoResourceId handle for use in configs and operations
    /// @note Called once per resource; result should be cached by the application.
    ///       Access control (uid) is enforced during resolution.
    virtual score::Result<CryptoResourceId> ResolveResource(const ResourceId& resource_id, ResourceType type) = 0;

    // ---- Context Factory ----

    /// @brief Creates a hash context.
    /// @param config Hash configuration (algorithm required)
    virtual score::Result<std::unique_ptr<IHashContext>> CreateHashContext(const HashContextConfig& config) = 0;

    /// @brief Creates a MAC context.
    /// @param config MAC configuration (algorithm + key_slot required)
    virtual score::Result<std::unique_ptr<IMacContext>> CreateMacContext(const MacContextConfig& config) = 0;

    /// @brief Creates a key management context.
    /// @param config Key management configuration (provider optional)
    virtual score::Result<std::unique_ptr<IKeyManagementContext>> CreateKeyManagementContext(
        const KeyManagementContextConfig& config) = 0;

    /// @brief Creates a certificate management context.
    /// @param config Certificate management configuration (provider optional)
    virtual score::Result<std::unique_ptr<ICertificateManagementContext>> CreateCertificateManagementContext(
        const CertificateContextConfig& config) = 0;

    /// @brief Creates a certificate verification context.
    /// @param config Certificate verification configuration (provider optional)
    virtual score::Result<std::unique_ptr<ICertificateVerificationContext>> CreateCertificateVerificationContext(
        const CertificateVerificationContextConfig& config) = 0;

    /// @brief Creates a trust-store management context.
    ///
    /// Trust-store membership curation (add/remove/enable/disable members, import
    /// CRL for a member) is a capability distinct from certificate lifecycle
    /// management; see ITrustStoreManagementContext.
    ///
    /// @param config Trust-store management configuration (provider optional)
    virtual score::Result<std::unique_ptr<ITrustStoreManagementContext>> CreateTrustStoreManagementContext(
        const TrustStoreManagementContextConfig& config) = 0;

    // The following factory methods are declared but not yet active.
    // Each is implemented in score/crypto/src/api/future/contexts/
    // and will be moved here together with its IPC implementation.

    // virtual score::Result<std::unique_ptr<ICipherContext>> CreateCipherContext(
    //     const CipherContextConfig& config) = 0;

    // virtual score::Result<std::unique_ptr<ISignContext>> CreateSignContext(
    //     const SignContextConfig& config) = 0;

    // virtual score::Result<std::unique_ptr<IVerifySignatureContext>> CreateVerifySignatureContext(
    //     const VerifySignatureContextConfig& config) = 0;

    // virtual score::Result<std::unique_ptr<IAeadContext>> CreateAeadContext(
    //     const AeadContextConfig& config) = 0;

    // virtual score::Result<std::unique_ptr<IRandomContext>> CreateRandomContext(
    //     const RandomContextConfig& config) = 0;

    // virtual score::Result<std::unique_ptr<ICsrGenerationContext>> CreateCsrGenerationContext(
    //     const CsrGenerationContextConfig& config) = 0;

    // ---- Queries ----

    /// @brief Queries algorithm capabilities and support.
    /// @param algorithm Algorithm identifier to query
    /// @return Capabilities including whether the algorithm is supported and available modes
    virtual score::Result<AlgorithmCapabilities> QueryCapabilities(const AlgorithmId& algorithm) = 0;

    /// @brief Queries system-wide capabilities across all providers.
    /// @return Aggregated capabilities including all registered providers and
    ///         the union of their supported algorithms
    virtual score::Result<SystemCapabilities> QueryCapabilities() = 0;

    // FUTURE: Uncomment when there is potentiant use for this in the future.
    /// @brief Queries cross-provider compatibility for a resource.
    /// @param resource Handle to the resource to query
    /// @return Compatibility info with primary and secondary providers
    /// @note Secondary providers can use this resource (e.g., SW-exported
    ///       key re-importable into another SW provider). The daemon computes
    ///       this based on algorithm support, key exportability, and provider
    ///       capabilities.
    // virtual score::Result<ProviderCompatibilityInfo> QueryProviderCompatibility(const CryptoResourceId& resource) =
    // 0;

    /// @brief Gets provider information for the primary provider in CryptoResourceId.
    /// @param resourceId CryptoResourceId
    /// @return Provider info with type and name
    virtual score::Result<ProviderInfo> GetProviderInfo(const CryptoResourceId& resourceId) = 0;

    /// @brief Maps a numeric provider ID to human-readable metadata.
    /// @param provider_id Numeric provider ID (from CryptoResourceId::primary_provider
    ///        or KeySlotInfo::compatible_providers)
    /// @return Provider info with type and name
    virtual score::Result<ProviderInfo> GetProviderInfo(uint16_t provider_id) = 0;

    // ---- Typed Object Access ----
    //
    // Obtain a specialised, read-only view of a resource identified by its
    // CryptoResourceId.  The resource type encoded in the id must match the
    // requested interface (e.g., kKey for GetKeyObject).

    /// @brief Obtains a typed key object for the given resource.
    /// @param id CryptoResourceId whose type must be kKey
    /// @return IKeyObject for algorithm / persistence / exportability queries
    virtual score::Result<std::unique_ptr<IKeyObject>> GetKeyObject(const CryptoResourceId& id) = 0;

    /// @brief Obtains a typed key-slot object for the given resource.
    /// @param id CryptoResourceId whose type must be kKeySlot
    /// @return IKeySlotObject for slot state / allowed-algorithm queries
    virtual score::Result<std::unique_ptr<IKeySlotObject>> GetKeySlotObject(const CryptoResourceId& id) = 0;

    /// @brief Obtains a typed certificate object for the given resource.
    ///
    /// ICertificateObject is the unified, non-owning certificate view — used
    /// for both ephemeral (ParseCertificate result) and persistent certificates.
    /// For an ephemeral certificate, the caller must retain its
    /// CryptoResourceGuard while using this view.
    ///
    /// @param id CryptoResourceId whose type must be kCertificate or kCertSlot
    /// @return ICertificateObject for subject/issuer/validity queries
    virtual score::Result<std::unique_ptr<ICertificateObject>> GetCertificateObject(const CryptoResourceId& id) = 0;

    /// @brief Obtains a typed certificate-slot object for the given resource.
    /// @param id CryptoResourceId whose type must be kCertSlot
    /// @return ICertSlotObject for slot state / CRL presence queries
    virtual score::Result<std::unique_ptr<ICertSlotObject>> GetCertSlotObject(const CryptoResourceId& id) = 0;

    /// @brief Obtains a read-only typed view of a named trust store.
    ///
    /// Returns a point-in-time snapshot of the trust store's member list:
    /// fingerprints, membership kind (shared-static / exclusive / conditional-external),
    /// and enabled/disabled state. The object is immutable after construction.
    ///
    /// Mutations (add, remove, enable, disable, CRL import) are performed via
    /// ICertificateManagementContext.
    ///
    /// @param id CryptoResourceId whose type must be kCertificateTrustStore
    /// @return ITrustStoreObject with a snapshot of all occupied member slots
    virtual score::Result<std::unique_ptr<ITrustStoreObject>> GetTrustStoreObject(const CryptoResourceId& id) = 0;

    // virtual score::Result<std::unique_ptr<IProviderObject>> GetProviderObject(
    //     const CryptoResourceId& id) = 0;

  protected:
    ICryptoContext() = default;
};

}  // namespace crypto

}  // namespace score

#endif  // SCORE_CRYPTO_SRC_API_I_CRYPTO_CONTEXT_HPP
