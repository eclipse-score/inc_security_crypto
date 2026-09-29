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

#ifndef SCORE_CRYPTO_SRC_API_TYPES_COMMON_HPP
#define SCORE_CRYPTO_SRC_API_TYPES_COMMON_HPP

#include "score/crypto/src/api/common/fixed_capacity_string.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>

namespace score::crypto
{

/// @brief Application-defined name used to resolve a resource through the daemon.
using ResourceId = FixedCapacityString<64>;
/// @brief Algorithm name or identifier accepted by a crypto operation.
using AlgorithmId = FixedCapacityString<64>;

/// @brief Kind of resource identified by a CryptoResourceId.
enum class ResourceType : uint8_t
{
    kProvider,               ///< Crypto provider.
    kKeySlot,                ///< Persistent key storage slot.
    kCertSlot,               ///< Persistent certificate storage slot.
    kCertificateTrustStore,  ///< Named certificate trust store.
    kKey,                    ///< Key resource.
    kCertificate,            ///< Parsed or loaded certificate resource.
    kSecureObject,           ///< Provider-backed secure object.
    kDataObject              ///< Provider-backed data object.
};

/// @brief Indicates whether a resource is persistent or scoped to a session.
enum class ResourcePersistence : uint8_t
{
    kPersistent,  ///< Survives release of the current client-side handle.
    kEphemeral    ///< Lifetime is controlled by a session/resource guard.
};

/// @brief Typed handle to a daemon-managed crypto resource.
///
/// The id is interpreted together with its resource type, persistence, and
/// primary provider. Handles are resolved and authorized by the daemon.
struct CryptoResourceId
{
    uint64_t id{0U};                                                   ///< Daemon-assigned resource identifier.
    ResourceType type{ResourceType::kKeySlot};                         ///< Kind of resource referenced by id.
    ResourcePersistence persistence{ResourcePersistence::kEphemeral};  ///< Resource lifetime category.
    uint16_t primary_provider{0U};                                     ///< Owning provider id, or zero when unbound.

    /// @brief Tests whether all resource identity fields match.
    constexpr bool operator==(const CryptoResourceId& other) const noexcept
    {
        return (id == other.id) && (type == other.type) && (persistence == other.persistence) &&
               (primary_provider == other.primary_provider);
    }

    /// @brief Tests whether any resource identity field differs.
    constexpr bool operator!=(const CryptoResourceId& other) const noexcept
    {
        return !(*this == other);
    }
};

/// @brief Provider category requested when creating a crypto context.
enum class ProviderType : uint8_t
{
    kDefault,            ///< Use the default provider-selection policy.
    kHardware,           ///< Require a hardware provider.
    kSoftware,           ///< Require a software provider.
    kHardwarePreferred,  ///< Prefer hardware; permit the corresponding fallback.
    kSoftwarePreferred   ///< Prefer software; permit the corresponding fallback.
};

/// @brief Encoding format for serialized key, certificate, or CRL data.
enum class FormatType : uint8_t
{
    kDer,  ///< Distinguished Encoding Rules (binary) encoding.
    kPem   ///< Privacy-Enhanced Mail (text) encoding.
};

/// @brief Direction of a symmetric cipher operation.
enum class CipherDirection : uint8_t
{
    kEncrypt,  ///< Encrypt or seal input data.
    kDecrypt   ///< Decrypt or open input data.
};

/// @brief Whether an operation generates output or verifies supplied data.
enum class OperationMode : uint8_t
{
    kGenerate,  ///< Produce a signature, MAC, or other operation result.
    kVerify     ///< Verify supplied signature, MAC, or other operation result.
};

/// @brief Memory compatibility requested for an allocation.
enum class MemoryType : uint8_t
{
    kDefault,            ///< Use the allocator's default memory type.
    kProviderCompatible  ///< Allocate memory compatible with the selected provider.
};

/// @brief Public metadata for a registered crypto provider.
struct ProviderInfo
{
    uint16_t id{0U};                            ///< Daemon-assigned provider id.
    ProviderType type{ProviderType::kDefault};  ///< Provider category.
    FixedCapacityString<32> name{};             ///< Human-readable provider name.
};

/// @brief Provider compatibility information for one resource.
struct ProviderCompatibilityInfo
{
    CryptoResourceId resource{};    ///< Resource whose provider compatibility is reported.
    uint16_t primary_provider{0U};  ///< Provider that owns the resource.
    static constexpr std::size_t kMaxSecondaryProviders = 8U;
    std::array<uint16_t, kMaxSecondaryProviders> secondary_providers{};  ///< Providers that can also use it.
    std::size_t secondary_provider_count{0U};  ///< Number of valid entries in secondary_providers.
};

/// @brief Support and mode information for one algorithm.
struct AlgorithmCapabilities
{
    AlgorithmId id{};       ///< Algorithm identifier.
    bool supported{false};  ///< Whether the queried provider supports the algorithm.
    static constexpr std::size_t kMaxModes = 16U;
    std::array<FixedCapacityString<16>, kMaxModes> modes{};  ///< Supported modes, when applicable.
    std::size_t mode_count{0U};                              ///< Number of valid entries in modes.
};

/// @brief Bounded snapshot of providers and algorithms available in the system.
struct SystemCapabilities
{
    static constexpr std::size_t kMaxProviders = 16U;
    std::array<ProviderInfo, kMaxProviders> providers{};  ///< Registered providers.
    std::size_t provider_count{0U};                       ///< Number of valid entries in providers.
    static constexpr std::size_t kMaxAlgorithms = 64U;
    std::array<AlgorithmCapabilities, kMaxAlgorithms> algorithms{};  ///< Reported algorithms.
    std::size_t algorithm_count{0U};                                 ///< Number of valid entries in algorithms.
};

/// @brief One key-value entry in a context's extended parameters.
struct ExtendedParameterEntry
{
    FixedCapacityString<32> key{};    ///< Parameter name.
    FixedCapacityString<64> value{};  ///< Parameter value.
};

/// @brief Bounded collection of provider- or context-specific parameters.
struct ExtendedParameters
{
    static constexpr std::size_t kMaxEntries = 16U;
    std::array<ExtendedParameterEntry, kMaxEntries> entries{};  ///< Parameter entries.
    std::size_t entry_count{0U};                                ///< Number of valid entries in entries.
};

}  // namespace score::crypto

template <>
struct std::hash<score::crypto::CryptoResourceId>
{
    /// @brief Hashes the complete resource identity for unordered containers.
    std::size_t operator()(const score::crypto::CryptoResourceId& rid) const noexcept
    {
        std::size_t h = std::hash<uint64_t>{}(rid.id);
        h ^= std::hash<uint8_t>{}(static_cast<uint8_t>(rid.type)) << 1U;
        h ^= std::hash<uint8_t>{}(static_cast<uint8_t>(rid.persistence)) << 2U;
        h ^= std::hash<uint16_t>{}(rid.primary_provider) << 3U;
        return h;
    }
};

#endif  // SCORE_CRYPTO_SRC_API_TYPES_COMMON_HPP
