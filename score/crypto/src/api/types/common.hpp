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

using ResourceId = FixedCapacityString<64>;
using AlgorithmId = FixedCapacityString<64>;

enum class ResourceType : uint8_t
{
    kProvider,
    kKeySlot,
    kCertSlot,
    kCertificateTrustStore,
    kKey,
    kCertificate,
    kSecureObject,
    kDataObject
};

enum class ResourcePersistence : uint8_t
{
    kPersistent,
    kEphemeral
};

struct CryptoResourceId
{
    uint64_t id{0U};
    ResourceType type{ResourceType::kKeySlot};
    ResourcePersistence persistence{ResourcePersistence::kEphemeral};
    uint16_t primary_provider{0U};

    constexpr bool operator==(const CryptoResourceId& other) const noexcept
    {
        return (id == other.id) && (type == other.type) && (persistence == other.persistence) &&
               (primary_provider == other.primary_provider);
    }

    constexpr bool operator!=(const CryptoResourceId& other) const noexcept
    {
        return !(*this == other);
    }
};

enum class ProviderType : uint8_t
{
    kDefault,
    kHardware,
    kSoftware,
    kHardwarePreferred,
    kSoftwarePreferred
};

enum class FormatType : uint8_t
{
    kDer,
    kPem
};

enum class CipherDirection : uint8_t
{
    kEncrypt,
    kDecrypt
};

enum class OperationMode : uint8_t
{
    kGenerate,
    kVerify
};

enum class MemoryType : uint8_t
{
    kDefault,
    kProviderCompatible
};

struct ProviderInfo
{
    uint16_t id{0U};
    ProviderType type{ProviderType::kDefault};
    FixedCapacityString<32> name{};
};

struct ProviderCompatibilityInfo
{
    CryptoResourceId resource{};
    uint16_t primary_provider{0U};
    static constexpr std::size_t kMaxSecondaryProviders = 8U;
    std::array<uint16_t, kMaxSecondaryProviders> secondary_providers{};
    std::size_t secondary_provider_count{0U};
};

struct AlgorithmCapabilities
{
    AlgorithmId id{};
    bool supported{false};
    static constexpr std::size_t kMaxModes = 16U;
    std::array<FixedCapacityString<16>, kMaxModes> modes{};
    std::size_t mode_count{0U};
};

struct SystemCapabilities
{
    static constexpr std::size_t kMaxProviders = 16U;
    std::array<ProviderInfo, kMaxProviders> providers{};
    std::size_t provider_count{0U};
    static constexpr std::size_t kMaxAlgorithms = 64U;
    std::array<AlgorithmCapabilities, kMaxAlgorithms> algorithms{};
    std::size_t algorithm_count{0U};
};

struct ExtendedParameterEntry
{
    FixedCapacityString<32> key{};
    FixedCapacityString<64> value{};
};

struct ExtendedParameters
{
    static constexpr std::size_t kMaxEntries = 16U;
    std::array<ExtendedParameterEntry, kMaxEntries> entries{};
    std::size_t entry_count{0U};
};

}  // namespace score::crypto

template <>
struct std::hash<score::crypto::CryptoResourceId>
{
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
