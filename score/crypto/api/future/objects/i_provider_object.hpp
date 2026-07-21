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

#ifndef SCORE_MW_CRYPTO_API_OBJECTS_I_PROVIDER_OBJECT_HPP
#define SCORE_MW_CRYPTO_API_OBJECTS_I_PROVIDER_OBJECT_HPP

#include "score/mw/crypto/api/objects/i_crypto_object.hpp"

#include <memory>
#include <string_view>
#include <vector>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Typed view of a crypto provider resource.
///
/// Provides provider type, name, and supported algorithm queries
/// for a resource whose type is kProvider.  Obtained via
/// ICryptoContext::GetProviderObject().
class IProviderObject : public ICryptoObject
{
  public:
    using Uptr = std::unique_ptr<IProviderObject>;

    ~IProviderObject() override = default;

    IProviderObject(const IProviderObject&) = delete;
    IProviderObject& operator=(const IProviderObject&) = delete;
    IProviderObject(IProviderObject&&) = default;
    IProviderObject& operator=(IProviderObject&&) = default;

    /// @brief Returns the provider type (kHardware, kSoftware, etc.).
    virtual ProviderType GetProviderType() const noexcept = 0;

    /// @brief Returns the provider's human-readable name.
    virtual std::string_view GetName() const noexcept = 0;

    /// @brief Returns the list of algorithms supported by this provider.
    virtual std::vector<AlgorithmCapabilities> GetSupportedAlgorithms() const = 0;

  protected:
    IProviderObject() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_OBJECTS_I_PROVIDER_OBJECT_HPP
