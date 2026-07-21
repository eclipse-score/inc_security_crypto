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

#ifndef SCORE_MW_CRYPTO_API_CONFIG_BASE_CONTEXT_CONFIG_HPP
#define SCORE_MW_CRYPTO_API_CONFIG_BASE_CONTEXT_CONFIG_HPP

#include "score/mw/crypto/api/common/types.hpp"

#include <chrono>
#include <optional>
#include <string>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Base configuration for all operation contexts.
///
/// **Provider auto-resolution**: When provider is omitted but a key_slot
/// is specified in a derived config, the daemon auto-resolves the provider
/// from CryptoResourceId::primary_provider of the key slot. Explicitly
/// setting provider overrides this — enabling cross-provider scenarios
/// where the app wants to use a secondary-compatible provider instead
/// of the key's primary.
struct BaseContextConfig
{
    /// @brief Algorithm identifier (e.g., "AES-256-CBC", "SHA-384", "ML-DSA-65").
    AlgorithmId algorithm{};

    /// @brief Optional resolved provider handle. When set, overrides
    ///        auto-resolution from key_slot's primary_provider.
    std::optional<CryptoResourceId> provider{std::nullopt};

    /// @brief Optional provider type preference (e.g., kHardwarePreferred).
    ///        Used when provider handle is not set to guide daemon selection.
    std::optional<ProviderType> provider_type{std::nullopt};

    /// @brief Algorithm- or operation-scoped extended parameters.
    ///
    /// Forward-compatible extension point for parameters not yet modeled as typed
    /// fields (e.g., PQC parameter sets, key-derivation labels). Key names and
    /// value semantics are defined by the **middleware specification** only —
    /// never by an individual provider or hardware back-end. Application code
    /// using this field must remain portable across all compliant providers.
    ///
    /// Provider-specific or hardware-specific tuning (HSM slot indices, PIN
    /// policies, vendor flags, etc.) must NOT be placed here; it belongs in
    /// the daemon's static configuration.
    ExtendedParameters extended_parameters{};

    /// @brief Per-context operation timeout override.
    ///
    /// When set (and timeout_enabled is true), overrides the stack-level
    /// default_operation_timeout for this context's IPC calls.
    /// When std::nullopt, falls back to CryptoStackConfig::default_operation_timeout.
    ///
    /// @note Applies per-IPC-call, not per-sequence. For streaming operations,
    ///       each Init()/Update()/Finalize() has its own deadline.
    std::optional<std::chrono::milliseconds> operation_timeout{std::nullopt};

    /// @brief Controls whether timeout enforcement is active for this context.
    ///
    /// When true (default), the effective timeout (per-context or stack-level)
    /// is enforced on every IPC call. Operations exceeding the deadline return
    /// CryptoErrorCode::kOperationTimedOut and the context transitions to an
    /// error state — subsequent calls return kInvalidOperation.
    ///
    /// When false, timeout is disabled entirely for this context, allowing
    /// unbounded execution. Use for operations that are legitimately
    /// long-running, such as:
    ///   - PQC key generation on hardware (ML-KEM, ML-DSA)
    ///   - HSM-backed key agreement or unwrapping
    ///   - Certificate chain verification with online OCSP
    ///
    /// @warning Disabling timeout removes the WCET bound for this context's
    ///          operations, which may impact Safety. Document the
    ///          rationale in the safety case when using DisableTimeout() in
    ///          safety-relevant applications.
    bool timeout_enabled{true};

    /// @brief Intended operation mode for MAC and signature contexts.
    ///
    /// Defaults to kGenerate. Set to kVerify for verification-only contexts
    /// so that key permission enforcement and provider API selection (e.g.
    /// PKCS#11 C_VerifyInit vs C_SignInit) are correct.
    OperationMode operation_mode{OperationMode::kGenerate};

    // -- Fluent builder --

    BaseContextConfig& SetAlgorithm(const AlgorithmId& alg) noexcept
    {
        algorithm = alg;
        return *this;
    }

    BaseContextConfig& SetProvider(const CryptoResourceId& prov) noexcept
    {
        provider = prov;
        return *this;
    }

    BaseContextConfig& SetProviderType(ProviderType type) noexcept
    {
        provider_type = type;
        return *this;
    }

    BaseContextConfig& SetOperationMode(OperationMode mode) noexcept
    {
        operation_mode = mode;
        return *this;
    }

    /// @brief Add or update a small, portable extended parameter.
    ///
    /// Keys must follow the middleware API naming rules; values are opaque
    /// strings. This method overwrites an existing key or appends a new entry
    /// if capacity allows.
    BaseContextConfig& SetExtendedParameter(const std::string& key, const std::string& value)
    {
        // Update existing entry if key is already present
        for (std::size_t i = 0U; i < extended_parameters.entry_count; ++i)
        {
            if (extended_parameters.entries[i].key == key)
            {
                extended_parameters.entries[i].value = value;
                return *this;
            }
        }
        // Add new entry if capacity allows
        if (extended_parameters.entry_count < extended_parameters.entries.size())
        {
            extended_parameters.entries[extended_parameters.entry_count].key = key;
            extended_parameters.entries[extended_parameters.entry_count].value = value;
            ++extended_parameters.entry_count;
        }
        return *this;
    }

    // TODO: 0 means infinite duration? (or time out disabled?). Add sanity check.
    /// @brief Sets the per-context operation timeout.
    /// @param timeout Maximum duration for each individual IPC call.
    ///        Overrides CryptoStackConfig::default_operation_timeout.
    ///        Automatically enables timeout if it was previously disabled.
    BaseContextConfig& SetOperationTimeout(std::chrono::milliseconds timeout)
    {
        operation_timeout = timeout;
        timeout_enabled = true;
        return *this;
    }

    /// @brief Disables timeout enforcement for this context.
    ///
    /// The context will wait indefinitely for daemon responses. Use for
    /// operations that are legitimately long-running (e.g., PQC key
    /// generation on hardware tokens).
    ///
    /// @warning Removes WCET bound — document rationale in safety case.
    BaseContextConfig& DisableTimeout() noexcept
    {
        timeout_enabled = false;
        return *this;
    }

    /// @brief Re-enables timeout enforcement for this context.
    ///
    /// Uses the per-context operation_timeout if set, otherwise falls back
    /// to CryptoStackConfig::default_operation_timeout.
    BaseContextConfig& EnableTimeout() noexcept
    {
        timeout_enabled = true;
        return *this;
    }
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONFIG_BASE_CONTEXT_CONFIG_HPP
