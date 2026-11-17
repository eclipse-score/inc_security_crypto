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

#include "score/crypto/src/backend/pkcs11/pkcs11_config_generated.h"
#include "score/crypto/src/common/flatbuffer_config_utils.hpp"
#include "score/crypto/src/daemon/common/secure_memory.hpp"
#include "score/crypto/src/daemon/common/storage/file_io.hpp"
#include "score/flatbuffers/buffer_version_info.hpp"
#include "score/flatbuffers/version_reader.hpp"
#include "score/mw/log/logging.h"

#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <unordered_set>
#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{

namespace
{
constexpr std::uint16_t kSupportedSchemaMajor = 0U;
constexpr std::uint16_t kSupportedSchemaMinor = 1U;
constexpr std::size_t kMaximumConfigFileSize = 1024U * 1024U;
constexpr ::score::flatbuffers::BufferVersionInfo kSupportedSchemaVersion{"P11C",
                                                                          kSupportedSchemaMajor,
                                                                          kSupportedSchemaMinor};

class SensitiveConfigGuard final
{
  public:
    explicit SensitiveConfigGuard(Pkcs11ProviderFactoryConfig& config) noexcept : config_{config} {}

    ~SensitiveConfigGuard()
    {
        SecureClearPins(config_);
    }

    SensitiveConfigGuard(const SensitiveConfigGuard&) = delete;
    SensitiveConfigGuard& operator=(const SensitiveConfigGuard&) = delete;
    SensitiveConfigGuard(SensitiveConfigGuard&&) = delete;
    SensitiveConfigGuard& operator=(SensitiveConfigGuard&&) = delete;

  private:
    Pkcs11ProviderFactoryConfig& config_;
};

std::string ProviderTypeToString(const score::crypto::backend::pkcs11::config::ProviderType provider_type)
{
    using ProviderType = score::crypto::backend::pkcs11::config::ProviderType;
    switch (provider_type)
    {
        case ProviderType::HARDWARE:
            return "HARDWARE";
        case ProviderType::SOFTWARE:
            return "SOFTWARE";
        case ProviderType::SPECIALIZED:
            return "SPECIALIZED";
    }
    return {};
}
}  // namespace

score::crypto::Expected<std::monostate, common::DaemonErrorCode> Pkcs11Config::ParseConfig(
    const std::optional<std::string_view> config_path)
{
    // A supplied configuration is authoritative. Clear any previously parsed
    // credentials before attempting the replacement so every failure path is
    // fail-closed and cannot expose stale provider configuration to a caller.
    SecureClearPins(m_config);
    m_config = Pkcs11ProviderFactoryConfig{};

    if (!config_path.has_value())
    {
        score::mw::log::LogWarn()
            << "[PKCS11_CONFIG] No PKCS#11 backend configuration reference; no PKCS#11 providers will be created";
        return std::monostate{};
    }

    auto buffer_result = common::storage::ReadOwnerOnlyFile(std::string{config_path.value()}, kMaximumConfigFileSize);
    if (!buffer_result.has_value())
    {
        score::mw::log::LogError() << "[PKCS11_CONFIG] Failed to read backend config file: " << config_path.value();
        return score::crypto::make_unexpected(buffer_result.error());
    }
    auto& buffer = buffer_result.value();
    const common::ScopedByteBufferZeroizer buffer_guard{buffer};
    const auto version_result = ::score::flatbuffers::VerifyVersion(buffer, kSupportedSchemaVersion);
    if (!version_result.has_value())
    {
        score::mw::log::LogError() << "[PKCS11_CONFIG] Missing or unsupported backend config identifier/version";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    ::flatbuffers::Verifier verifier{buffer.data(), buffer.size()};
    if (!score::crypto::backend::pkcs11::config::VerifyPkcs11BackendConfigBuffer(verifier))
    {
        score::mw::log::LogError() << "[PKCS11_CONFIG] Backend config failed FlatBuffers verification";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    const auto* root = score::crypto::backend::pkcs11::config::GetPkcs11BackendConfig(buffer.data());
    if (!root)
    {
        score::mw::log::LogError() << "[PKCS11_CONFIG] Backend config root is missing";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }

    Pkcs11ProviderFactoryConfig parsed;
    const SensitiveConfigGuard parsed_guard{parsed};
    std::unordered_set<std::string> provider_names;
    const auto* tokens = root->tokens();
    if (!tokens || tokens->empty())
    {
        score::mw::log::LogError() << "[PKCS11_CONFIG] At least one token entry is required";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
    }
    parsed.tokens.reserve(tokens->size());
    for (const auto* token : *tokens)
    {
        if (!token || !score::crypto::config_utils::HasText(token->token_label()) ||
            !score::crypto::config_utils::HasText(token->provider_name()))
        {
            score::mw::log::LogError() << "[PKCS11_CONFIG] Token label and provider name are required";
            return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }

        std::string provider_name{token->provider_name()->str()};
        if (!provider_names.insert(provider_name).second)
        {
            score::mw::log::LogError() << "[PKCS11_CONFIG] Duplicate provider name: " << provider_name;
            return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }

        const auto provider_type = ProviderTypeToString(token->provider_type());
        if (provider_type.empty())
        {
            score::mw::log::LogError() << "[PKCS11_CONFIG] Invalid provider type";
            return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }

        const auto cleanup_strategy = token->cleanup_strategy();
        if ((cleanup_strategy != score::crypto::backend::pkcs11::config::CleanupStrategy::SOFT) &&
            (cleanup_strategy != score::crypto::backend::pkcs11::config::CleanupStrategy::HARD))
        {
            score::mw::log::LogError() << "[PKCS11_CONFIG] Invalid cleanup strategy";
            return score::crypto::make_unexpected(common::DaemonErrorCode::kInvalidArgument);
        }

        parsed.tokens.emplace_back();
        auto& parsed_token = parsed.tokens.back();
        parsed_token.tokenLabel = token->token_label()->str();
        parsed_token.tokenModel = token->token_model() ? token->token_model()->str() : std::string{};
        if (token->user_pin())
        {
            parsed_token.userPin.assign(token->user_pin()->c_str(), token->user_pin()->size());
        }
        parsed_token.providerName = std::move(provider_name);
        parsed_token.providerType = provider_type;
        parsed_token.useHardCleanup = cleanup_strategy == score::crypto::backend::pkcs11::config::CleanupStrategy::HARD;
    }

    m_config = std::move(parsed);

    return std::monostate{};
}

}  // namespace score::crypto::daemon::provider::pkcs11
