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

#include "score/crypto/src/daemon/config/src/flatbuffer_config_parser.hpp"

#include "score/crypto/src/daemon/config/crypto_config_generated.h"

#include <atomic>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include <gtest/gtest.h>

namespace score::crypto::daemon::config
{
namespace
{
namespace schema = score::crypto::daemon::config::keyslot;

class ScopedEnvironmentVariable
{
  public:
    ScopedEnvironmentVariable(const char* name, const std::string& value) : m_name{name}
    {
        if (const auto* current_value = std::getenv(name); current_value != nullptr)
        {
            m_previous_value = current_value;
        }
        EXPECT_EQ(::setenv(name, value.c_str(), 1), 0);
    }

    ~ScopedEnvironmentVariable()
    {
        if (m_previous_value.has_value())
        {
            (void)::setenv(m_name.c_str(), m_previous_value->c_str(), 1);
        }
        else
        {
            (void)::unsetenv(m_name.c_str());
        }
    }

  private:
    std::string m_name;
    std::optional<std::string> m_previous_value;
};

class TemporaryConfigFile
{
  public:
    explicit TemporaryConfigFile(const std::vector<std::pair<std::string, std::string>>& references,
                                 const bool include_backend_section = true)
    {
        static std::atomic<std::uint64_t> sequence{0U};
        m_path = std::filesystem::temp_directory_path() /
                 ("crypto_backend_config_" + std::to_string(sequence.fetch_add(1U)) + ".bin");

        flatbuffers::FlatBufferBuilder builder;
        std::vector<flatbuffers::Offset<schema::BackendConfigReference>> entries;
        entries.reserve(references.size());
        for (const auto& [backend_id, config_path] : references)
        {
            entries.push_back(
                schema::CreateBackendConfigReferenceDirect(builder, backend_id.c_str(), config_path.c_str()));
        }
        flatbuffers::Offset<schema::BackendConfigSection> section{};
        if (include_backend_section)
        {
            section = schema::CreateBackendConfigSectionDirect(builder, &entries);
        }
        const auto root = schema::CreateCryptoConfig(builder, 0, 0, section);
        schema::FinishCryptoConfigBuffer(builder, root);

        std::ofstream output{m_path, std::ios::binary};
        output.write(reinterpret_cast<const char*>(builder.GetBufferPointer()),
                     static_cast<std::streamsize>(builder.GetSize()));
    }

    ~TemporaryConfigFile()
    {
        std::error_code error;
        std::filesystem::remove(m_path, error);
    }

    const std::filesystem::path& Path() const noexcept
    {
        return m_path;
    }

  private:
    std::filesystem::path m_path;
};

TEST(BackendConfigParserTest, ParsesProviderNeutralReferences)
{
    TemporaryConfigFile config_file{{{"openssl", "providers/openssl.bin"}, {"pkcs11", "/etc/crypto/pkcs11.bin"}}};
    const auto file = FlatBufferConfigParser::LoadFile(config_file.Path().string());
    ASSERT_TRUE(file.has_value());

    BackendConfigCatalog catalog;
    const auto result = FlatBufferConfigParser::ParseBackendConfigReferences(file.value(), catalog);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value());
    ASSERT_EQ(catalog.GetReferences().size(), 2U);
    EXPECT_EQ(catalog.FindConfigPath("openssl"), std::optional<std::string_view>{"providers/openssl.bin"});
    EXPECT_EQ(catalog.FindConfigPath("pkcs11"), std::optional<std::string_view>{"/etc/crypto/pkcs11.bin"});
    EXPECT_FALSE(catalog.FindConfigPath("primula").has_value());
}

TEST(BackendConfigParserTest, PreservesReferenceForBackendWithoutCommonParser)
{
    TemporaryConfigFile config_file{{{"future_backend", "providers/future_backend.bin"}}};
    const auto file = FlatBufferConfigParser::LoadFile(config_file.Path().string());
    ASSERT_TRUE(file.has_value());

    BackendConfigCatalog catalog;
    const auto result = FlatBufferConfigParser::ParseBackendConfigReferences(file.value(), catalog);

    ASSERT_TRUE(result.has_value());
    EXPECT_TRUE(result.value());
    EXPECT_EQ(catalog.FindConfigPath("future_backend"),
              std::optional<std::string_view>{"providers/future_backend.bin"});
}

TEST(BackendConfigParserTest, ResolvesRelativePathsFromCommonConfigDirectory)
{
    TemporaryConfigFile config_file{{{"pkcs11", "providers/pkcs11.bin"}}};
    ScopedEnvironmentVariable config_path{CRYPTO_CONFIG_FILE_ENV.data(), config_file.Path().string()};
    Config config;

    ASSERT_TRUE(config.ParseConfig());

    const auto expected_path = (config_file.Path().parent_path() / "providers/pkcs11.bin").lexically_normal().string();
    EXPECT_EQ(config.GetBackendConfigCatalog().FindConfigPath("pkcs11"),
              std::optional<std::string_view>{expected_path});
}

TEST(BackendConfigParserTest, PreservesAbsoluteBackendConfigPaths)
{
    constexpr std::string_view kAbsoluteBackendPath{"/etc/crypto/pkcs11.bin"};
    TemporaryConfigFile config_file{{{"pkcs11", std::string{kAbsoluteBackendPath}}}};
    ScopedEnvironmentVariable config_path{CRYPTO_CONFIG_FILE_ENV.data(), config_file.Path().string()};
    Config config;

    ASSERT_TRUE(config.ParseConfig());

    EXPECT_EQ(config.GetBackendConfigCatalog().FindConfigPath("pkcs11"),
              std::optional<std::string_view>{kAbsoluteBackendPath});
}

TEST(BackendConfigParserTest, AcceptsAbsentBackendConfigSection)
{
    TemporaryConfigFile config_file{std::vector<std::pair<std::string, std::string>>{}, false};
    ScopedEnvironmentVariable config_path{CRYPTO_CONFIG_FILE_ENV.data(), config_file.Path().string()};
    Config config;

    ASSERT_TRUE(config.ParseConfig());
    EXPECT_TRUE(config.GetBackendConfigCatalog().GetReferences().empty());
}

TEST(BackendConfigParserTest, AcceptsEmptyBackendConfigSection)
{
    TemporaryConfigFile config_file{std::vector<std::pair<std::string, std::string>>{}};
    ScopedEnvironmentVariable config_path{CRYPTO_CONFIG_FILE_ENV.data(), config_file.Path().string()};
    Config config;

    ASSERT_TRUE(config.ParseConfig());
    EXPECT_TRUE(config.GetBackendConfigCatalog().GetReferences().empty());
}

TEST(BackendConfigParserTest, RejectsDuplicateBackendIdentifiersTransactionally)
{
    TemporaryConfigFile config_file{{{"pkcs11", "first.bin"}, {"pkcs11", "second.bin"}}};
    const auto file = FlatBufferConfigParser::LoadFile(config_file.Path().string());
    ASSERT_TRUE(file.has_value());

    BackendConfigCatalog catalog;
    catalog.SetReferences({BackendConfigReference{"existing", "unchanged.bin"}});
    const auto result = FlatBufferConfigParser::ParseBackendConfigReferences(file.value(), catalog);

    EXPECT_FALSE(result.has_value());
    ASSERT_EQ(catalog.GetReferences().size(), 1U);
    EXPECT_EQ(catalog.GetReferences().front().backendId, "existing");
}

TEST(BackendConfigParserTest, RejectsBlankOrControlCharacterReferenceFields)
{
    const std::vector<std::pair<std::string, std::string>> invalid_references{
        {"  ", "pkcs11.bin"}, {"pkcs11", " \t\n"}, {"pkcs\n11", "pkcs11.bin"}};
    for (const auto& invalid_reference : invalid_references)
    {
        TemporaryConfigFile config_file{{invalid_reference}};
        const auto file = FlatBufferConfigParser::LoadFile(config_file.Path().string());
        ASSERT_TRUE(file.has_value());

        BackendConfigCatalog catalog;
        EXPECT_FALSE(FlatBufferConfigParser::ParseBackendConfigReferences(file.value(), catalog).has_value());
    }
}

}  // namespace
}  // namespace score::crypto::daemon::config
