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

#include <algorithm>
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <optional>
#include <string>
#include <vector>

#include <gtest/gtest.h>

namespace score::crypto::daemon::provider::pkcs11
{
namespace
{
namespace schema = score::crypto::backend::pkcs11::config;

struct TokenInput
{
    std::string label;
    std::string model;
    std::string pin;
    std::string provider_name;
    schema::ProviderType provider_type{schema::ProviderType::HARDWARE};
    schema::CleanupStrategy cleanup_strategy{schema::CleanupStrategy::HARD};
};

class TemporaryPkcs11Config
{
  public:
    TemporaryPkcs11Config(const std::vector<TokenInput>& tokens,
                          const std::uint16_t major = 0U,
                          const std::uint16_t minor = 1U,
                          const bool include_version = true,
                          const bool valid_identifier = true)
    {
        static std::atomic<std::uint64_t> sequence{0U};
        m_path = std::filesystem::temp_directory_path() /
                 ("pkcs11_backend_config_" + std::to_string(sequence.fetch_add(1U)) + ".bin");

        ::flatbuffers::FlatBufferBuilder builder;
        std::vector<::flatbuffers::Offset<schema::TokenEntry>> entries;
        entries.reserve(tokens.size());
        for (const auto& token : tokens)
        {
            entries.push_back(schema::CreateTokenEntryDirect(builder,
                                                             token.label.c_str(),
                                                             token.model.c_str(),
                                                             token.pin.c_str(),
                                                             token.provider_name.c_str(),
                                                             token.provider_type,
                                                             token.cleanup_strategy));
        }
        ::flatbuffers::Offset<::score::flatbuffers::BufferVersion> version_info{};
        if (include_version)
        {
            const auto type_marker = builder.CreateString("BV");
            version_info = ::score::flatbuffers::CreateBufferVersion(builder, type_marker, major, minor);
        }
        const auto root = schema::CreatePkcs11BackendConfigDirect(builder, version_info, &entries);
        schema::FinishPkcs11BackendConfigBuffer(builder, root);

        if (!valid_identifier)
        {
            constexpr std::size_t kIdentifierOffset = sizeof(::flatbuffers::uoffset_t);
            constexpr char kWrongIdentifier[] = "BAD!";
            std::copy_n(
                kWrongIdentifier, ::flatbuffers::kFileIdentifierLength, builder.GetBufferPointer() + kIdentifierOffset);
        }

        std::ofstream output{m_path, std::ios::binary};
        output.write(reinterpret_cast<const char*>(builder.GetBufferPointer()),
                     static_cast<std::streamsize>(builder.GetSize()));
    }

    ~TemporaryPkcs11Config()
    {
        std::error_code error;
        std::filesystem::remove(m_path, error);
    }

    std::string Path() const
    {
        return m_path.string();
    }

  private:
    std::filesystem::path m_path;
};

class TemporaryRawConfig
{
  public:
    explicit TemporaryRawConfig(const std::size_t size)
    {
        static std::atomic<std::uint64_t> sequence{0U};
        m_path = std::filesystem::temp_directory_path() /
                 ("pkcs11_raw_config_" + std::to_string(sequence.fetch_add(1U)) + ".bin");

        std::ofstream output{m_path, std::ios::binary};
        if (size > 0U)
        {
            output.seekp(static_cast<std::streamoff>(size - 1U));
            output.put('\0');
        }
    }

    ~TemporaryRawConfig()
    {
        std::error_code error;
        std::filesystem::remove(m_path, error);
    }

    std::string Path() const
    {
        return m_path.string();
    }

  private:
    std::filesystem::path m_path;
};

TEST(Pkcs11ConfigParserTest, ParsesBackendOwnedTokenConfiguration)
{
    TemporaryPkcs11Config file{
        {TokenInput{"TokenA", "ModelA", "1234", "HSM_A", schema::ProviderType::HARDWARE, schema::CleanupStrategy::HARD},
         TokenInput{"TokenB", "", "", "HSM_B", schema::ProviderType::SOFTWARE, schema::CleanupStrategy::SOFT},
         TokenInput{"TokenC", "", "", "HSM_C", schema::ProviderType::SPECIALIZED, schema::CleanupStrategy::HARD}}};
    Pkcs11Config config;
    const auto path = file.Path();

    const auto result = config.ParseConfig(std::optional<std::string_view>{path});

    ASSERT_TRUE(result.has_value());
    const auto& tokens = config.GetConfig().tokens;
    ASSERT_EQ(tokens.size(), 3U);
    EXPECT_EQ(tokens[0].tokenLabel, "TokenA");
    EXPECT_EQ(tokens[0].tokenModel, "ModelA");
    EXPECT_EQ(tokens[0].userPin, "1234");
    EXPECT_EQ(tokens[0].providerName, "HSM_A");
    EXPECT_EQ(tokens[0].providerType, "HARDWARE");
    EXPECT_TRUE(tokens[0].useHardCleanup);
    EXPECT_EQ(tokens[1].providerType, "SOFTWARE");
    EXPECT_FALSE(tokens[1].useHardCleanup);
    EXPECT_EQ(tokens[2].providerType, "SPECIALIZED");
    EXPECT_TRUE(tokens[2].useHardCleanup);
}

TEST(Pkcs11ConfigParserTest, RejectsDuplicateProviderNamesTransactionally)
{
    TemporaryPkcs11Config file{{TokenInput{"TokenA", "", "", "DUPLICATE"}, TokenInput{"TokenB", "", "", "DUPLICATE"}}};
    Pkcs11Config config;
    const auto path = file.Path();

    EXPECT_FALSE(config.ParseConfig(std::optional<std::string_view>{path}).has_value());
    EXPECT_TRUE(config.GetConfig().tokens.empty());
}

TEST(Pkcs11ConfigParserTest, RejectsUnsupportedSchemaMajorVersion)
{
    TemporaryPkcs11Config file{{TokenInput{"TokenA", "", "", "HSM_A"}}, 1U, 0U};
    Pkcs11Config config;
    const auto path = file.Path();

    EXPECT_FALSE(config.ParseConfig(std::optional<std::string_view>{path}).has_value());
    EXPECT_TRUE(config.GetConfig().tokens.empty());
}

TEST(Pkcs11ConfigParserTest, RejectsUnsupportedSchemaMinorVersion)
{
    TemporaryPkcs11Config file{{TokenInput{"TokenA", "", "", "HSM_A"}}, 0U, 2U};
    Pkcs11Config config;
    const auto path = file.Path();

    EXPECT_FALSE(config.ParseConfig(std::optional<std::string_view>{path}).has_value());
    EXPECT_TRUE(config.GetConfig().tokens.empty());
}

TEST(Pkcs11ConfigParserTest, RejectsMissingSchemaVersion)
{
    TemporaryPkcs11Config file{{TokenInput{"TokenA", "", "", "HSM_A"}}, 0U, 1U, false};
    Pkcs11Config config;
    const auto path = file.Path();

    EXPECT_FALSE(config.ParseConfig(std::optional<std::string_view>{path}).has_value());
    EXPECT_TRUE(config.GetConfig().tokens.empty());
}

TEST(Pkcs11ConfigParserTest, RejectsWrongFileIdentifier)
{
    TemporaryPkcs11Config file{{TokenInput{"TokenA", "", "", "HSM_A"}}, 0U, 1U, true, false};
    Pkcs11Config config;
    const auto path = file.Path();

    EXPECT_FALSE(config.ParseConfig(std::optional<std::string_view>{path}).has_value());
    EXPECT_TRUE(config.GetConfig().tokens.empty());
}

TEST(Pkcs11ConfigParserTest, RejectsEmptyTokenList)
{
    TemporaryPkcs11Config file{std::vector<TokenInput>{}};
    Pkcs11Config config;
    const auto path = file.Path();

    EXPECT_FALSE(config.ParseConfig(std::optional<std::string_view>{path}).has_value());
    EXPECT_TRUE(config.GetConfig().tokens.empty());
}

TEST(Pkcs11ConfigParserTest, RejectsUnknownProviderTypeTransactionally)
{
    TemporaryPkcs11Config file{
        {TokenInput{"TokenA", "", "", "HSM_A", static_cast<schema::ProviderType>(99), schema::CleanupStrategy::HARD}}};
    Pkcs11Config config;
    const auto path = file.Path();

    EXPECT_FALSE(config.ParseConfig(std::optional<std::string_view>{path}).has_value());
    EXPECT_TRUE(config.GetConfig().tokens.empty());
}

TEST(Pkcs11ConfigParserTest, RejectsUnknownCleanupStrategyTransactionally)
{
    TemporaryPkcs11Config file{{TokenInput{
        "TokenA", "", "", "HSM_A", schema::ProviderType::HARDWARE, static_cast<schema::CleanupStrategy>(99)}}};
    Pkcs11Config config;
    const auto path = file.Path();

    EXPECT_FALSE(config.ParseConfig(std::optional<std::string_view>{path}).has_value());
    EXPECT_TRUE(config.GetConfig().tokens.empty());
}

TEST(Pkcs11ConfigParserTest, RejectsBlankOrControlCharacterRequiredFields)
{
    TemporaryPkcs11Config blank_label_file{{TokenInput{" \t\n", "", "", "HSM_A"}}};
    Pkcs11Config blank_label_config;
    const auto blank_label_path = blank_label_file.Path();
    EXPECT_FALSE(blank_label_config.ParseConfig(std::optional<std::string_view>{blank_label_path}).has_value());
    EXPECT_TRUE(blank_label_config.GetConfig().tokens.empty());

    TemporaryPkcs11Config control_character_file{{TokenInput{"TokenA", "", "", "HSM\nA"}}};
    Pkcs11Config control_character_config;
    const auto control_character_path = control_character_file.Path();
    EXPECT_FALSE(
        control_character_config.ParseConfig(std::optional<std::string_view>{control_character_path}).has_value());
    EXPECT_TRUE(control_character_config.GetConfig().tokens.empty());
}

TEST(Pkcs11ConfigParserTest, RejectsEmptyMalformedAndOversizedFiles)
{
    TemporaryRawConfig empty_file{0U};
    TemporaryRawConfig malformed_file{64U};
    TemporaryRawConfig oversized_file{(1024U * 1024U) + 1U};

    Pkcs11Config empty_config;
    const auto empty_path = empty_file.Path();
    EXPECT_FALSE(empty_config.ParseConfig(std::optional<std::string_view>{empty_path}).has_value());
    EXPECT_TRUE(empty_config.GetConfig().tokens.empty());

    Pkcs11Config malformed_config;
    const auto malformed_path = malformed_file.Path();
    EXPECT_FALSE(malformed_config.ParseConfig(std::optional<std::string_view>{malformed_path}).has_value());
    EXPECT_TRUE(malformed_config.GetConfig().tokens.empty());

    Pkcs11Config oversized_config;
    const auto oversized_path = oversized_file.Path();
    EXPECT_FALSE(oversized_config.ParseConfig(std::optional<std::string_view>{oversized_path}).has_value());
    EXPECT_TRUE(oversized_config.GetConfig().tokens.empty());
}

TEST(Pkcs11ConfigParserTest, SuppliedMissingFileDoesNotFallBackToDefaults)
{
    static std::atomic<std::uint64_t> sequence{0U};
    const auto path = std::filesystem::temp_directory_path() /
                      ("missing_pkcs11_backend_config_" + std::to_string(sequence.fetch_add(1U)) + ".bin");
    std::error_code error;
    std::filesystem::remove(path, error);
    Pkcs11Config config;
    const auto path_string = path.string();

    EXPECT_FALSE(config.ParseConfig(std::optional<std::string_view>{path_string}).has_value());
    EXPECT_TRUE(config.GetConfig().tokens.empty());
}

TEST(Pkcs11ConfigParserTest, PreservesExistingDefaultWhenNoRuntimeConfigIsProvided)
{
    Pkcs11Config config;

    ASSERT_TRUE(config.ParseConfig(std::nullopt).has_value());
    ASSERT_EQ(config.GetConfig().tokens.size(), 1U);
    EXPECT_EQ(config.GetConfig().tokens.front().providerName, "PKCS11_ENGINE");
}

TEST(Pkcs11ConfigParserTest, SuppliedRuntimeConfigReplacesPreviouslySelectedDefaults)
{
    TemporaryPkcs11Config file{{TokenInput{"ConfiguredToken", "", "", "CONFIGURED_PROVIDER"}}};
    Pkcs11Config config;

    ASSERT_TRUE(config.ParseConfig(std::nullopt).has_value());
    ASSERT_EQ(config.GetConfig().tokens.size(), 1U);
    EXPECT_EQ(config.GetConfig().tokens.front().providerName, "PKCS11_ENGINE");

    const auto path = file.Path();
    ASSERT_TRUE(config.ParseConfig(std::optional<std::string_view>{path}).has_value());
    ASSERT_EQ(config.GetConfig().tokens.size(), 1U);
    EXPECT_EQ(config.GetConfig().tokens.front().providerName, "CONFIGURED_PROVIDER");
}

}  // namespace
}  // namespace score::crypto::daemon::provider::pkcs11
