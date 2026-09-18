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

#include "score/crypto/src/daemon/common/storage/kv/kv_deployment_loader.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

namespace score::crypto::daemon::common::storage
{
namespace
{

std::filesystem::path TestPath(const std::string& suffix)
{
    return std::filesystem::temp_directory_path() /
           ("score_crypto_kv_deployment_loader_" +
            std::to_string(std::chrono::steady_clock::now().time_since_epoch().count()) + "_" + suffix);
}

std::string WriteDescriptor(const std::string& suffix, const std::string& content)
{
    const auto path = TestPath(suffix);
    std::ofstream output{path};
    output << content;
    output.close();
    return path.string();
}

TEST(KvDeploymentLoaderTest, ValidDescriptorLoadsSuccessfully)
{
    const auto path = WriteDescriptor("valid",
                                      "[certificate]\n"
                                      "cert_path = /tmp/cert.pem\n"
                                      "cert_format = pem\n"
                                      "\n"
                                      "[crl]\n"
                                      "crl_path = /tmp/cert.crl\n");

    KvDeploymentLoader loader;
    const auto result = loader.Load(path);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->Get("certificate", "cert_path"), "/tmp/cert.pem");
    EXPECT_EQ(result->Get("certificate", "cert_format"), "pem");
    EXPECT_EQ(result->Get("crl", "crl_path"), "/tmp/cert.crl");
    std::filesystem::remove(path);
}

TEST(KvDeploymentLoaderTest, DuplicateKeyInSameSectionIsRejected)
{
    const auto path = WriteDescriptor("duplicate",
                                      "[certificate]\n"
                                      "cert_path = /tmp/first.pem\n"
                                      "cert_path = /tmp/second.pem\n");

    KvDeploymentLoader loader;
    const auto result = loader.Load(path);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    std::filesystem::remove(path);
}

TEST(KvDeploymentLoaderTest, DuplicateKeyWithSurroundingWhitespaceIsRejected)
{
    const auto path = WriteDescriptor("duplicate_whitespace",
                                      "[certificate]\n"
                                      "  cert_path  = /tmp/first.pem\n"
                                      "cert_path= /tmp/second.pem\n");

    KvDeploymentLoader loader;
    const auto result = loader.Load(path);

    ASSERT_FALSE(result.has_value());
    EXPECT_EQ(result.error(), DaemonErrorCode::kInvalidArgument);
    std::filesystem::remove(path);
}

TEST(KvDeploymentLoaderTest, SameKeyInDifferentSectionsIsAllowed)
{
    const auto path = WriteDescriptor("same_key_different_sections",
                                      "[certificate]\n"
                                      "path = /tmp/cert.pem\n"
                                      "\n"
                                      "[crl]\n"
                                      "path = /tmp/cert.crl\n");

    KvDeploymentLoader loader;
    const auto result = loader.Load(path);

    ASSERT_TRUE(result.has_value());
    EXPECT_EQ(result->Get("certificate", "path"), "/tmp/cert.pem");
    EXPECT_EQ(result->Get("crl", "path"), "/tmp/cert.crl");
    std::filesystem::remove(path);
}

}  // namespace
}  // namespace score::crypto::daemon::common::storage
