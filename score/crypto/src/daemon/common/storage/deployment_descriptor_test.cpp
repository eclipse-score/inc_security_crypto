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

#include "score/crypto/src/daemon/common/storage/deployment_descriptor.hpp"

#include <gtest/gtest.h>

#include <type_traits>

namespace score::crypto::daemon::common::storage
{
namespace
{

TEST(DeploymentDescriptorTest, MissingKeyWithoutDefaultReturnsStableEmptyString)
{
    DeploymentDescriptor descriptor;

    const auto& value = descriptor.Get("certificate", "cert_path");

    EXPECT_TRUE(value.empty());
    EXPECT_EQ(&value, &descriptor.Get("certificate", "cert_path"));
}

TEST(DeploymentDescriptorTest, MissingKeyWithDefaultReturnsDefaultValue)
{
    DeploymentDescriptor descriptor;

    const auto& value = descriptor.Get("certificate", "cert_path", "/default/path");

    EXPECT_EQ(value, "/default/path");
    static_assert(std::is_same_v<decltype(descriptor.Get("certificate", "cert_path", "/default/path")), std::string>);
}

TEST(DeploymentDescriptorTest, ExistingValueWithoutDefaultReturnsDescriptorValue)
{
    DeploymentDescriptor descriptor;
    descriptor.Set("certificate", "cert_path", "/certificate/path");

    const auto& value = descriptor.Get("certificate", "cert_path");

    EXPECT_EQ(value, "/certificate/path");
    static_assert(std::is_same_v<decltype((descriptor.Get("certificate", "cert_path"))), const std::string&>);
}

TEST(DeploymentDescriptorTest, ExistingValueWithDefaultReturnsDescriptorValue)
{
    DeploymentDescriptor descriptor;
    descriptor.Set("certificate", "cert_path", "/certificate/path");

    const auto value = descriptor.Get("certificate", "cert_path", "/default/path");

    EXPECT_EQ(value, "/certificate/path");
}

TEST(DeploymentDescriptorTest, StoresValuesWithoutFormatSpecificValidation)
{
    DeploymentDescriptor descriptor;

    descriptor.Set("certificate", "#_my_key", "my_value_\n_has_two_lines");

    EXPECT_TRUE(descriptor.HasKey("certificate", "#_my_key"));
    EXPECT_EQ(descriptor.Get("certificate", "#_my_key"), "my_value_\n_has_two_lines");
}

}  // namespace
}  // namespace score::crypto::daemon::common::storage
