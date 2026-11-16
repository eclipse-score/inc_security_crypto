/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#ifndef SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TESTS_TEST_ENVIRONMENT_HPP
#define SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TESTS_TEST_ENVIRONMENT_HPP

#include <cstdlib>
#include <filesystem>
#include <string_view>

namespace score::crypto::daemon::cert_management::test
{
inline std::filesystem::path TempDirectory(std::string_view name)
{
    const char* test_tmpdir = std::getenv("TEST_TMPDIR");
    const auto base = (test_tmpdir != nullptr && *test_tmpdir != '\0') ? std::filesystem::path{test_tmpdir}
                                                                       : std::filesystem::path{"/tmp"};
    return base / name;
}

inline std::filesystem::path TestVectorPath(std::string_view relative_path)
{
    const char* test_srcdir = std::getenv("TEST_SRCDIR");
    if (test_srcdir != nullptr && *test_srcdir != '\0')
    {
        const char* test_workspace = std::getenv("TEST_WORKSPACE");
        const auto workspace = (test_workspace != nullptr && *test_workspace != '\0') ? test_workspace : "_main";
        return std::filesystem::path{test_srcdir} / workspace / relative_path;
    }
    return std::filesystem::path{relative_path};
}

inline void ConfigureTestLogging()
{
    const auto config = TestVectorPath("score/tests/config/logging.json");
    static_cast<void>(setenv("MW_LOG_CONFIG_FILE", config.c_str(), 1));
}
}  // namespace score::crypto::daemon::cert_management::test

#endif  // SCORE_CRYPTO_SRC_DAEMON_CERT_MANAGEMENT_TESTS_TEST_ENVIRONMENT_HPP
