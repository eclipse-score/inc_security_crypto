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

#include "score/tests/integration_tests/csr_der_test_helper.hpp"

#include <gtest/gtest.h>

#include <fcntl.h>
#include <spawn.h>
#include <sys/wait.h>
#include <unistd.h>
#include <limits.h>

#include <array>
#include <cerrno>
#include <cstdlib>
#include <memory>
#include <string>
#include <vector>

extern char** environ;

namespace score
{
namespace crypto
{
namespace test
{
namespace
{
class PublicDerFile
{
  public:
    PublicDerFile() : descriptor_{mkstemp(path_.data())} {}
    PublicDerFile(const PublicDerFile&) = delete;
    PublicDerFile& operator=(const PublicDerFile&) = delete;

    ~PublicDerFile()
    {
        if (descriptor_ != -1)
        {
            close(descriptor_);
            // Only the path successfully created by this instance is removed.
            unlink(path_.c_str());
        }
    }

    void Write(const std::vector<std::uint8_t>& der)
    {
        ASSERT_GE(descriptor_, 0) << "Cannot create private CSR evidence file: errno=" << errno;
        ASSERT_EQ(fcntl(descriptor_, F_SETFD, FD_CLOEXEC), 0);
        ASSERT_FALSE(der.empty());
        ASSERT_LE(der.size(), kMaxCsrDerBytes);
        std::size_t offset = 0U;
        while (offset < der.size())
        {
            const auto written = write(descriptor_, der.data() + offset, der.size() - offset);
            if (written == -1 && errno == EINTR)
            {
                continue;
            }
            ASSERT_GT(written, 0) << "Incomplete CSR evidence write: errno=" << errno;
            offset += static_cast<std::size_t>(written);
        }
    }

    const std::string& Path() const
    {
        return path_;
    }

  private:
    // mkstemp creates a unique, owner-only (0600) file; no fixture path is
    // deleted, including the persistent reference CSR used across restarts.
    std::string path_{"/tmp/score-csr-evidence-XXXXXX"};
    int descriptor_;
};

std::string VerifierPath()
{
    std::array<char, PATH_MAX> executable{};
    const auto size = readlink("/proc/self/exe", executable.data(), executable.size());
    if (size <= 0 || static_cast<std::size_t>(size) >= executable.size())
    {
        ADD_FAILURE() << "Cannot resolve deployed client executable: errno=" << errno;
        return {};
    }
    std::string path{executable.data(), static_cast<std::size_t>(size)};
    const auto separator = path.find_last_of('/');
    if (separator == std::string::npos)
    {
        ADD_FAILURE() << "Client executable has no absolute parent directory";
        return {};
    }
    path.resize(separator + 1U);
    path += "csr_der_test_verifier";
    return path;
}
}  // namespace

void VerifyCsrDer(const char* mode,
                  const std::vector<std::uint8_t>& first,
                  const std::vector<std::uint8_t>& second,
                  const char* expected_common_name)
{
    ASSERT_NE(mode, nullptr);
    ASSERT_FALSE(first.empty());
    ASSERT_LE(first.size(), kMaxCsrDerBytes);
    ASSERT_LE(second.size(), kMaxCsrDerBytes);
    ASSERT_FALSE(!second.empty() && expected_common_name != nullptr);
    const auto verifier = VerifierPath();
    ASSERT_FALSE(verifier.empty());

    PublicDerFile first_file;
    ASSERT_NO_FATAL_FAILURE(first_file.Write(first));
    std::unique_ptr<PublicDerFile> second_file;
    std::vector<std::string> values{verifier, mode, first_file.Path()};
    if (!second.empty())
    {
        second_file = std::make_unique<PublicDerFile>();
        ASSERT_NO_FATAL_FAILURE(second_file->Write(second));
        values.push_back(second_file->Path());
    }
    if (expected_common_name != nullptr)
    {
        values.emplace_back(expected_common_name);
    }
    std::vector<char*> arguments;
    for (auto& value : values)
    {
        arguments.push_back(value.data());
    }
    arguments.push_back(nullptr);

    // Avoid fork() while the SCORE client has gRPC background threads.
    pid_t child{};
    const int spawned = posix_spawn(&child, verifier.c_str(), nullptr, nullptr, arguments.data(), environ);
    ASSERT_EQ(spawned, 0) << "Cannot launch sibling verifier: " << verifier;
    int status = 0;
    pid_t waited{};
    do
    {
        waited = waitpid(child, &status, 0);
    } while (waited == -1 && errno == EINTR);
    ASSERT_EQ(waited, child) << "Cannot reap CSR verifier: errno=" << errno;
    ASSERT_TRUE(WIFEXITED(status)) << "CSR verifier terminated abnormally: " << status;
    ASSERT_EQ(WEXITSTATUS(status), 0) << "CSR oracle failed in mode " << mode;
}
}  // namespace test
}  // namespace crypto
}  // namespace score
