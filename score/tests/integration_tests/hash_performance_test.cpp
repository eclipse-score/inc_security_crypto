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

/// @file hash_performance_test.cpp
/// @brief Validates concurrent and sequential hash operations via pool and bulk SHM paths.
/// disclaimer :  This is an early version and should actually be changed to google benchmark type of performance test.
/// The test is parameterized: GetParam()==true  → tasks run in parallel threads
///                             GetParam()==false → tasks run sequentially (no threads).

#include "score/crypto/src/api/config/hash_context_config.hpp"
#include "score/crypto/src/api/contexts/i_hash_context.hpp"
#include "score/crypto/src/api/crypto_stack_factory.hpp"
#include "score/crypto/src/api/i_crypto_context.hpp"
#include "score/crypto/src/api/i_crypto_stack.hpp"
#include "score/tests/utility/test_utility.hpp"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <optional>
#include <string>
#include <thread>
#include <vector>

using namespace score::crypto;
using tests::utility::Barrier;
using tests::utility::COLOR_RESET;
using tests::utility::GetThreadColor;
using tests::utility::print_hex;

namespace
{
constexpr const char* kDaemonEndpoint = "unix:///tmp/crypto_daemon.sock";
constexpr std::size_t kSha512DigestSize = 64U;
constexpr int kNumThreads = 4;

/// @brief Validates concurrent and sequential hash operations via pool and bulk SHM paths.
/// disclaimer :  This is an early version and should actually be changed to google benchmark type of performance test.
/// The test is parameterized: GetParam()==true  → tasks run in parallel threads
///                             GetParam()==false → tasks run sequentially (no threads).
struct ScalabilityTestParams
{
    bool run_parallel;             ///< true → parallel threads, false → sequential
    std::size_t input_size_small;  ///< Small input size (typically < 1024 B, 1 pool slot)
    std::size_t input_size_large;  ///< Large input size (typically > 1024 B, 2+ pool slots)

    // Helper to compute bulk region size
    std::size_t GetBulkRegionSize() const
    {
        return input_size_large + kSha512DigestSize;
    }
};

// Helpers
static score::Result<ICryptoStack::Uptr> MakeStack(std::optional<std::chrono::milliseconds> timeout = std::nullopt)
{
    CryptoStackConfig cfg;
    cfg.SetConnectionEndpoint(kDaemonEndpoint);
    if (timeout.has_value())
    {
        cfg.SetDefaultOperationTimeout(timeout.value());
    }
    return CreateCryptoStack(cfg);
}

static bool ComputeSha512WithNewStack(const std::string& input, std::vector<uint8_t>& out_digest)
{
    auto stack_result = MakeStack(std::chrono::milliseconds{1000});
    if (!stack_result.has_value())
    {
        return false;
    }
    auto ctx_result = stack_result.value()->CreateCryptoContext();
    if (!ctx_result.has_value())
    {
        return false;
    }

    HashContextConfig cfg;
    cfg.SetAlgorithm("SHA512");
    auto hash_result = ctx_result.value()->CreateHashContext(cfg);
    if (!hash_result.has_value())
    {
        return false;
    }
    auto& hash = hash_result.value();

    if (!hash->Init().has_value())
    {
        return false;
    }
    hash->Update({reinterpret_cast<const uint8_t*>(input.data()), input.size()});
    auto fin = hash->Finalize({out_digest.data(), out_digest.size()});
    return fin.has_value();
}

// ============================================================
// Test fixture — parameterised on execution mode and input sizes.
// ============================================================

class ScalabilityTest : public ::testing::TestWithParam<ScalabilityTestParams>
{
  public:
    void SetUp() override
    {
        const auto& params = GetParam();
        msg_small_ = std::string(params.input_size_small, 'A');
        msg_large_ = std::string(params.input_size_large, 'B');

        reference_digest_small_.assign(kSha512DigestSize, 0);
        reference_digest_large_.assign(kSha512DigestSize, 0);
        ASSERT_TRUE(ComputeSha512WithNewStack(msg_small_, reference_digest_small_))
            << "Reference SHA-512 (small) failed";
        ASSERT_TRUE(ComputeSha512WithNewStack(msg_large_, reference_digest_large_))
            << "Reference SHA-512 (large) failed";
    }

  protected:
    std::string msg_small_;
    std::string msg_large_;
    std::vector<uint8_t> reference_digest_small_;
    std::vector<uint8_t> reference_digest_large_;
};

// ============================================================
// Test — 4 tasks sharing 1 CryptoStack and 1 CryptoContext.
//
// Task 0  bulk SHM, large (1100 B, 2 slots)
// Task 1  pool SHM, small  (200 B, 1 slot)
// Task 2  bulk SHM, large (1100 B, 2 slots)
// Task 3  pool SHM, large (1100 B, 2 slots)
// ============================================================
TEST_P(ScalabilityTest, AlternatingPoolAndBulkSHM)
{
    const auto& params = GetParam();
    const bool run_parallel = params.run_parallel;

    auto stack_result = MakeStack(std::chrono::milliseconds{2000});
    ASSERT_TRUE(stack_result.has_value()) << "Stack creation failed";
    auto& stack = stack_result.value();

    auto ctx_result = stack->CreateCryptoContext();
    ASSERT_TRUE(ctx_result.has_value()) << "CreateCryptoContext failed";
    auto& ctx = ctx_result.value();

    std::cout << "\nAlternatingPoolAndBulkSHM — " << kNumThreads << " "
              << (run_parallel ? "parallel threads" : "sequential tasks") << "\n"
              << "  Tasks 0,2: bulk SHM, large (" << params.input_size_large << " B)\n"
              << "  Task  1:   pool SHM, small (" << params.input_size_small << " B)\n"
              << "  Task  3:   pool SHM, large (" << params.input_size_large << " B)\n";
    print_hex("  Reference SHA-512 (small)", reference_digest_small_, reference_digest_small_.size());
    print_hex("  Reference SHA-512 (large)", reference_digest_large_, reference_digest_large_.size());

    std::optional<Barrier> start_barrier;
    if (run_parallel)
    {
        start_barrier.emplace(kNumThreads);
    }

    std::vector<int> success_flags(static_cast<std::size_t>(kNumThreads), 0);
    std::vector<std::vector<uint8_t>> digests(static_cast<std::size_t>(kNumThreads),
                                              std::vector<uint8_t>(kSha512DigestSize, 0));

    auto run_task = [&](int i) {
        const std::string color = GetThreadColor(i);
        const bool use_bulk = (i % 2 == 0);
        const bool use_large = use_bulk || (i == 3);
        const std::string& task_msg = use_large ? msg_large_ : msg_small_;

        HashContextConfig cfg;
        cfg.SetAlgorithm("SHA512");
        auto hash_result = ctx->CreateHashContext(cfg);
        if (!hash_result.has_value())
        {
            std::cerr << color << "[T" << i << "] CreateHashContext failed" << COLOR_RESET << "\n";
            return;
        }
        auto& hash = hash_result.value();

        if (use_bulk)
        {
            auto alloc_result = stack->GetMemoryAllocator();
            if (!alloc_result.has_value())
            {
                std::cerr << color << "[T" << i << "] GetMemoryAllocator failed" << COLOR_RESET << "\n";
                return;
            }
            auto allocator = std::move(alloc_result).value();

            auto region_result = allocator->Allocate(params.GetBulkRegionSize());
            if (!region_result.has_value())
            {
                std::cerr << color << "[T" << i << "] Allocate failed" << COLOR_RESET << "\n";
                return;
            }
            auto bulk_region = std::move(region_result).value();

            std::memcpy(bulk_region->AsWritableSpan().data(), task_msg.data(), task_msg.size());
            const auto bulk_input = bulk_region->AsSpan().subspan(0, task_msg.size());
            uint8_t* output_ptr = bulk_region->AsWritableSpan().data() + task_msg.size();
            score::cpp::span<uint8_t> output_span{output_ptr, kSha512DigestSize};

            if (start_barrier)
            {
                start_barrier->Wait();
            }

            if (!hash->Init().has_value() || !hash->Update(bulk_input).has_value())
            {
                return;
            }
            const auto fin = hash->Finalize(output_span);
            if (!fin.has_value())
            {
                std::cerr << color << "[T" << i << "] Finalize failed" << COLOR_RESET << "\n";
                return;
            }

            std::memcpy(digests[static_cast<std::size_t>(i)].data(), output_ptr, kSha512DigestSize);
            bulk_region.reset();

            std::cout << color << "  [T" << i << "] bulk-path SHA-512 OK (" << task_msg.size() << " B)" << COLOR_RESET
                      << "\n";
        }
        else
        {
            const std::string local_msg(task_msg);

            if (start_barrier)
            {
                start_barrier->Wait();
            }

            if (!hash->Init().has_value())
            {
                return;
            }
            const auto update_res =
                hash->Update({reinterpret_cast<const uint8_t*>(local_msg.data()), local_msg.size()});
            if (!update_res.has_value())
            {
                return;
            }
            const auto fin = hash->Finalize({digests[static_cast<std::size_t>(i)].data(), kSha512DigestSize});
            if (!fin.has_value())
            {
                std::cerr << color << "[T" << i << "] Finalize failed" << COLOR_RESET << "\n";
                return;
            }

            std::cout << color << "  [T" << i << "] pool-path SHA-512 OK (" << local_msg.size() << " B)" << COLOR_RESET
                      << "\n";
        }

        success_flags[static_cast<std::size_t>(i)] = 1;
    };

    if (run_parallel)
    {
        std::vector<std::thread> threads;
        threads.reserve(static_cast<std::size_t>(kNumThreads));
        for (int i = 0; i < kNumThreads; ++i)
        {
            threads.emplace_back([&, i]() {
                run_task(i);
            });
        }
        for (auto& t : threads)
        {
            t.join();
        }
    }
    else
    {
        for (int i = 0; i < kNumThreads; ++i)
        {
            run_task(i);
        }
    }

    for (int i = 0; i < kNumThreads; ++i)
    {
        EXPECT_EQ(success_flags[static_cast<std::size_t>(i)], 1) << "Task " << i << " failed";
        const auto& expected = (i == 1) ? reference_digest_small_ : reference_digest_large_;
        EXPECT_EQ(digests[static_cast<std::size_t>(i)], expected) << "Task " << i << " digest does not match reference";
    }
}

INSTANTIATE_TEST_SUITE_P(
    Execution,
    ScalabilityTest,
    ::testing::Values(ScalabilityTestParams{true, 200U, 1100U},  // Parallel, small=200B, large=1100B
                      ScalabilityTestParams{false, 200U, 1100U}  // Sequential, small=200B, large=1100B
                      ),
    [](const ::testing::TestParamInfo<ScalabilityTestParams>& info) {
        std::string mode = info.param.run_parallel ? "Parallel" : "Sequential";
        return mode + "_Small" + std::to_string(info.param.input_size_small) + "_Large" +
               std::to_string(info.param.input_size_large);
    });

}  // namespace

int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
