/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License Version 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0.
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

// =============================================================================
// WARNING: EXPERIMENTAL REFERENCE CODE - DO NOT USE IN PRODUCTION
//
// This file measures the local queue and worker scheduling path without IPC.
// =============================================================================

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <queue>
#include <random>
#include <thread>
#include <utility>
#include <vector>

#include "score/tests/utility/runtime_measurement.hpp"

namespace
{

using Clock = std::chrono::steady_clock;

constexpr int kProducerThreads{1};
constexpr int kWorkItemsPerProducer{1000};
constexpr int kWorkerThreads{8};
constexpr int kSleepMilliseconds{0};
constexpr bool kRandomWait{false};

void WaitAfterEnqueue(const bool random_wait)
{
    if (!random_wait)
    {
        return;
    }

    thread_local std::mt19937 generator{std::random_device{}()};
    std::uniform_int_distribution<int> distribution{0, 5};
    std::this_thread::sleep_for(std::chrono::milliseconds(distribution(generator)));
}

class ThreadStartBarrier final
{
  public:
    explicit ThreadStartBarrier(const std::size_t participant_count) : participant_count_{participant_count} {}

    void ArriveAndWait()
    {
        std::unique_lock<std::mutex> lock{mutex_};
        ++arrived_count_;
        condition_.notify_all();
        condition_.wait(lock, [this] { return released_; });
    }

    void WaitForAll()
    {
        std::unique_lock<std::mutex> lock{mutex_};
        condition_.wait(lock, [this] { return arrived_count_ == participant_count_; });
    }

    void Release()
    {
        {
            std::lock_guard<std::mutex> lock{mutex_};
            released_ = true;
        }
        condition_.notify_all();
    }

  private:
    const std::size_t participant_count_;
    std::size_t arrived_count_{0U};
    bool released_{false};
    std::mutex mutex_;
    std::condition_variable condition_;
};

struct WorkItem final
{
    std::uint64_t id{0U};
    std::vector<std::uint8_t> request_bytes;
    Clock::time_point queued_at;
};

struct WorkQueue final
{
    std::mutex mutex;
    std::condition_variable condition;
    std::queue<WorkItem> items;
    bool stopping{false};
};

void ProcessWorkItem(const WorkItem& item, const int sleep_milliseconds, std::atomic<std::uint64_t>& processed_items)
{
    static_cast<void>(item);
    if (sleep_milliseconds > 0)
    {
        std::this_thread::sleep_for(std::chrono::milliseconds(sleep_milliseconds));
    }

    processed_items.fetch_add(1U, std::memory_order_relaxed);
}

int Run()
{
    score::crypto::daemon::common::RuntimeMeasurement latency_measurement;
    WorkQueue work_queue;
    std::atomic<std::uint64_t> processed_items{0U};
    std::atomic<std::uint64_t> next_work_item_id{1U};

    const auto participant_count = static_cast<std::size_t>(kProducerThreads + kWorkerThreads);
    ThreadStartBarrier start_barrier{participant_count};
    std::vector<std::thread> workers;
    workers.reserve(static_cast<std::size_t>(kWorkerThreads));

    for (int worker_index = 0; worker_index < kWorkerThreads; ++worker_index)
    {
        workers.emplace_back([&, worker_index] {
            static_cast<void>(worker_index);
            start_barrier.ArriveAndWait();
            while (true)
            {
                std::unique_lock<std::mutex> lock{work_queue.mutex};
                work_queue.condition.wait(lock, [&] {
                    return !work_queue.items.empty() || work_queue.stopping;
                });

                if (work_queue.stopping && work_queue.items.empty())
                {
                    break;
                }

                WorkItem item = std::move(work_queue.items.front());
                work_queue.items.pop();
                lock.unlock();

                latency_measurement.RecordElapsed("POC::ThreadPool::QueueToProcessingStart", item.queued_at);
                ProcessWorkItem(item, kSleepMilliseconds, processed_items);
            }
        });
    }

    std::vector<std::thread> producers;
    producers.reserve(static_cast<std::size_t>(kProducerThreads));
    for (int producer_index = 0; producer_index < kProducerThreads; ++producer_index)
    {
        producers.emplace_back([&, producer_index] {
            start_barrier.ArriveAndWait();
            for (int item_index = 0; item_index < kWorkItemsPerProducer; ++item_index)
            {
                const auto work_item_id = next_work_item_id.fetch_add(1U, std::memory_order_relaxed);
                {
                    std::lock_guard<std::mutex> lock{work_queue.mutex};
                    const WorkItem item{work_item_id, {}, Clock::now()};
                    work_queue.items.push(item);
                }
                work_queue.condition.notify_one();
                WaitAfterEnqueue(kRandomWait);
            }
        });
    }

    start_barrier.WaitForAll();
    std::cout << "[Settings] producer_threads=" << kProducerThreads
              << " work_items_per_producer=" << kWorkItemsPerProducer
              << " worker_threads=" << kWorkerThreads
              << " sleep_milliseconds=" << kSleepMilliseconds
              << " random_wait=" << (kRandomWait ? "true" : "false") << '\n';
    start_barrier.Release();

    for (auto& producer : producers)
    {
        producer.join();
    }

    {
        std::lock_guard<std::mutex> lock{work_queue.mutex};
        work_queue.stopping = true;
    }
    work_queue.condition.notify_all();

    for (auto& worker : workers)
    {
        worker.join();
    }

    const auto expected_items = static_cast<std::uint64_t>(kProducerThreads) *
                                static_cast<std::uint64_t>(kWorkItemsPerProducer);
    std::cout << "[Result] processed_items=" << expected_items << '\n';
    return processed_items.load(std::memory_order_relaxed) == expected_items ? 0 : 1;
}

}  // namespace

int main()
{
    return Run();
}
