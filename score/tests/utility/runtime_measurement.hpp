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

#ifndef TESTS_UTILITY_RUNTIME_MEASUREMENT_HPP
#define TESTS_UTILITY_RUNTIME_MEASUREMENT_HPP

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdio>
#include <cstdint>
#include <limits>
#include <mutex>
#include <string_view>
#include <thread>
#include <vector>

namespace score::crypto::daemon::common
{

class RuntimeMeasurement final
{
  public:
	explicit RuntimeMeasurement(const bool enable_individual_output = false)
		: enable_individual_output_(enable_individual_output)
	{
		measurements_.reserve(1024U * 1024U);
	}

	class ScopedMeasurement final
	{
	  public:
		ScopedMeasurement(RuntimeMeasurement& measurement, std::string_view tag)
			: measurement_(measurement), tag_(tag)
		{
			measurement_.Start(tag_);
		}

		~ScopedMeasurement() noexcept
		{
			measurement_.End(tag_);
		}

		ScopedMeasurement(const ScopedMeasurement&) = delete;
		ScopedMeasurement& operator=(const ScopedMeasurement&) = delete;

	  private:
		RuntimeMeasurement& measurement_;
		std::string_view tag_;
	};

	static RuntimeMeasurement& Instance() noexcept
	{
		static RuntimeMeasurement instance;
		return instance;
	}

	void Start(std::string_view tag)
	{
		std::lock_guard<std::mutex> lock(mutex_);
		measurements_.push_back({tag, Clock::now(), std::this_thread::get_id(), true});
	}

	void End(std::string_view tag)
	{
		std::lock_guard<std::mutex> lock(mutex_);
		measurements_.push_back({tag, Clock::now(), std::this_thread::get_id(), false});
	}

	void RecordElapsed(std::string_view tag, const std::chrono::steady_clock::time_point start)
	{
		const auto end = Clock::now();
		std::lock_guard<std::mutex> lock(mutex_);
		measurements_.push_back({tag, start, std::this_thread::get_id(), true});
		measurements_.push_back({tag, end, std::this_thread::get_id(), false});
	}

	void Print() noexcept
	{
		std::lock_guard<std::mutex> lock(mutex_);
		const auto unmatched = std::numeric_limits<std::size_t>::max();
		std::vector<std::size_t> end_for_start(measurements_.size(), unmatched);
		std::vector<bool> matched_end(measurements_.size(), false);
		struct Summary
		{
			std::string_view tag;
			std::uint64_t total_nanoseconds{0U};
			std::size_t count{0U};
			std::vector<std::uint64_t> durations;
		};
		std::vector<Summary> summaries;
		summaries.reserve(measurements_.size());
		constexpr std::string_view kOpenSslTagPrefix{"OpenSSL::"};

		for (std::size_t end_index = 0; end_index < measurements_.size(); ++end_index)
		{
			const auto& end_measurement = measurements_[end_index];
			if (end_measurement.is_start)
			{
				continue;
			}

			for (std::size_t start_index = end_index; start_index > 0U; --start_index)
			{
				const auto candidate_index = start_index - 1U;
				const auto& candidate = measurements_[candidate_index];
				if (candidate.is_start && end_for_start[candidate_index] == unmatched &&
					candidate.thread_id == end_measurement.thread_id && candidate.tag == end_measurement.tag)
				{
					end_for_start[candidate_index] = end_index;
					matched_end[end_index] = true;
					break;
				}
			}
		}

		for (std::size_t start_index = 0; start_index < measurements_.size(); ++start_index)
		{
			const auto& start_measurement = measurements_[start_index];
			if (!start_measurement.is_start)
			{
				continue;
			}

			if (end_for_start[start_index] == unmatched)
			{
				std::fprintf(stderr,
							 "[Timing] incomplete measurement for %.*s\n",
							 static_cast<int>(start_measurement.tag.size()),
							 start_measurement.tag.data());
				std::fflush(stderr);
				continue;
			}

			const auto& end_measurement = measurements_[end_for_start[start_index]];
			const auto elapsed =
				std::chrono::duration_cast<std::chrono::nanoseconds>(end_measurement.time - start_measurement.time);
			if (enable_individual_output_)
			{
				std::fprintf(stdout,
							 "[Timing] %.*s: %lld ns\n",
							 static_cast<int>(start_measurement.tag.size()),
							 start_measurement.tag.data(),
							 static_cast<long long>(elapsed.count()));
				std::fflush(stdout);
			}

			Summary* summary = nullptr;
			for (auto& candidate : summaries)
			{
				if (candidate.tag == start_measurement.tag)
				{
					summary = &candidate;
					break;
				}
			}
			if (summary == nullptr)
			{
				summaries.push_back({start_measurement.tag, 0U, 0U, {}});
				summary = &summaries.back();
			}
			summary->total_nanoseconds += static_cast<std::uint64_t>(elapsed.count());
			++summary->count;
			summary->durations.push_back(static_cast<std::uint64_t>(elapsed.count()));
		}

		for (std::size_t end_index = 0; end_index < measurements_.size(); ++end_index)
		{
			if (!measurements_[end_index].is_start && !matched_end[end_index])
			{
				std::fprintf(stderr,
							 "[Timing] incomplete end measurement for %.*s\n",
							 static_cast<int>(measurements_[end_index].tag.size()),
							 measurements_[end_index].tag.data());
				std::fflush(stderr);
			}
		}

		std::uint64_t open_ssl_average_sum_nanoseconds{0U};
		std::size_t open_ssl_subpart_count{0U};
		for (const auto& summary : summaries)
		{
			const auto average_nanoseconds = summary.total_nanoseconds / summary.count;
			auto sorted_durations = summary.durations;
			std::sort(sorted_durations.begin(), sorted_durations.end());
			const auto nearest_rank = [&sorted_durations](const std::size_t numerator, const std::size_t denominator) {
				const auto rank = (sorted_durations.size() * numerator + denominator - 1U) / denominator;
				return sorted_durations[rank - 1U];
			};
			const auto p50_nanoseconds = nearest_rank(1U, 2U);
			const auto p90_nanoseconds = nearest_rank(9U, 10U);
			const auto p99_nanoseconds = nearest_rank(99U, 100U);
			std::fprintf(stdout,
						 "[Timing] average %.*s: %llu ns over %zu measurement(s)\n",
						 static_cast<int>(summary.tag.size()),
						 summary.tag.data(),
						 static_cast<unsigned long long>(average_nanoseconds),
						 summary.count);
			std::fprintf(stdout,
						 "[Timing] p50 %.*s: %llu ns\n",
						 static_cast<int>(summary.tag.size()),
						 summary.tag.data(),
						 static_cast<unsigned long long>(p50_nanoseconds));
			std::fprintf(stdout,
						 "[Timing] p90 %.*s: %llu ns\n",
						 static_cast<int>(summary.tag.size()),
						 summary.tag.data(),
						 static_cast<unsigned long long>(p90_nanoseconds));
			std::fprintf(stdout,
						 "[Timing] p99 %.*s: %llu ns\n",
						 static_cast<int>(summary.tag.size()),
						 summary.tag.data(),
						 static_cast<unsigned long long>(p99_nanoseconds));
			std::fflush(stdout);

			if (summary.tag.size() >= kOpenSslTagPrefix.size() &&
				summary.tag.compare(0U, kOpenSslTagPrefix.size(), kOpenSslTagPrefix) == 0)
			{
				open_ssl_average_sum_nanoseconds += average_nanoseconds;
				++open_ssl_subpart_count;
			}
		}

		if (open_ssl_subpart_count > 0U)
		{
			std::fprintf(stdout,
						 "[Timing] sum of OpenSSL subpart averages: %llu ns over %zu subpart(s)\n",
						 static_cast<unsigned long long>(open_ssl_average_sum_nanoseconds),
						 open_ssl_subpart_count);
			std::fflush(stdout);
		}

		std::fflush(stdout);
	}

	~RuntimeMeasurement() noexcept
	{
		Print();
	}

	RuntimeMeasurement(const RuntimeMeasurement&) = delete;
	RuntimeMeasurement& operator=(const RuntimeMeasurement&) = delete;

  private:
	using Clock = std::chrono::steady_clock;
	using TimePoint = Clock::time_point;
	static_assert(Clock::is_steady, "Runtime measurements require a monotonic clock");

	struct Measurement
	{
		std::string_view tag;
		TimePoint time;
		std::thread::id thread_id;
		bool is_start;
	};

	const bool enable_individual_output_;
	std::mutex mutex_;
	std::vector<Measurement> measurements_;
};

}  // namespace score::crypto::daemon::common

namespace tests::utility
{

using RuntimeMeasurement = ::score::crypto::daemon::common::RuntimeMeasurement;

}  // namespace tests::utility

#endif  // TESTS_UTILITY_RUNTIME_MEASUREMENT_HPP
