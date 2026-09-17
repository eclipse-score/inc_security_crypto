/********************************************************************************
 * Copyright (c) 2026 Contributors to the Eclipse Foundation
 *
 * See the NOTICE file(s) distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This program and the accompanying materials are made available under the
 * terms of the Apache License 2.0 which is available at
 * https://www.apache.org/licenses/LICENSE-2.0
 *
 * SPDX-License-Identifier: Apache-2.0
 ********************************************************************************/

#ifndef SCORE_TESTS_UTILITY_PROCESS_RESOURCE_MEASUREMENT_HPP
#define SCORE_TESTS_UTILITY_PROCESS_RESOURCE_MEASUREMENT_HPP

#include <cstdint>
#include <string_view>

namespace tests::utility
{

struct ProcessResourceSnapshot
{
    std::uint64_t resident_bytes{0U};
    std::uint64_t peak_resident_bytes{0U};
    std::uint64_t virtual_bytes{0U};
    std::uint64_t thread_count{0U};
    std::uint64_t voluntary_context_switches{0U};
    std::uint64_t involuntary_context_switches{0U};
    std::uint64_t cpu_user_time_ns{0U};
    std::uint64_t cpu_system_time_ns{0U};
    bool resident_available{false};
    bool peak_resident_available{false};
    bool virtual_available{false};
    bool thread_count_available{false};
    bool context_switches_available{false};
    bool cpu_time_available{false};
};

ProcessResourceSnapshot CaptureProcessResourceSnapshot();

void PrintProcessResourceDelta(std::string_view tag,
                               const ProcessResourceSnapshot& before,
                               const ProcessResourceSnapshot& after);

}  // namespace tests::utility

#endif  // SCORE_TESTS_UTILITY_PROCESS_RESOURCE_MEASUREMENT_HPP
