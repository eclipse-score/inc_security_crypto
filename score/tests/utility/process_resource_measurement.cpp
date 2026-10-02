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

#include "score/tests/utility/process_resource_measurement.hpp"

#include <sys/resource.h>

#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <limits>
#include <string_view>

#if defined(__QNXNTO__)
#include <devctl.h>
#include <fcntl.h>
#include <sys/procfs.h>
#include <unistd.h>
#endif

namespace tests::utility
{
namespace
{

#if defined(__linux__)
std::uint64_t ReadProcValueBytes(const char* field_name, bool& available)
{
    available = false;
    FILE* status_file = std::fopen("/proc/self/status", "r");
    if (status_file == nullptr)
    {
        return 0U;
    }

    char line[256]{};
    while (std::fgets(line, sizeof(line), status_file) != nullptr)
    {
        char parsed_field[64]{};
        unsigned long long parsed_value = 0U;
        char unit[32]{};
        if (std::sscanf(line, "%63[^:]: %llu %31s", parsed_field, &parsed_value, unit) == 3 &&
            std::strcmp(parsed_field, field_name) == 0)
        {
            std::fclose(status_file);
            available = true;
            return static_cast<std::uint64_t>(parsed_value) * 1024U;
        }
    }

    std::fclose(status_file);
    return 0U;
}

std::uint64_t ReadProcThreadCount(bool& available)
{
    available = false;
    FILE* status_file = std::fopen("/proc/self/status", "r");
    if (status_file == nullptr)
    {
        return 0U;
    }

    char line[256]{};
    while (std::fgets(line, sizeof(line), status_file) != nullptr)
    {
        unsigned long long parsed_value = 0U;
        if (std::sscanf(line, "Threads: %llu", &parsed_value) == 1)
        {
            std::fclose(status_file);
            available = true;
            return static_cast<std::uint64_t>(parsed_value);
        }
    }

    std::fclose(status_file);
    return 0U;
}
#endif

#if defined(__QNXNTO__)
void ReadQnxVmStat(ProcessResourceSnapshot& snapshot)
{
    const long page_size = sysconf(_SC_PAGESIZE);
    if (page_size <= 0)
    {
        return;
    }

    char vmstat_path[64]{};
    std::snprintf(vmstat_path, sizeof(vmstat_path), "/proc/%d/vmstat", static_cast<int>(getpid()));
    FILE* vmstat_file = std::fopen(vmstat_path, "r");
    if (vmstat_file == nullptr)
    {
        return;
    }

    const std::uint64_t page_size_bytes = static_cast<std::uint64_t>(page_size);
    char line[256]{};
    while (std::fgets(line, sizeof(line), vmstat_file) != nullptr)
    {
        char field[64]{};
        unsigned long long page_count = 0U;
        if (std::sscanf(line, "%63[^=]=0x%llx", field, &page_count) != 2)
        {
            continue;
        }

        const bool is_resident = std::strcmp(field, "as_stats.rss") == 0;
        const bool is_virtual = std::strcmp(field, "as_stats.map_size") == 0;
        if ((!is_resident && !is_virtual) ||
            static_cast<std::uint64_t>(page_count) >
                (std::numeric_limits<std::uint64_t>::max() / page_size_bytes))
        {
            continue;
        }

        const std::uint64_t value_bytes = static_cast<std::uint64_t>(page_count) * page_size_bytes;
        if (is_resident)
        {
            snapshot.resident_bytes = value_bytes;
            snapshot.resident_available = true;
        }
        else
        {
            snapshot.virtual_bytes = value_bytes;
            snapshot.virtual_available = true;
        }
    }

    std::fclose(vmstat_file);
}

void ReadQnxThreadCount(ProcessResourceSnapshot& snapshot)
{
    char ctl_path[64]{};
    std::snprintf(ctl_path, sizeof(ctl_path), "/proc/%d/ctl", static_cast<int>(getpid()));
    const int ctl_fd = open(ctl_path, O_RDONLY);
    if (ctl_fd < 0)
    {
        return;
    }

    std::uint64_t count = 0U;
    pthread_t requested_tid = static_cast<pthread_t>(1U);
    bool enumeration_complete = false;
    for (;;)
    {
        procfs_status status{};
        status.tid = requested_tid;
        const int result = devctl(ctl_fd, DCMD_PROC_TIDSTATUS, &status, sizeof(status), nullptr);
        if (result == ESRCH)
        {
            enumeration_complete = count > 0U;
            break;
        }
        if (result != EOK || status.tid < requested_tid)
        {
            break;
        }

        ++count;
        requested_tid = status.tid;
        ++requested_tid;
    }

    close(ctl_fd);
    if (enumeration_complete)
    {
        snapshot.thread_count = count;
        snapshot.thread_count_available = true;
    }
}
#endif

ProcessResourceSnapshot CaptureProcessResourceSnapshotImpl()
{
    ProcessResourceSnapshot snapshot;

#if defined(__linux__)
    snapshot.resident_bytes = ReadProcValueBytes("VmRSS", snapshot.resident_available);
    snapshot.virtual_bytes = ReadProcValueBytes("VmSize", snapshot.virtual_available);
    snapshot.thread_count = ReadProcThreadCount(snapshot.thread_count_available);
#elif defined(__QNXNTO__)
    ReadQnxVmStat(snapshot);
    ReadQnxThreadCount(snapshot);
#endif

    struct rusage usage
    {
    };
    if (getrusage(RUSAGE_SELF, &usage) == 0)
    {
        snapshot.cpu_user_time_ns = static_cast<std::uint64_t>(usage.ru_utime.tv_sec) * 1'000'000'000U +
                                    static_cast<std::uint64_t>(usage.ru_utime.tv_usec) * 1'000U;
        snapshot.cpu_system_time_ns = static_cast<std::uint64_t>(usage.ru_stime.tv_sec) * 1'000'000'000U +
                                      static_cast<std::uint64_t>(usage.ru_stime.tv_usec) * 1'000U;
        snapshot.cpu_time_available = true;

#if defined(__linux__)
        snapshot.peak_resident_bytes = static_cast<std::uint64_t>(usage.ru_maxrss);
        snapshot.peak_resident_bytes *= 1024U;
        snapshot.peak_resident_available = true;

        snapshot.voluntary_context_switches = static_cast<std::uint64_t>(usage.ru_nvcsw);
        snapshot.involuntary_context_switches = static_cast<std::uint64_t>(usage.ru_nivcsw);
        snapshot.context_switches_available = true;
#endif
    }

    return snapshot;
}

void PrintResourceValue(const char* name, bool available, std::uint64_t value)
{
    if (available)
    {
        std::fprintf(stdout, " %s=%" PRIu64, name, value);
    }
    else
    {
        std::fprintf(stdout, " %s=unavailable", name);
    }
}

void PrintProcessResourceDeltaImpl(std::string_view tag,
                                   const ProcessResourceSnapshot& before,
                                   const ProcessResourceSnapshot& after)
{
    std::fprintf(stdout,
                 "[Resources] %.*s:",
                 static_cast<int>(tag.size()),
                 tag.data());
    PrintResourceValue("resident_before_bytes", before.resident_available, before.resident_bytes);
    PrintResourceValue("resident_after_bytes", after.resident_available, after.resident_bytes);
    PrintResourceValue("peak_resident_before_bytes", before.peak_resident_available, before.peak_resident_bytes);
    PrintResourceValue("peak_resident_after_bytes", after.peak_resident_available, after.peak_resident_bytes);
    PrintResourceValue("virtual_before_bytes", before.virtual_available, before.virtual_bytes);
    PrintResourceValue("virtual_after_bytes", after.virtual_available, after.virtual_bytes);
    PrintResourceValue("threads_before", before.thread_count_available, before.thread_count);
    PrintResourceValue("threads_after", after.thread_count_available, after.thread_count);
    PrintResourceValue("voluntary_cs_before", before.context_switches_available, before.voluntary_context_switches);
    PrintResourceValue("voluntary_cs_after", after.context_switches_available, after.voluntary_context_switches);
    PrintResourceValue("involuntary_cs_before", before.context_switches_available, before.involuntary_context_switches);
    PrintResourceValue("involuntary_cs_after", after.context_switches_available, after.involuntary_context_switches);
    PrintResourceValue("cpu_user_time_before_ns", before.cpu_time_available, before.cpu_user_time_ns);
    PrintResourceValue("cpu_user_time_after_ns", after.cpu_time_available, after.cpu_user_time_ns);
    PrintResourceValue("cpu_system_time_before_ns", before.cpu_time_available, before.cpu_system_time_ns);
    PrintResourceValue("cpu_system_time_after_ns", after.cpu_time_available, after.cpu_system_time_ns);

    if (before.resident_available && after.resident_available)
    {
        std::fprintf(stdout,
                     " resident_delta_bytes=%" PRId64,
                     static_cast<std::int64_t>(after.resident_bytes) - static_cast<std::int64_t>(before.resident_bytes));
    }
    if (before.virtual_available && after.virtual_available)
    {
        std::fprintf(stdout,
                     " virtual_delta_bytes=%" PRId64,
                     static_cast<std::int64_t>(after.virtual_bytes) - static_cast<std::int64_t>(before.virtual_bytes));
    }
    if (before.context_switches_available && after.context_switches_available)
    {
        std::fprintf(stdout,
                     " voluntary_cs_delta=%" PRId64,
                     static_cast<std::int64_t>(after.voluntary_context_switches) -
                         static_cast<std::int64_t>(before.voluntary_context_switches));
        std::fprintf(stdout,
                     " involuntary_cs_delta=%" PRId64,
                     static_cast<std::int64_t>(after.involuntary_context_switches) -
                         static_cast<std::int64_t>(before.involuntary_context_switches));
    }
    if (before.cpu_time_available && after.cpu_time_available)
    {
        const std::int64_t user_delta = static_cast<std::int64_t>(after.cpu_user_time_ns) -
                                        static_cast<std::int64_t>(before.cpu_user_time_ns);
        const std::int64_t system_delta = static_cast<std::int64_t>(after.cpu_system_time_ns) -
                                          static_cast<std::int64_t>(before.cpu_system_time_ns);
        std::fprintf(stdout, " cpu_user_time_delta_ns=%" PRId64, user_delta);
        std::fprintf(stdout, " cpu_system_time_delta_ns=%" PRId64, system_delta);
        std::fprintf(stdout, " cpu_total_time_delta_ns=%" PRId64, user_delta + system_delta);
    }
    std::fprintf(stdout, "\n");
}

}  // namespace

ProcessResourceSnapshot CaptureProcessResourceSnapshot()
{
    return CaptureProcessResourceSnapshotImpl();
}

void PrintProcessResourceDelta(std::string_view tag,
                               const ProcessResourceSnapshot& before,
                               const ProcessResourceSnapshot& after)
{
    PrintProcessResourceDeltaImpl(tag, before, after);
}

}  // namespace tests::utility
