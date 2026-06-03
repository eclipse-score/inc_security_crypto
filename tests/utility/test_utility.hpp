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

#ifndef TESTS_UTILITY_TEST_UTILITY_HPP
#define TESTS_UTILITY_TEST_UTILITY_HPP

#include <array>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace tests
{
namespace utility
{

// =========================================================================
// Color Enumeration
// =========================================================================

enum class Color : int
{
    Red = 0,             // Standard Red
    Green = 1,           // Standard Green
    Yellow = 2,          // Standard Yellow
    Blue = 3,            // Standard Blue
    Magenta = 4,         // Standard Magenta
    Cyan = 5,            // Standard Cyan
    BrightRed = 6,       // Bright Red
    BrightGreen = 7,     // Bright Green
    BrightYellow = 8,    // Bright Yellow
    BrightBlue = 9,      // Bright Blue
    BrightMagenta = 10,  // Bright Magenta
    BrightCyan = 11,     // Bright Cyan
    BrightWhite = 12,    // Bright White
    Orange = 13,         // Orange
    Pink = 14,           // Pink
    CyanBlue = 15        // Cyan Blue
};

/**
 * @brief Read binary file into a vector of bytes
 * @param path Path to the binary file
 * @return Vector containing the file contents
 */
std::vector<uint8_t> read_bin(const std::string& path);

/**
 * @brief Print bytes in hexadecimal format
 * @param prefix String to print before the hex values
 * @param v Vector of bytes to print
 * @param len Number of bytes to print from the vector
 * @param color Optional color enum (default: Color::BrightWhite for no color)
 */
void print_hex(const std::string& prefix,
               const std::vector<uint8_t>& vec,
               size_t len,
               Color color = Color::BrightWhite);

// ANSI color codes for thread output
inline const std::array<std::string, 16> COLOR_CODES = {
    "\033[31m",        // 0: Red
    "\033[32m",        // 1: Green
    "\033[33m",        // 2: Yellow
    "\033[34m",        // 3: Blue
    "\033[35m",        // 4: Magenta
    "\033[36m",        // 5: Cyan
    "\033[91m",        // 6: Bright Red
    "\033[92m",        // 7: Bright Green
    "\033[93m",        // 8: Bright Yellow
    "\033[94m",        // 9: Bright Blue
    "\033[95m",        // 10: Bright Magenta
    "\033[96m",        // 11: Bright Cyan
    "\033[97m",        // 12: Bright White
    "\033[38;5;208m",  // 13: Orange
    "\033[38;5;213m",  // 14: Pink
    "\033[38;5;51m"    // 15: Cyan Blue
};

inline const std::string COLOR_RESET = "\033[0m";

inline std::string GetThreadColor(int thread_id)
{
    return COLOR_CODES[static_cast<size_t>(thread_id) % COLOR_CODES.size()];
}

// =========================================================================
// Colored Print Helpers
// =========================================================================

/**
 * @brief Print colored text to stdout
 * @param message The message to print
 * @param color Color enum value (default: Color::BrightWhite)
 */
void print_colored(const std::string& message, Color color = Color::BrightWhite);

/**
 * @brief Print success message (green)
 */
void print_success(const std::string& message);

/**
 * @brief Print error message (bright red)
 */
void print_error(const std::string& message);

/**
 * @brief Print section header (bright cyan)
 */
void print_section(const std::string& message);

// Simple reusable barrier for synchronizing threads in tests
class Barrier
{
  public:
    explicit Barrier(int count) : threshold_(count), count_(count), generation_(0) {}

    void Wait()
    {
        std::unique_lock<std::mutex> lock(mutex_);
        int gen = generation_;
        if (--count_ == 0)
        {
            generation_++;
            count_ = threshold_;
            cv_.notify_all();
        }
        else
        {
            cv_.wait(lock, [this, gen] {
                return gen != generation_;
            });
        }
    }

  private:
    std::mutex mutex_;
    std::condition_variable cv_;
    int threshold_;
    int count_;
    int generation_;
};

}  // namespace utility
}  // namespace tests

#endif  // TESTS_UTILITY_TEST_UTILITY_HPP
