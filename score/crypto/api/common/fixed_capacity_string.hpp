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

#ifndef SCORE_MW_CRYPTO_API_COMMON_FIXED_CAPACITY_STRING_HPP
#define SCORE_MW_CRYPTO_API_COMMON_FIXED_CAPACITY_STRING_HPP

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstring>
#include <string>
#include <string_view>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief A fixed-capacity, stack-allocated string that never heap-allocates.
///
/// @par Usage
/// @code
///   FixedCapacityString<64> alg{"AES-256-CBC"};
///   alg = "ML-KEM-768";  // reassignment, still no allocation
///   std::string_view sv = alg;  // implicit conversion
///   assert(alg == "SHA-256");   // comparison with string literals
/// @endcode
template <std::size_t N>
class FixedCapacityString
{
  public:
    // TODO: Consider adding a static_assert to enforce a reasonable maximum capacity (e.g., N <= 256) to prevent
    // misuse.
    //       static_assert(N > 0U, "FixedCapacityString must have a positive capacity");
    //       static_assert(N <= 256U, "FixedCapacityString capacity should be reasonably small to avoid misuse");
    //       This would help catch errors at compile time if someone tries to create an excessively large
    //       FixedCapacityString.
    // TODO: mention additional methods from std::string that should be supported to make it easier to use.
    // TODO: Add a Create method that returns a std::optional<FixedCapacityString> to handle truncation more explicitly,
    // if desired.

    /// @brief Maximum number of characters this string can hold.
    static constexpr std::size_t max_capacity = N;

    /// @brief Default constructor — empty string.
    constexpr FixedCapacityString() noexcept : size_{0U}, truncated_{false}
    {
        data_[0U] = '\0';
    }

    /// @brief Constructs from a null-terminated C string.
    /// @param str Null-terminated string. If strlen(str) > N, the input is
    ///        silently truncated to N characters and truncated() returns true.
    ///
    /// @par Safety
    /// No exceptions — truncation is deterministic and bounded. Use
    /// truncated() after construction to detect data loss in debug builds.
    // NOLINTNEXTLINE(google-explicit-constructor)
    constexpr FixedCapacityString(const char* str) noexcept : size_{0U}, truncated_{false}
    {
        if (str != nullptr)
        {
            const std::size_t len = const_strlen(str);
            if (len > N)
            {
                size_ = N;
                truncated_ = true;
            }
            else
            {
                size_ = len;
            }
            for (std::size_t i = 0U; i < size_; ++i)
            {
                data_[i] = str[i];
            }
        }
        data_[size_] = '\0';
    }

    /// @brief Constructs from a std::string_view.
    /// @param sv String view. If sv.size() > N, the input is silently
    ///        truncated to N characters and truncated() returns true.
    // NOLINTNEXTLINE(google-explicit-constructor)
    constexpr FixedCapacityString(std::string_view sv) noexcept : size_{0U}, truncated_{false}
    {
        if (sv.size() > N)
        {
            size_ = N;
            truncated_ = true;
        }
        else
        {
            size_ = sv.size();
        }
        for (std::size_t i = 0U; i < size_; ++i)
        {
            data_[i] = sv[i];
        }
        data_[size_] = '\0';
    }

    /// @brief Constructs from a std::string.
    /// @param s String. If s.size() > N, the input is silently truncated.
    // NOLINTNEXTLINE(google-explicit-constructor)
    FixedCapacityString(const std::string& s) noexcept : FixedCapacityString(std::string_view{s}) {}

    // -- Defaulted copy/move (trivial — no heap resources) --

    constexpr FixedCapacityString(const FixedCapacityString&) = default;
    constexpr FixedCapacityString& operator=(const FixedCapacityString&) = default;
    constexpr FixedCapacityString(FixedCapacityString&&) noexcept = default;
    constexpr FixedCapacityString& operator=(FixedCapacityString&&) noexcept = default;
    ~FixedCapacityString() = default;

    /// @brief Assigns from a C string. Truncates if strlen(str) > N.
    FixedCapacityString& operator=(const char* str) noexcept
    {
        *this = FixedCapacityString{str};
        return *this;
    }

    /// @brief Assigns from a string_view. Truncates if sv.size() > N.
    FixedCapacityString& operator=(std::string_view sv) noexcept
    {
        *this = FixedCapacityString{sv};
        return *this;
    }

    /// @brief Assigns from a std::string. Truncates if s.size() > N.
    FixedCapacityString& operator=(const std::string& s) noexcept
    {
        *this = FixedCapacityString{std::string_view{s}};
        return *this;
    }

    // -- Accessors --

    /// @brief Returns a pointer to the null-terminated character data.
    constexpr const char* c_str() const noexcept
    {
        return data_.data();
    }

    /// @brief Returns a pointer to the character data.
    constexpr const char* data() const noexcept
    {
        return data_.data();
    }

    /// @brief Returns the number of characters (excluding null terminator).
    constexpr std::size_t size() const noexcept
    {
        return size_;
    }

    /// @brief Returns the number of characters (excluding null terminator).
    constexpr std::size_t length() const noexcept
    {
        return size_;
    }

    /// @brief Returns true if the string is empty.
    constexpr bool empty() const noexcept
    {
        return size_ == 0U;
    }

    /// @brief Returns true if the last assignment/construction truncated input.
    ///
    /// Use this to detect data loss after construction or assignment.
    /// In debug builds, callers may assert on this value for early detection
    /// of capacity mismatches. In production, truncation is a deterministic,
    /// bounded operation — no undefined behaviour occurs.
    ///
    /// @code
    ///   AlgorithmId alg{"VERY-LONG-ALGORITHM-NAME-THAT-EXCEEDS-64-CHARS..."};
    ///   if (alg.truncated()) {
    ///       // handle data loss — algorithm name was truncated
    ///   }
    /// @endcode
    constexpr bool truncated() const noexcept
    {
        return truncated_;
    }

    /// @brief Returns the maximum number of characters this string can hold.
    static constexpr std::size_t capacity() noexcept
    {
        return N;
    }

    // -- Conversions --

    /// @brief Implicit conversion to std::string_view.
    ///
    /// This is the primary interop mechanism. Enables passing a
    /// FixedCapacityString to any API that accepts std::string_view
    /// without allocation.
    // NOLINTNEXTLINE(google-explicit-constructor)
    constexpr operator std::string_view() const noexcept
    {
        return std::string_view{data_.data(), size_};
    }

    /// @brief Explicit conversion to std::string.
    ///
    /// This allocates — use only when a std::string is required
    /// (e.g., for IPC serialization).
    explicit operator std::string() const
    {
        return std::string{data_.data(), size_};
    }

    // -- Comparison operators --

    constexpr bool operator==(const FixedCapacityString& other) const noexcept
    {
        if (size_ != other.size_)
        {
            return false;
        }
        for (std::size_t i = 0U; i < size_; ++i)
        {
            if (data_[i] != other.data_[i])
            {
                return false;
            }
        }
        return true;
    }

    constexpr bool operator!=(const FixedCapacityString& other) const noexcept
    {
        return !(*this == other);
    }

    constexpr bool operator==(std::string_view sv) const noexcept
    {
        return std::string_view{data_.data(), size_} == sv;
    }

    constexpr bool operator!=(std::string_view sv) const noexcept
    {
        return !(*this == sv);
    }

    constexpr bool operator==(const char* str) const noexcept
    {
        return std::string_view{data_.data(), size_} == std::string_view{str};
    }

    constexpr bool operator!=(const char* str) const noexcept
    {
        return !(*this == str);
    }

    bool operator==(const std::string& s) const noexcept
    {
        return std::string_view{data_.data(), size_} == std::string_view{s};
    }

    bool operator!=(const std::string& s) const noexcept
    {
        return !(*this == s);
    }

    // -- Relational operators (for use in ordered containers) --

    constexpr bool operator<(const FixedCapacityString& other) const noexcept
    {
        return std::string_view{data_.data(), size_} < std::string_view{other.data_.data(), other.size_};
    }

  private:
    /// @brief Compile-time strlen for constexpr construction.
    static constexpr std::size_t const_strlen(const char* str) noexcept
    {
        // TODO: Improve to avoid any potential out-of-bounds access if str is not null-terminated within N+1
        // characters. For example, we could add a check to ensure we don't read beyond N characters:
        std::size_t len = 0U;
        while (str[len] != '\0')
        {
            ++len;
        }
        return len;
    }

    /// @brief Internal storage: N characters + null terminator.
    std::array<char, N + 1U> data_{};

    /// @brief Current string length (excluding null terminator).
    std::size_t size_{0U};

    /// @brief Whether the last construction/assignment truncated the input.
    bool truncated_{false};
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

/// @brief std::hash specialization for FixedCapacityString.
///
/// Enables use as key in std::unordered_map and std::unordered_set.
/// Delegates to std::hash<std::string_view> for consistent hashing.
template <std::size_t N>
struct std::hash<score::mw::crypto::FixedCapacityString<N>>
{
    std::size_t operator()(const score::mw::crypto::FixedCapacityString<N>& s) const noexcept
    {
        return std::hash<std::string_view>{}(std::string_view{s});
    }
};

#endif  // SCORE_MW_CRYPTO_API_COMMON_FIXED_CAPACITY_STRING_HPP
