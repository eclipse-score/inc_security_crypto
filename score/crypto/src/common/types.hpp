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

#ifndef SCORE_CRYPTO_COMMON_TYPES_HPP
#define SCORE_CRYPTO_COMMON_TYPES_HPP

#include <utility>

#include "score/span.hpp"

#if STD_LIB_CPP17 == 0
#include "score/result/details/expected/expected.h"
#else
#include <variant>
#endif

namespace score
{
namespace crypto
{

#if STD_LIB_CPP17 == 1

// C++17 standard library implementation using std::variant
template <typename E>
class Unexpected
{
  private:
    E error_;

  public:
    explicit Unexpected(E error) : error_(std::move(error)) {}
    const E& value() const
    {
        return error_;
    }
};

template <typename E>
Unexpected<E> make_unexpected(E error)
{
    return Unexpected<E>(std::move(error));
}

// C++17 implementation of expected using std::variant
template <typename T, typename E>
class Expected
{
  private:
    std::variant<T, E> m_data;

  public:
    // Constructors for success case
    Expected(T value) : m_data(std::move(value)) {}

    // Constructor for error case using unexpected
    Expected(Unexpected<E> err) : m_data(std::move(err.value())) {}

    // Implicit conversion constructor from any type convertible to T
    template <typename U, typename = std::enable_if_t<std::is_convertible_v<U, T> && !std::is_same_v<U, Unexpected<E>>>>
    Expected(U&& value) : m_data(T(std::forward<U>(value)))
    {
    }

    // Boolean operator - returns true if contains value
    explicit operator bool() const
    {
        return std::holds_alternative<T>(m_data);
    }

    // Check if contains value
    bool has_value() const
    {
        return std::holds_alternative<T>(m_data);
    }

    // Get value (throws if contains error)
    T& value()
    {
        if (!has_value())
        {
            throw std::bad_variant_access();
        }
        return std::get<T>(m_data);
    }

    const T& value() const
    {
        if (!has_value())
        {
            throw std::bad_variant_access();
        }
        return std::get<T>(m_data);
    }

    // Get error
    E& error()
    {
        if (has_value())
        {
            throw std::bad_variant_access();
        }
        return std::get<E>(m_data);
    }

    const E& error() const
    {
        if (has_value())
        {
            throw std::bad_variant_access();
        }
        return std::get<E>(m_data);
    }

    // Move value out
    T&& operator*() &&
    {
        return std::move(std::get<T>(m_data));
    }

    // Reference to value
    T& operator*() &
    {
        return std::get<T>(m_data);
    }

    const T& operator*() const&
    {
        return std::get<T>(m_data);
    }
};

#else

// Use score::details::expected from baselibs/futurecpp directly
// Simple type aliases - no wrappers needed
template <typename T, typename E>
using Expected = score::details::expected<T, E>;

// Forward to score::cpp::unexpected
template <typename E>
auto make_unexpected(E error)
{
    return score::details::unexpected(std::move(error));
}

template <typename T>
using span = score::cpp::span<T>;

#endif

}  // namespace crypto
}  // namespace score

#endif  // SCORE_CRYPTO_COMMON_TYPES_HPP
