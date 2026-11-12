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

#ifndef SCORE_TESTS_INTEGRATION_TESTS_CSR_DER_TEST_HELPER_HPP
#define SCORE_TESTS_INTEGRATION_TESTS_CSR_DER_TEST_HELPER_HPP

#include <cstddef>
#include <cstdint>
#include <vector>

namespace score
{
namespace crypto
{
namespace test
{
constexpr std::size_t kMaxCsrDerBytes = 64U * 1024U;

// Private Linux integration-test bridge: public DER only, no SCORE or provider
// types. Failures in the offline sibling verifier become GoogleTest failures.
void VerifyCsrDer(const char* mode,
                  const std::vector<std::uint8_t>& first,
                  const std::vector<std::uint8_t>& second = {},
                  const char* expected_common_name = nullptr);
}  // namespace test
}  // namespace crypto
}  // namespace score

#endif  // SCORE_TESTS_INTEGRATION_TESTS_CSR_DER_TEST_HELPER_HPP
