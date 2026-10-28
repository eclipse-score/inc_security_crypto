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

#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_symmetric_key.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handle.hpp"
#include "score/crypto/src/daemon/provider/score_provider/openssl/key_management/openssl_key_handler.hpp"

#include <openssl/crypto.h>  // OPENSSL_cleanse
#include <openssl/rand.h>    // RAND_bytes

#include <cstdint>
#include <vector>

namespace score::crypto::daemon::provider::openssl
{

namespace
{
constexpr std::string_view kSymmetricKeyFamilies[] = {"AES-", "HMAC-"};

/// Wipes a key buffer when the enclosing scope exits, including by exception.
///
/// Once the buffer has been moved into an OpenSslKeyHandler it is empty, and
/// the wipe does nothing.
class CleanseOnExit final
{
  public:
    explicit CleanseOnExit(std::vector<std::uint8_t>& bytes) noexcept : m_bytes{bytes} {}
    ~CleanseOnExit()
    {
        OPENSSL_cleanse(m_bytes.data(), m_bytes.size());
    }

    CleanseOnExit(const CleanseOnExit&) = delete;
    CleanseOnExit& operator=(const CleanseOnExit&) = delete;
    CleanseOnExit(CleanseOnExit&&) = delete;
    CleanseOnExit& operator=(CleanseOnExit&&) = delete;

  private:
    std::vector<std::uint8_t>& m_bytes;
};
}  // namespace

bool IsSymmetricKeyAlgorithm(std::string_view algorithm) noexcept
{
    for (const auto family : kSymmetricKeyFamilies)
    {
        if (algorithm.substr(0U, family.size()) == family)
        {
            return true;
        }
    }
    return false;
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
GenerateSymmetricKey(common::ProviderId provider_id, const key_management::KeyGenerationRequest& request)
{
    const auto key_size = ::score::crypto::daemon::common::LookupKeySize(
        std::string_view{request.algorithm.data(), request.algorithm.size()});
    if (!key_size.has_value())
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kInvalidArgument);
    }

    std::vector<std::uint8_t> key_bytes(*key_size);
    const CleanseOnExit cleanse{key_bytes};

    if (RAND_bytes(key_bytes.data(), static_cast<int>(*key_size)) != 1)
    {
        return ::score::crypto::make_unexpected(::score::crypto::daemon::common::DaemonErrorCode::kOperationFailed);
    }

    const auto handle =
        detail::MakeKeyHandle(provider_id, request.algorithm, request.permissions, *key_size, false, key_bytes.data());

    return std::make_shared<OpenSslKeyHandler>(std::move(key_bytes), handle);
}

::score::crypto::Expected<key_management::IKeyHandler::Sptr, ::score::crypto::daemon::common::DaemonErrorCode>
ImportSymmetricKey(common::ProviderId provider_id, const key_management::KeyImportRequest& request)
{
    std::vector<std::uint8_t> key_bytes(request.key_data, request.key_data + request.key_data_size);
    const CleanseOnExit cleanse{key_bytes};

    const auto handle = detail::MakeKeyHandle(
        provider_id, request.algorithm, request.permissions, request.key_data_size, false, key_bytes.data());

    return std::make_shared<OpenSslKeyHandler>(std::move(key_bytes), handle);
}

}  // namespace score::crypto::daemon::provider::openssl
