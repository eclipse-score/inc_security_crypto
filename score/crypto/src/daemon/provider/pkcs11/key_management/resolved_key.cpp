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

#include "score/crypto/src/daemon/provider/pkcs11/key_management/resolved_key.hpp"

#include "score/crypto/src/common/types.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

#include <pkcs11.h>

#include <atomic>
#include <memory>
#include <utility>

namespace score::crypto::daemon::provider::pkcs11
{

// NOLINTNEXTLINE(bugprone-easily-swappable-parameters)
ResolvedKey::ResolvedKey(CK_SESSION_HANDLE session,
                         CK_OBJECT_HANDLE object,
                         std::shared_ptr<std::atomic_flag> flag) noexcept
    : m_session{session}, m_object{object}, m_flag{std::move(flag)}
{
}

score::crypto::Expected<ResolvedKey, score::crypto::daemon::common::DaemonErrorCode> ResolvedKey::Acquire(
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE object,
    std::shared_ptr<std::atomic_flag> flag) noexcept
{
    // test_and_set returns the old value: true means already held by another handler.
    if (flag->test_and_set(std::memory_order_acquire))
    {
        return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kResourceBusy);
    }
    return ResolvedKey{session, object, std::move(flag)};
}

score::crypto::Expected<ResolvedKey, score::crypto::daemon::common::DaemonErrorCode> ResolvedKey::ForToken(
    CK_SESSION_HANDLE session,
    CK_OBJECT_HANDLE object) noexcept
{
    return ResolvedKey{session, object, nullptr};
}

ResolvedKey::~ResolvedKey() noexcept
{
    if (m_flag)
    {
        m_flag->clear(std::memory_order_release);
    }
}

ResolvedKey::ResolvedKey(ResolvedKey&& other) noexcept
    : m_session{other.m_session}, m_object{other.m_object}, m_flag{std::move(other.m_flag)}
{
    other.m_session = CK_INVALID_HANDLE;
    other.m_object = CK_INVALID_HANDLE;
}

ResolvedKey& ResolvedKey::operator=(ResolvedKey&& other) noexcept
{
    if (this != &other)
    {
        if (m_flag)
        {
            m_flag->clear(std::memory_order_release);
        }
        m_session = other.m_session;
        m_object = other.m_object;
        m_flag = std::move(other.m_flag);
        other.m_session = CK_INVALID_HANDLE;
        other.m_object = CK_INVALID_HANDLE;
    }
    return *this;
}

[[nodiscard]] CK_SESSION_HANDLE ResolvedKey::session() const noexcept
{
    return m_session;
}

[[nodiscard]] CK_OBJECT_HANDLE ResolvedKey::object() const noexcept
{
    return m_object;
}

}  // namespace score::crypto::daemon::provider::pkcs11
