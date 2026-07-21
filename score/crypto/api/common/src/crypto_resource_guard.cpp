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

#include "score/mw/crypto/api/common/crypto_resource_guard.hpp"
#include "score/mw/crypto/api/common/error_domain.hpp"
#include "score/mw/crypto/api/common/src/i_release_callback.hpp"

#include <cassert>
#include <utility>
namespace score
{
namespace mw
{
namespace crypto
{
CryptoResourceGuard::CryptoResourceGuard(std::shared_ptr<void> release_handle, CryptoResourceId id) noexcept
    : release_handle_{std::move(release_handle)}, id_{id}, active_{true}
{
}

CryptoResourceGuard::~CryptoResourceGuard() noexcept
{
    if (active_ && release_handle_)
    {
        // static_cast is safe: release_handle_ is always constructed from
        // shared_ptr<IReleaseCallback> via implicit conversion in MakeGuard.
        // Silently swallow errors — destructors must not propagate.
        auto* cb = static_cast<IReleaseCallback*>(release_handle_.get());
        static_cast<void>(cb->ReleaseResource(id_));
    }
}

CryptoResourceGuard::CryptoResourceGuard(CryptoResourceGuard&& other) noexcept
    : release_handle_{std::move(other.release_handle_)}, id_{other.id_}, active_{other.active_}
{
    other.active_ = false;
}

CryptoResourceGuard& CryptoResourceGuard::operator=(CryptoResourceGuard&& other) noexcept
{
    if (this != &other)
    {
        if (active_ && release_handle_)
        {
            auto* cb = static_cast<IReleaseCallback*>(release_handle_.get());
            static_cast<void>(cb->ReleaseResource(id_));
        }
        release_handle_ = std::move(other.release_handle_);
        id_ = other.id_;
        active_ = other.active_;
        other.active_ = false;
    }
    return *this;
}

const CryptoResourceId& CryptoResourceGuard::Id() const noexcept
{
    assert(active_ &&
           "CryptoResourceGuard::Id() called on an inactive guard "
           "(moved-from, Released, or default-constructed)");
    return id_;
}

CryptoResourceGuard::operator const CryptoResourceId&() const noexcept
{
    assert(active_ && "CryptoResourceGuard implicit conversion called on an inactive guard");
    return id_;
}

bool CryptoResourceGuard::IsActive() const noexcept
{
    return active_;
}

score::Result<std::monostate> CryptoResourceGuard::Release() noexcept
{
    if (!active_ || !release_handle_)
    {
        return score::Result<std::monostate>{
            score::unexpect, MakeError(CryptoErrorCode::kInvalidResourceId, "Release() called on an inactive guard")};
    }
    auto* cb = static_cast<IReleaseCallback*>(release_handle_.get());
    auto result = cb->ReleaseResource(id_);
    if (result.has_value())
    {
        active_ = false;          // guard no longer owns the resource
        release_handle_.reset();  // destructor will be a no-op
    }
    return result;
}

}  // namespace crypto
}  // namespace mw
}  // namespace score
