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

#ifndef SCORE_MW_CRYPTO_API_CONTEXTS_I_CONTEXT_HPP
#define SCORE_MW_CRYPTO_API_CONTEXTS_I_CONTEXT_HPP

#include "score/mw/crypto/api/common/error_domain.hpp"

#include <memory>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Root base interface for all crypto operation contexts.
///
/// Provides the common Uptr typedef and virtual destructor. All concrete
/// operation contexts (hash, encrypt, sign, etc.) ultimately derive from
/// this interface, either directly or via IStreamingContext /
/// IStreamingOutputContext.
class IContext
{
  public:
    using Uptr = std::unique_ptr<IContext>;

    virtual ~IContext() = default;

    IContext(const IContext&) = delete;
    IContext& operator=(const IContext&) = delete;
    IContext(IContext&&) = default;
    IContext& operator=(IContext&&) = default;

  protected:
    IContext() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_CONTEXTS_I_CONTEXT_HPP
