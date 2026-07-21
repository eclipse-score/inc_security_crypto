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

#ifndef SCORE_MW_CRYPTO_API_OBJECTS_I_PRIVATE_KEY_OBJECT_HPP
#define SCORE_MW_CRYPTO_API_OBJECTS_I_PRIVATE_KEY_OBJECT_HPP

#include "score/mw/crypto/api/common/crypto_resource_guard.hpp"
#include "score/mw/crypto/api/objects/i_key_object.hpp"
#include "score/result/result.h"

#include <memory>

namespace score
{
namespace mw
{
namespace crypto
{

/// @brief Typed view of private key material (asymmetric only).
///
/// Extends IKeyObject with the ability to derive the corresponding public key.
/// Obtained by down-casting an IKeyObject whose role is "private", or returned
/// directly from GenerateKey() when the algorithm is asymmetric (RSA, ECDH, ML-DSA, etc.).
///
/// The public key is logically derived from the private key (zero-copy in the daemon);
/// no separate generation is performed. Implementations construct the returned guard
/// using `CryptoResourceGuardFactory::Make()` with the daemon-provided public key ID.
class IPrivateKeyObject : public IKeyObject
{
  public:
    using Uptr = std::unique_ptr<IPrivateKeyObject>;

    ~IPrivateKeyObject() override = default;

    IPrivateKeyObject(const IPrivateKeyObject&) = delete;
    IPrivateKeyObject& operator=(const IPrivateKeyObject&) = delete;
    IPrivateKeyObject(IPrivateKeyObject&&) = default;
    IPrivateKeyObject& operator=(IPrivateKeyObject&&) = default;

    /// @brief Derives an ephemeral public key from this private key.
    ///
    /// The returned guard owns an ephemeral copy of the public key in the daemon.
    /// The public key is automatically cleaned up when the guard is destroyed (RAII).
    /// This is a lightweight operation; no key material is recomputed.
    ///
    /// @return CryptoResourceGuard wrapping the ephemeral public key.
    ///         Can be used in any API accepting CryptoResourceId via implicit conversion.
    /// @note The guard provides access to IPublicKeyObject via typed downcasting.
    ///       Implementations construct the returned guard via CryptoResourceGuardFactory::Make()
    ///       using the IPC layer's release callback.
    virtual score::Result<CryptoResourceGuard> GetPublicKey() const = 0;

  protected:
    IPrivateKeyObject() = default;
};

}  // namespace crypto
}  // namespace mw
}  // namespace score

#endif  // SCORE_MW_CRYPTO_API_OBJECTS_I_PRIVATE_KEY_OBJECT_HPP
