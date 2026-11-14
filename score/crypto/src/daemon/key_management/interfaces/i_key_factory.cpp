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

#include "score/crypto/src/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/src/daemon/key_management/interfaces/i_key_slot_handler.hpp"

#include "score/crypto/src/daemon/common/algorithm_info.hpp"
#include "score/crypto/src/daemon/common/daemon_error.hpp"

namespace score::crypto::daemon::key_management
{

score::crypto::Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode> IKeyFactory::GenerateKey(
    const KeyGenerationRequest& /*request*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode> IKeyFactory::ImportKey(
    const KeyImportRequest& /*request*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode> IKeyFactory::DeriveKey(
    const KeyDeriveRequest& /*request*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode> IKeyFactory::AgreeKey(
    const KeyAgreeRequest& /*request*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<SecureKeyBytes, score::crypto::daemon::common::DaemonErrorCode> IKeyFactory::WrapKey(
    const WrapKeyRequest& /*request*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<std::size_t, score::crypto::daemon::common::DaemonErrorCode> IKeyFactory::GetWrapKeySize(
    const WrapKeyRequest& /*request*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<IKeyHandler::Sptr, score::crypto::daemon::common::DaemonErrorCode> IKeyFactory::UnwrapKey(
    const UnwrapKeyRequest& /*request*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<SecureKeyBytes, score::crypto::daemon::common::DaemonErrorCode> IKeyFactory::ExportKey(
    const ProviderKeyHandle& /*handle*/,
    score::crypto::FormatType /*format*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<std::size_t, score::crypto::daemon::common::DaemonErrorCode> IKeyFactory::GetExportKeySize(
    const ProviderKeyHandle& /*handle*/,
    score::crypto::FormatType /*format*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode> IKeyFactory::GenerateKeyToSlot(
    const KeySlotConfig& slot,
    const KeyGenerationRequest& request,
    IKeySlotHandler& slot_handler)
{
    auto handler_result = GenerateKey(request);
    if (!handler_result.has_value())
    {
        return score::crypto::make_unexpected(handler_result.error());
    }
    return slot_handler.StoreKey(slot, *handler_result.value());
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
IKeyFactory::ImportKeyToSlot(const KeySlotConfig& slot, const KeyImportRequest& request, IKeySlotHandler& slot_handler)
{
    auto handler_result = ImportKey(request);
    if (!handler_result.has_value())
    {
        return score::crypto::make_unexpected(handler_result.error());
    }
    return slot_handler.StoreKey(slot, *handler_result.value());
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
IKeyFactory::DeriveKeyToSlot(const KeySlotConfig& slot, const KeyDeriveRequest& request, IKeySlotHandler& slot_handler)
{
    auto handler_result = DeriveKey(request);
    if (!handler_result.has_value())
    {
        return score::crypto::make_unexpected(handler_result.error());
    }
    return slot_handler.StoreKey(slot, *handler_result.value());
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
IKeyFactory::AgreeKeyToSlot(const KeySlotConfig& slot, const KeyAgreeRequest& request, IKeySlotHandler& slot_handler)
{
    auto handler_result = AgreeKey(request);
    if (!handler_result.has_value())
    {
        return score::crypto::make_unexpected(handler_result.error());
    }
    return slot_handler.StoreKey(slot, *handler_result.value());
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
IKeyFactory::UnwrapKeyToSlot(const KeySlotConfig& slot, const UnwrapKeyRequest& request, IKeySlotHandler& slot_handler)
{
    auto handler_result = UnwrapKey(request);
    if (!handler_result.has_value())
    {
        return score::crypto::make_unexpected(handler_result.error());
    }
    return slot_handler.StoreKey(slot, *handler_result.value());
}

score::crypto::Expected<std::monostate, score::crypto::daemon::common::DaemonErrorCode>
IKeyFactory::ValidateSymmetricImport(const KeyImportRequest& request) noexcept
{
    using score::crypto::daemon::common::DaemonErrorCode;

    const auto& algorithm = request.algorithm;
    const bool is_symmetric_key = ((algorithm.key_type == ::score::crypto::KeyType::kAes) ||
                                   (algorithm.key_type == ::score::crypto::KeyType::kSecret)) &&
                                  ::score::crypto::daemon::common::LookupKeySize(algorithm).has_value();
    if (!is_symmetric_key)
    {
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidArgument);
    }

    // Symmetric keys have no DER or PEM encoding: raw bytes are their native
    // format, so only no format or an explicit kRaw is accepted.
    if (request.format.has_value() && (request.format.value() != score::crypto::FormatType::kRaw))
    {
        return score::crypto::make_unexpected(DaemonErrorCode::kInvalidFormat);
    }

    if (algorithm.key_type == ::score::crypto::KeyType::kAes)
    {
        if (request.key_data_size != ::score::crypto::daemon::common::LookupKeySize(algorithm).value_or(0U))
        {
            return score::crypto::make_unexpected(DaemonErrorCode::kIncompatibleKeyType);
        }
        return std::monostate{};
    }

    // An HMAC key shorter than the digest caps the MAC's security strength below
    // that of its hash (NIST SP 800-107r1), so the digest length is the floor.
    // Longer keys are valid: HMAC hashes keys longer than one block.
    const auto digest_size = ::score::crypto::daemon::common::LookupDigestSize(algorithm.hash);
    if (!digest_size.has_value() || (request.key_data_size < digest_size.value()))
    {
        return score::crypto::make_unexpected(DaemonErrorCode::kIncompatibleKeyType);
    }
    return std::monostate{};
}

}  // namespace score::crypto::daemon::key_management
