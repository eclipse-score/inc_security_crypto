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

#include "score/crypto/daemon/key_management/interfaces/i_key_factory.hpp"
#include "score/crypto/daemon/key_management/interfaces/i_key_slot_handler.hpp"

#include "score/crypto/daemon/common/daemon_error.hpp"

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
    score::mw::crypto::FormatType /*format*/)
{
    return score::crypto::make_unexpected(score::crypto::daemon::common::DaemonErrorCode::kUnsupportedOperation);
}

score::crypto::Expected<std::size_t, score::crypto::daemon::common::DaemonErrorCode> IKeyFactory::GetExportKeySize(
    const ProviderKeyHandle& /*handle*/,
    score::mw::crypto::FormatType /*format*/)
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

}  // namespace score::crypto::daemon::key_management
