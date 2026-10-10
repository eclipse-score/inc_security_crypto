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

#include "score/crypto/src/daemon/cert_management/slot/slot_handler_factory.hpp"

#include "score/crypto/src/daemon/cert_management/slot/file_backed_slot_handler.hpp"
#include "score/crypto/src/daemon/provider/i_provider.hpp"
#include "score/mw/log/logging.h"

#include <string_view>
#include <utility>

namespace score::crypto::daemon::cert_management
{
namespace
{
constexpr std::string_view kLogPrefix{"[CertMgmt] "};
}

score::crypto::Expected<provider::cert_management::ICertParser::Sptr, common::DaemonErrorCode>
SlotHandlerFactory::ResolveCertParser() const
{
    if (m_parser_cache->resolved.load(std::memory_order_acquire))
    {
        return m_parser_cache->parser;
    }

    std::lock_guard<std::mutex> lock(m_parser_cache->mutex);
    if (m_parser_cache->resolved.load(std::memory_order_relaxed))
    {
        return m_parser_cache->parser;
    }

    const bool parser_provider_is_pinned = !m_parser_provider_name.empty();
    if (!m_provider_manager)
    {
        if (parser_provider_is_pinned)
        {
            score::mw::log::LogError() << kLogPrefix << "Configured certificate parser provider '"
                                       << m_parser_provider_name << "' cannot be resolved without a provider manager.";
            return score::crypto::make_unexpected(common::DaemonErrorCode::kProviderNotAvailable);
        }
        score::mw::log::LogWarn() << kLogPrefix << "No provider manager is available for certificate parsing.";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
    }

    auto parser_provider =
        parser_provider_is_pinned
            ? m_provider_manager->GetProvider(m_parser_provider_name)
            : m_provider_manager->GetProviderForCapability(common::ProviderCapability::kCertManagement);
    if (!parser_provider)
    {
        if (parser_provider_is_pinned)
        {
            score::mw::log::LogError() << kLogPrefix << "Configured certificate parser provider '"
                                       << m_parser_provider_name << "' is unavailable.";
            return score::crypto::make_unexpected(common::DaemonErrorCode::kProviderNotAvailable);
        }
        score::mw::log::LogWarn() << kLogPrefix
                                  << "No provider with kCertManagement capability is available; "
                                     "certificate parsing remains unavailable.";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
    }

    if (!common::HasCapability(parser_provider->GetProviderCapabilities(), common::ProviderCapability::kCertManagement))
    {
        score::mw::log::LogError() << kLogPrefix << "Certificate parser provider '"
                                   << parser_provider->GetProviderName() << "' does not advertise kCertManagement.";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
    }

    auto parser = parser_provider->GetCertParser();
    if (!parser)
    {
        score::mw::log::LogError() << kLogPrefix << "Provider '" << parser_provider->GetProviderName()
                                   << "' advertises kCertManagement but returned no certificate parser.";
        return score::crypto::make_unexpected(common::DaemonErrorCode::kUnsupportedOperation);
    }

    m_parser_cache->parser = std::move(parser);
    m_parser_cache->resolved.store(true, std::memory_order_release);
    return m_parser_cache->parser;
}

score::crypto::Expected<std::monostate, common::DaemonErrorCode> SlotHandlerFactory::Initialize() const
{
    const auto parser_result = ResolveCertParser();
    if (!parser_result.has_value())
    {
        return score::crypto::make_unexpected(parser_result.error());
    }
    return std::monostate{};
}

ICertSlotHandler::Sptr SlotHandlerFactory::operator()(const CertSlotConfig& slot) const
{
    auto parser_result = ResolveCertParser();
    auto cert_parser = parser_result.has_value() ? parser_result.value() : nullptr;

    if (slot.storage_backend == "DEFAULT")
    {
        return std::make_shared<FileBackedSlotHandler>(std::move(cert_parser));
    }

    if (!m_provider_manager)
    {
        return nullptr;
    }

    auto provider = m_provider_manager->GetProvider(slot.storage_backend);
    if (!provider)
    {
        return nullptr;
    }
    return provider->GetCertSlotHandler(slot, std::move(cert_parser));
}

}  // namespace score::crypto::daemon::cert_management
