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
#include "score/mw/log/logging.h"

#include <string_view>
#include <utility>

namespace score::crypto::daemon::cert_management
{
namespace
{
constexpr std::string_view kLogPrefix{"[CertMgmt] "};
}

provider::cert_management::ICertParser::Sptr SlotHandlerFactory::ResolveCertParser(
    const provider::ProviderManager::Sptr& provider_manager) const
{
    {
        std::lock_guard<std::mutex> lock(m_cache->mutex);
        if (m_cache->parser)
        {
            return m_cache->parser;
        }
    }

    if (!provider_manager)
    {
        return nullptr;
    }

    auto cert_prov = provider_manager->GetProviderForCapability(common::ProviderCapability::kCertManagement);
    if (!cert_prov)
    {
        score::mw::log::LogWarn() << kLogPrefix << "No provider with kCertManagement capability registered."
                                  << " Certificate slot loads will fail.";
        return nullptr;
    }

    auto cert_parser = cert_prov->GetCertParser();
    if (!cert_parser)
    {
        score::mw::log::LogError() << kLogPrefix << "Provider '" << cert_prov->GetProviderName()
                                   << "' advertises kCertManagement but GetCertParser() returned null."
                                   << " Providers claiming kCertManagement must implement GetCertParser()."
                                   << " Certificate slot loads will fail until this is resolved.";
        return nullptr;
    }

    std::lock_guard<std::mutex> lock(m_cache->mutex);
    m_cache->parser = std::move(cert_parser);
    return m_cache->parser;
}

ICertSlotHandler::Sptr SlotHandlerFactory::operator()(const CertSlotConfig& slot) const
{
    auto provider_manager = m_provider_manager.lock();
    auto cert_parser = ResolveCertParser(provider_manager);

    if (slot.storage_backend == "DEFAULT")
    {
        return std::make_shared<FileBackedSlotHandler>(std::move(cert_parser));
    }

    if (!provider_manager)
    {
        return nullptr;
    }

    auto provider = provider_manager->GetProvider(slot.storage_backend);
    if (!provider)
    {
        return nullptr;
    }
    return provider->GetCertSlotHandler(slot, std::move(cert_parser));
}

}  // namespace score::crypto::daemon::cert_management
