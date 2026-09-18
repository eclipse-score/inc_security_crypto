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

#include "score/crypto/src/daemon/provider/pkcs11/cert_management/pkcs11_cert_slot_handler.hpp"

#include "score/crypto/src/daemon/cert_management/interfaces/cert_types.hpp"
#include "score/crypto/src/daemon/cert_management/slot/crl_handler.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_loader.hpp"
#include "score/crypto/src/daemon/cert_management/slot/deployment_writer.hpp"
#include "score/crypto/src/daemon/common/storage/file_io.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/detail/pkcs11_algorithm_info.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_module.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_provider.hpp"
#include "score/crypto/src/daemon/provider/pkcs11/pkcs11_session_guard.hpp"

#include <algorithm>
#include <string>
#include <vector>

namespace score::crypto::daemon::provider::pkcs11
{
namespace daemon_cert_management = ::score::crypto::daemon::cert_management;

namespace
{
using Error = common::DaemonErrorCode;
using daemon_cert_management::cert_deployment_keys::kPkcs11Label;
using daemon_cert_management::cert_deployment_keys::kPkcs11ObjectId;
using daemon_cert_management::cert_section_names::kCertificate;
using daemon_cert_management::cert_section_names::kCertificateMetadata;
using daemon_cert_management::cert_section_names::kCrl;
namespace cert_keys = daemon_cert_management::cert_deployment_keys;
namespace file_io = ::score::crypto::daemon::common::storage;

constexpr CK_OBJECT_CLASS kCertificateClass = CKO_CERTIFICATE;
constexpr CK_CERTIFICATE_TYPE kX509CertificateType = CKC_X_509;

struct SessionRelease
{
    std::shared_ptr<Pkcs11Provider> provider;
    CK_SESSION_HANDLE session{CK_INVALID_HANDLE};
    ~SessionRelease()
    {
        if (provider && session != CK_INVALID_HANDLE)
        {
            provider->ReleaseSession(session, {Pkcs11SessionType::ReadOnly, Pkcs11TokenAuthState::Public});
        }
    }
};

/// Locate a CKO_CERTIFICATE object on an already-open session.
/// Returns CK_INVALID_HANDLE (not an error) when count==0.
score::crypto::Expected<CK_OBJECT_HANDLE, Error> FindCertOnSession(CK_SESSION_HANDLE session,
                                                                   CK_FUNCTION_LIST* functions,
                                                                   const std::string& label,
                                                                   const std::vector<uint8_t>& id_bytes)
{
    std::vector<CK_ATTRIBUTE> find_attrs;
    find_attrs.push_back({CKA_CLASS, const_cast<CK_OBJECT_CLASS*>(&kCertificateClass), sizeof(kCertificateClass)});
    find_attrs.push_back(
        {CKA_CERTIFICATE_TYPE, const_cast<CK_CERTIFICATE_TYPE*>(&kX509CertificateType), sizeof(kX509CertificateType)});
    std::string label_copy{label};
    if (!label_copy.empty())
        find_attrs.push_back(
            {CKA_LABEL, const_cast<char*>(label_copy.data()), static_cast<CK_ULONG>(label_copy.size())});
    std::vector<uint8_t> id_copy{id_bytes};
    if (!id_copy.empty())
        find_attrs.push_back({CKA_ID, id_copy.data(), static_cast<CK_ULONG>(id_copy.size())});

    const CK_RV rv_init =
        functions->C_FindObjectsInit(session, find_attrs.data(), static_cast<CK_ULONG>(find_attrs.size()));
    if (rv_init != CKR_OK)
        return score::crypto::make_unexpected(Error::kResourceNotAllocated);

    CK_OBJECT_HANDLE found = CK_INVALID_HANDLE;
    CK_ULONG count = 0U;
    functions->C_FindObjects(session, &found, 1U, &count);
    functions->C_FindObjectsFinal(session);
    return (count == 1U) ? found : CK_INVALID_HANDLE;
}

}  // namespace

Pkcs11CertSlotHandler::Pkcs11CertSlotHandler(std::shared_ptr<Pkcs11Provider> provider,
                                             std::weak_ptr<Pkcs11Module> module,
                                             provider::cert_management::ICertParser::Sptr parser)
    : m_provider{std::move(provider)}, m_module{std::move(module)}, m_parser{std::move(parser)}
{
}

score::crypto::Expected<Pkcs11CertSlotHandler::LocatedCertificate, Error> Pkcs11CertSlotHandler::Locate(
    const daemon_cert_management::CertSlotConfig& slot)
{
    if (!m_provider)
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    const auto descriptor =
        daemon_cert_management::DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!descriptor)
        return score::crypto::make_unexpected(descriptor.error());

    const std::string& label = descriptor->Get(std::string{kCertificate}, std::string{kPkcs11Label});
    const std::string& object_id = descriptor->Get(std::string{kCertificate}, std::string{kPkcs11ObjectId});
    if (label.empty() && object_id.empty())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    const Pkcs11HandlerRequirements requirements{Pkcs11SessionType::ReadOnly, Pkcs11TokenAuthState::Public};
    const auto session = m_provider->AcquireSession(requirements);
    if (!session)
        return score::crypto::make_unexpected(Error::kProviderBusy);
    SessionRelease release{m_provider, *session};

    const auto module = m_module.lock();
    if (!module || module->GetFunctionList() == nullptr)
        return score::crypto::make_unexpected(Error::kInternalError);
    CK_FUNCTION_LIST* functions = module->GetFunctionList();

    std::vector<CK_ATTRIBUTE> template_attributes;
    template_attributes.push_back(
        {CKA_CLASS, const_cast<CK_OBJECT_CLASS*>(&kCertificateClass), sizeof(kCertificateClass)});
    template_attributes.push_back(
        {CKA_CERTIFICATE_TYPE, const_cast<CK_CERTIFICATE_TYPE*>(&kX509CertificateType), sizeof(kX509CertificateType)});

    std::string label_copy{label};
    if (!label_copy.empty())
    {
        template_attributes.push_back(
            {CKA_LABEL, const_cast<char*>(label_copy.data()), static_cast<CK_ULONG>(label_copy.size())});
    }

    std::vector<std::uint8_t> id_bytes;
    if (!object_id.empty())
    {
        id_bytes = detail::HexDecode(object_id);
        if (id_bytes.empty())
            return score::crypto::make_unexpected(Error::kInvalidArgument);
        template_attributes.push_back({CKA_ID, id_bytes.data(), static_cast<CK_ULONG>(id_bytes.size())});
    }

    CK_RV result = functions->C_FindObjectsInit(
        *session, template_attributes.data(), static_cast<CK_ULONG>(template_attributes.size()));
    if (result != CKR_OK)
        return score::crypto::make_unexpected(Error::kResourceNotAllocated);

    CK_OBJECT_HANDLE objects[2U] = {CK_INVALID_HANDLE, CK_INVALID_HANDLE};
    CK_ULONG count = 0U;
    result = functions->C_FindObjects(*session, objects, 2U, &count);
    const CK_RV final_result = functions->C_FindObjectsFinal(*session);
    if (result != CKR_OK || final_result != CKR_OK || count != 1U || objects[0] == CK_INVALID_HANDLE)
        return score::crypto::make_unexpected(Error::kResourceNotAllocated);

    release.provider.reset();
    return LocatedCertificate{*session, objects[0]};
}

score::crypto::Expected<daemon_cert_management::CertObject::Sptr, Error> Pkcs11CertSlotHandler::LoadCertificate(
    const daemon_cert_management::CertSlotConfig& slot)
{
    if (!m_parser)
        return score::crypto::make_unexpected(Error::kProviderNotAvailable);

    auto located = Locate(slot);
    if (!located)
        return score::crypto::make_unexpected(located.error());
    SessionRelease release{m_provider, located->session};

    const auto module = m_module.lock();
    if (!module || module->GetFunctionList() == nullptr)
        return score::crypto::make_unexpected(Error::kInternalError);
    CK_FUNCTION_LIST* functions = module->GetFunctionList();

    CK_ULONG value_size = 0U;
    CK_ATTRIBUTE value_attribute{CKA_VALUE, nullptr, 0U};
    if (functions->C_GetAttributeValue(located->session, located->object, &value_attribute, 1U) != CKR_OK ||
        value_attribute.ulValueLen == CK_UNAVAILABLE_INFORMATION || value_attribute.ulValueLen == 0U)
    {
        return score::crypto::make_unexpected(Error::kCertificateParsingFailed);
    }
    value_size = value_attribute.ulValueLen;
    std::vector<std::uint8_t> value(value_size);
    value_attribute.pValue = value.data();
    if (functions->C_GetAttributeValue(located->session, located->object, &value_attribute, 1U) != CKR_OK)
        return score::crypto::make_unexpected(Error::kCertificateParsingFailed);

    return m_parser->ParseCertificate(value.data(), value.size(), score::crypto::FormatType::kDer);
}

score::crypto::Expected<std::monostate, Error> Pkcs11CertSlotHandler::StoreCertificate(
    const daemon_cert_management::CertSlotConfig& slot,
    const daemon_cert_management::CertObject& cert)
{
    if (!m_provider)
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    // PKCS#11 CKA_VALUE requires DER-encoded certificate bytes.
    if (cert.GetFormat() != score::crypto::FormatType::kDer)
        return score::crypto::make_unexpected(Error::kUnsupportedOperation);

    const auto descriptor_result =
        daemon_cert_management::DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!descriptor_result)
        return score::crypto::make_unexpected(descriptor_result.error());
    auto descriptor = *descriptor_result;

    const std::string& label = descriptor.Get(std::string{kCertificate}, std::string{kPkcs11Label});
    const std::string& object_id_hex = descriptor.Get(std::string{kCertificate}, std::string{kPkcs11ObjectId});
    if (label.empty() && object_id_hex.empty())
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    std::vector<uint8_t> id_bytes;
    if (!object_id_hex.empty())
        id_bytes = detail::HexDecode(object_id_hex);

    const Pkcs11HandlerRequirements rw_reqs{Pkcs11SessionType::ReadWrite, Pkcs11TokenAuthState::User};
    Pkcs11SessionGuard guard(*m_provider, rw_reqs);
    if (!guard)
        return score::crypto::make_unexpected(Error::kProviderBusy);

    const auto module = m_module.lock();
    if (!module || module->GetFunctionList() == nullptr)
        return score::crypto::make_unexpected(Error::kInternalError);
    CK_FUNCTION_LIST* functions = module->GetFunctionList();

    // Destroy any pre-existing cert object so C_CreateObject doesn't duplicate it.
    const auto existing = FindCertOnSession(guard.get(), functions, label, id_bytes);
    if (existing && *existing != CK_INVALID_HANDLE)
        static_cast<void>(functions->C_DestroyObject(guard.get(), *existing));

    // Create new persistent certificate object on the token.
    const auto& raw = cert.GetRawBytes();
    CK_BBOOL ck_true = CK_TRUE;
    // MISRA C++:2023 Rule 8.2.3 deviation — PKCS#11 C API requires non-const pValue.
    // NOLINTNEXTLINE(cppcoreguidelines-pro-type-const-cast)
    CK_BYTE_PTR value_ptr = const_cast<CK_BYTE_PTR>(static_cast<const CK_BYTE*>(raw.data()));
    std::string label_copy{label};

    std::vector<CK_ATTRIBUTE> attrs;
    attrs.push_back({CKA_CLASS, const_cast<CK_OBJECT_CLASS*>(&kCertificateClass), sizeof(kCertificateClass)});
    attrs.push_back(
        {CKA_CERTIFICATE_TYPE, const_cast<CK_CERTIFICATE_TYPE*>(&kX509CertificateType), sizeof(kX509CertificateType)});
    attrs.push_back({CKA_TOKEN, &ck_true, sizeof(CK_BBOOL)});
    attrs.push_back({CKA_VALUE, value_ptr, static_cast<CK_ULONG>(raw.size())});
    if (!label_copy.empty())
        attrs.push_back({CKA_LABEL, const_cast<char*>(label_copy.data()), static_cast<CK_ULONG>(label_copy.size())});
    if (!id_bytes.empty())
        attrs.push_back({CKA_ID, id_bytes.data(), static_cast<CK_ULONG>(id_bytes.size())});

    CK_OBJECT_HANDLE new_obj = CK_INVALID_HANDLE;
    if (functions->C_CreateObject(guard.get(), attrs.data(), static_cast<CK_ULONG>(attrs.size()), &new_obj) != CKR_OK)
        return score::crypto::make_unexpected(Error::kPersistFailed);

    // Stale CRL invalidation: clear [crl] except crl_path (preserve for future StoreCrl).
    // Metadata is cleared unconditionally so the descriptor never reports a stale
    // CRL as current, even if the physical file removal below fails.
    const auto old_crl_path = descriptor.Get(std::string{kCrl}, std::string{cert_keys::kCrlPath});
    descriptor.RemoveSection(std::string{kCrl});
    if (!old_crl_path.empty())
    {
        descriptor.Set(std::string{kCrl}, std::string{cert_keys::kCrlPath}, old_crl_path);
        static_cast<void>(file_io::RemoveFile(old_crl_path));
    }

    // Update cached certificate metadata.
    descriptor.Set(std::string{kCertificateMetadata}, std::string{cert_keys::kSubject}, std::string(cert.GetSubject()));
    descriptor.Set(std::string{kCertificateMetadata}, std::string{cert_keys::kIssuer}, std::string(cert.GetIssuer()));
    descriptor.Set(
        std::string{kCertificateMetadata}, std::string{cert_keys::kNotBefore}, std::to_string(cert.GetNotBefore()));
    descriptor.Set(
        std::string{kCertificateMetadata}, std::string{cert_keys::kNotAfter}, std::to_string(cert.GetNotAfter()));
    descriptor.Set(std::string{kCertificateMetadata}, std::string{cert_keys::kIsCA}, cert.IsCA() ? "true" : "false");

    return daemon_cert_management::DeploymentWriter::Write(slot.deployment_path, slot.deployment_format, descriptor);
}

score::crypto::Expected<std::monostate, Error> Pkcs11CertSlotHandler::ClearSlot(
    const daemon_cert_management::CertSlotConfig& slot)
{
    if (!m_provider)
        return score::crypto::make_unexpected(Error::kInvalidArgument);

    const auto descriptor_result =
        daemon_cert_management::DeploymentLoader::Load(slot.deployment_path, slot.deployment_format);
    if (!descriptor_result)
        return score::crypto::make_unexpected(descriptor_result.error());
    auto descriptor = *descriptor_result;

    const std::string& label = descriptor.Get(std::string{kCertificate}, std::string{kPkcs11Label});
    const std::string& object_id_hex = descriptor.Get(std::string{kCertificate}, std::string{kPkcs11ObjectId});

    std::vector<uint8_t> id_bytes;
    if (!object_id_hex.empty())
        id_bytes = detail::HexDecode(object_id_hex);

    if (!label.empty() || !id_bytes.empty())
    {
        // Locate and destroy the token certificate object.
        const Pkcs11HandlerRequirements rw_reqs{Pkcs11SessionType::ReadWrite, Pkcs11TokenAuthState::User};
        Pkcs11SessionGuard guard(*m_provider, rw_reqs);
        if (!guard)
            return score::crypto::make_unexpected(Error::kProviderBusy);

        const auto module = m_module.lock();
        if (!module || module->GetFunctionList() == nullptr)
            return score::crypto::make_unexpected(Error::kInternalError);
        CK_FUNCTION_LIST* functions = module->GetFunctionList();

        const auto found = FindCertOnSession(guard.get(), functions, label, id_bytes);
        if (found && *found != CK_INVALID_HANDLE)
        {
            const CK_RV rv = functions->C_DestroyObject(guard.get(), *found);
            if (rv != CKR_OK)
                return score::crypto::make_unexpected(Error::kPersistFailed);
        }
    }

    // CRL cleanup: remove file and clear [crl] section, preserving crl_path.
    const auto crl_path = descriptor.Get(std::string{kCrl}, std::string{cert_keys::kCrlPath});
    if (!crl_path.empty())
    {
        if (const auto rm = file_io::RemoveFile(crl_path); !rm)
            return rm;
    }
    descriptor.RemoveSection(std::string{kCrl});
    if (!crl_path.empty())
        descriptor.Set(std::string{kCrl}, std::string{cert_keys::kCrlPath}, crl_path);
    descriptor.RemoveSection(std::string{kCertificateMetadata});

    return daemon_cert_management::DeploymentWriter::Write(slot.deployment_path, slot.deployment_format, descriptor);
}

score::crypto::Expected<score::crypto::CertificateSlotState, Error> Pkcs11CertSlotHandler::GetSlotState(
    const daemon_cert_management::CertSlotConfig& slot)
{
    auto located = Locate(slot);
    if (!located)
        return score::crypto::CertificateSlotState::kEmpty;
    SessionRelease release{m_provider, located->session};
    return score::crypto::CertificateSlotState::kOccupied;
}

score::crypto::Expected<score::crypto::CertificateSlotInfo, Error> Pkcs11CertSlotHandler::GetSlotInfo(
    const daemon_cert_management::CertSlotConfig& slot)
{
    auto state = GetSlotState(slot);
    if (!state)
        return score::crypto::make_unexpected(state.error());
    score::crypto::CertificateSlotInfo info{};
    info.state = *state;
    const auto has_crl = m_crl.HasCrl(slot);
    if (!has_crl)
        return score::crypto::make_unexpected(has_crl.error());
    info.has_crl = has_crl.value();
    return info;
}

score::crypto::Expected<bool, Error> Pkcs11CertSlotHandler::HasCrl(const daemon_cert_management::CertSlotConfig& slot)
{
    const auto has_crl = m_crl.HasCrl(slot);
    if (!has_crl)
        return score::crypto::make_unexpected(has_crl.error());
    return has_crl.value();
}

score::crypto::Expected<std::vector<uint8_t>, Error> Pkcs11CertSlotHandler::LoadCrl(
    const daemon_cert_management::CertSlotConfig& slot)
{
    return m_crl.LoadCrl(slot);
}

score::crypto::Expected<std::monostate, Error> Pkcs11CertSlotHandler::StoreCrl(
    const daemon_cert_management::CertSlotConfig& slot,
    score::crypto::span<const uint8_t> data,
    score::crypto::FormatType format,
    std::optional<score::crypto::CrlMetadata> metadata)
{
    return m_crl.StoreCrl(slot, data, format, std::move(metadata));
}

score::crypto::Expected<std::monostate, Error> Pkcs11CertSlotHandler::ClearCrl(
    const daemon_cert_management::CertSlotConfig& slot)
{
    return m_crl.ClearCrl(slot);
}

score::crypto::Expected<int64_t, Error> Pkcs11CertSlotHandler::GetCrlNextUpdate(
    const daemon_cert_management::CertSlotConfig& slot)
{
    return m_crl.GetCrlNextUpdate(slot);
}

score::crypto::FormatType Pkcs11CertSlotHandler::GetCrlFormat(const daemon_cert_management::CertSlotConfig& slot)
{
    return m_crl.GetCrlFormat(slot);
}

std::optional<score::crypto::CrlMetadata> Pkcs11CertSlotHandler::GetCrlMetadata(
    const daemon_cert_management::CertSlotConfig& slot)
{
    if (const auto metadata = m_crl.GetCrlMetadata(slot); metadata.has_value())
        return metadata;
    const auto has_crl = m_crl.HasCrl(slot);
    if (!m_parser || !has_crl || !has_crl.value())
        return std::nullopt;

    const auto certificate = LoadCertificate(slot);
    const auto crl = m_crl.LoadCrl(slot);
    if (!certificate.has_value() || !crl.has_value())
        return std::nullopt;

    const auto result = m_parser->ValidateCrl(crl->data(),
                                              crl->size(),
                                              m_crl.GetCrlFormat(slot),
                                              certificate.value()->GetRawBytes().data(),
                                              certificate.value()->GetRawBytes().size(),
                                              certificate.value()->GetFormat());
    return result.has_value() ? std::optional<score::crypto::CrlMetadata>{result.value()} : std::nullopt;
}

}  // namespace score::crypto::daemon::provider::pkcs11
