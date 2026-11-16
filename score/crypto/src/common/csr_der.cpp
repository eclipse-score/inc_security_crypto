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

#include "score/crypto/src/common/csr_der.hpp"

#include "score/crypto/src/api/common/error_domain.hpp"
#include "score/crypto/src/daemon/provider/handler/operations/csr_handler_operations.hpp"

#include <openssl/asn1t.h>
#include <openssl/x509v3.h>

#include <algorithm>
#include <array>
#include <limits>
#include <memory>
#include <utility>

namespace score::crypto::csr::der
{
namespace
{
namespace bounds = daemon::provider::handler::csr_handler_operations;
using View = score::cpp::span<const std::uint8_t>;
constexpr std::size_t kMaxTemplateBytes = 65536U;
constexpr std::size_t kMaxDepth = 16U;
constexpr std::size_t kMaxTemplateIdBytes = 128U;
constexpr std::size_t kMaxResourceBytes = 64U;
constexpr std::size_t kMaxAlgorithmBytes = 64U;

// Only these two fields travel to the signing provider. In particular, this
// type is NOT X509_REQ_INFO and cannot carry a key, version or algorithm.
struct Parameters
{
    X509_NAME* subject;
    STACK_OF(X509_ATTRIBUTE) * attributes;
};
ASN1_SEQUENCE(Parameters) = {ASN1_SIMPLE(Parameters, subject, X509_NAME),
                             ASN1_SET_OF(Parameters, attributes, X509_ATTRIBUTE)} ASN1_SEQUENCE_END(Parameters)
    IMPLEMENT_ASN1_FUNCTIONS(Parameters)

        struct TemplateEntry
{
    ASN1_OBJECT* oid;
    ASN1_UTF8STRING* value;
};
DEFINE_STACK_OF(TemplateEntry)
ASN1_SEQUENCE(TemplateEntry) = {ASN1_SIMPLE(TemplateEntry, oid, ASN1_OBJECT),
                                ASN1_SIMPLE(TemplateEntry, value, ASN1_UTF8STRING)} ASN1_SEQUENCE_END(TemplateEntry)
    IMPLEMENT_ASN1_ALLOC_FUNCTIONS(TemplateEntry)

        struct TemplateExtension
{
    ASN1_OBJECT* oid;
    ASN1_BOOLEAN critical;
    ASN1_UTF8STRING* value;
};
DEFINE_STACK_OF(TemplateExtension)
ASN1_SEQUENCE(TemplateExtension) = {ASN1_SIMPLE(TemplateExtension, oid, ASN1_OBJECT),
                                    // ASN1_FBOOLEAN omits the default FALSE, unlike an ordinary optional bool.
                                    ASN1_OPT(TemplateExtension, critical, ASN1_FBOOLEAN),
                                    ASN1_SIMPLE(TemplateExtension,
                                                value,
                                                ASN1_UTF8STRING)} ASN1_SEQUENCE_END(TemplateExtension)
    IMPLEMENT_ASN1_ALLOC_FUNCTIONS(TemplateExtension)

        struct StoredTemplate
{
    ASN1_INTEGER* version;
    ASN1_UTF8STRING* id;
    ASN1_UTF8STRING* key_resource;
    ASN1_UTF8STRING* algorithm;
    STACK_OF(TemplateEntry) * subject;
    STACK_OF(TemplateEntry) * issuer;
    STACK_OF(TemplateExtension) * extensions;
    ASN1_UTF8STRING* submission_url;
};
ASN1_SEQUENCE(StoredTemplate) = {ASN1_SIMPLE(StoredTemplate, version, ASN1_INTEGER),
                                 ASN1_SIMPLE(StoredTemplate, id, ASN1_UTF8STRING),
                                 ASN1_SIMPLE(StoredTemplate, key_resource, ASN1_UTF8STRING),
                                 ASN1_SIMPLE(StoredTemplate, algorithm, ASN1_UTF8STRING),
                                 ASN1_SEQUENCE_OF(StoredTemplate, subject, TemplateEntry),
                                 ASN1_SEQUENCE_OF(StoredTemplate, issuer, TemplateEntry),
                                 ASN1_SEQUENCE_OF(StoredTemplate, extensions, TemplateExtension),
                                 ASN1_SIMPLE(StoredTemplate,
                                             submission_url,
                                             ASN1_UTF8STRING)} ASN1_SEQUENCE_END(StoredTemplate)
    IMPLEMENT_ASN1_FUNCTIONS(StoredTemplate)

        template <typename T, void (*Free)(T*)>
        using Owned = std::unique_ptr<T, decltype(Free)>;
using RequestPtr = Owned<X509_REQ, X509_REQ_free>;
using NamePtr = Owned<X509_NAME, X509_NAME_free>;
using ObjectPtr = Owned<ASN1_OBJECT, ASN1_OBJECT_free>;
using AttributePtr = Owned<X509_ATTRIBUTE, X509_ATTRIBUTE_free>;
struct ExtensionsDeleter
{
    void operator()(STACK_OF(X509_EXTENSION) * value) const
    {
        sk_X509_EXTENSION_pop_free(value, X509_EXTENSION_free);
    }
};
using ExtensionsPtr = std::unique_ptr<STACK_OF(X509_EXTENSION), ExtensionsDeleter>;
struct BufferDeleter
{
    void operator()(unsigned char* value) const
    {
        OPENSSL_free(value);
    }
};

auto Invalid()
{
    return score::Unexpected{MakeError(CryptoErrorCode::kInvalidArgument, "Invalid CSR DER parameters")};
}
auto AllocationFailed()
{
    return score::Unexpected{MakeError(CryptoErrorCode::kAllocationFailed, "CSR DER allocation failed")};
}

bool ValidText(std::string_view value, std::size_t limit, bool allow_empty = false) noexcept
{
    if ((!allow_empty && value.empty()) || value.size() > limit)
    {
        return false;
    }
    for (std::size_t i = 0U; i < value.size();)
    {
        const auto first = static_cast<unsigned char>(value[i++]);
        if (first == 0U)
        {
            return false;
        }
        if (first < 0x80U)
        {
            continue;
        }
        unsigned remaining = 0U;
        std::uint32_t cp = 0U;
        std::uint32_t minimum = 0U;
        if (first >= 0xC2U && first <= 0xDFU)
        {
            remaining = 1U;
            cp = first & 0x1FU;
            minimum = 0x80U;
        }
        else if (first >= 0xE0U && first <= 0xEFU)
        {
            remaining = 2U;
            cp = first & 0x0FU;
            minimum = 0x800U;
        }
        else if (first >= 0xF0U && first <= 0xF4U)
        {
            remaining = 3U;
            cp = first & 0x07U;
            minimum = 0x10000U;
        }
        else
        {
            return false;
        }
        if (value.size() - i < remaining)
        {
            return false;
        }
        for (unsigned j = 0U; j < remaining; ++j)
        {
            const auto next = static_cast<unsigned char>(value[i++]);
            if ((next & 0xC0U) != 0x80U)
            {
                return false;
            }
            cp = (cp << 6U) | (next & 0x3FU);
        }
        if (cp < minimum || cp > 0x10FFFFU || (cp >= 0xD800U && cp <= 0xDFFFU))
        {
            return false;
        }
    }
    return true;
}

bool ValidOid(std::string_view oid)
{
    if (oid.size() < 3U || oid.size() > bounds::kMaxOidBytes || oid[1] != '.' || oid[0] < '0' || oid[0] > '2')
    {
        return false;
    }
    std::size_t start = 2U;
    bool second = true;
    while (start < oid.size())
    {
        auto end = oid.find('.', start);
        if (end == std::string_view::npos)
        {
            end = oid.size();
        }
        const auto arc = oid.substr(start, end - start);
        if (arc.empty() || (arc.size() > 1U && arc[0] == '0'))
        {
            return false;
        }
        for (char c : arc)
        {
            if (c < '0' || c > '9')
            {
                return false;
            }
        }
        if (second && oid[0] != '2' && (arc.size() > 2U || (arc.size() == 2U && arc > "39")))
        {
            return false;
        }
        if (end == oid.size())
        {
            return true;
        }
        start = end + 1U;
        second = false;
    }
    return false;
}

bool ReadOid(const ASN1_OBJECT* object, std::string& output)
{
    if (object == nullptr)
    {
        return false;
    }
    std::array<char, bounds::kMaxOidBytes + 1U> text{};
    const int length = OBJ_obj2txt(text.data(), static_cast<int>(text.size()), object, 1);
    if (length <= 0 || static_cast<std::size_t>(length) > bounds::kMaxOidBytes)
    {
        return false;
    }
    output.assign(text.data(), static_cast<std::size_t>(length));
    return ValidOid(output);
}

// This reader only checks structure. All production encoding is performed by
// OpenSSL ASN.1 items. OCTET STRING and BIT STRING payloads remain opaque.
struct Element
{
    unsigned tag{0U};
    unsigned tag_class{0U};
    bool constructed{false};
    std::size_t begin{0U};
    std::size_t content{0U};
    std::size_t end{0U};
};

bool ReadElement(View input, std::size_t& position, Element& element) noexcept
{
    if (position >= input.size())
    {
        return false;
    }
    element.begin = position;
    const auto identifier = input[position++];
    element.tag_class = identifier & 0xC0U;
    element.constructed = (identifier & 0x20U) != 0U;
    element.tag = identifier & 0x1FU;
    if (element.tag == 0x1FU)
    {
        element.tag = 0U;
        bool first = true;
        for (;;)
        {
            if (position >= input.size())
            {
                return false;
            }
            const auto next = input[position++];
            if ((first && (next & 0x7FU) == 0U) || element.tag > (std::numeric_limits<unsigned>::max() >> 7U))
            {
                return false;
            }
            element.tag = (element.tag << 7U) | (next & 0x7FU);
            first = false;
            if ((next & 0x80U) == 0U)
            {
                break;
            }
        }
        if (element.tag < 31U)
        {
            return false;
        }
    }
    if (position >= input.size())
    {
        return false;
    }
    const auto first_length = input[position++];
    std::size_t length = first_length;
    if ((first_length & 0x80U) != 0U)
    {
        const auto count = static_cast<std::size_t>(first_length & 0x7FU);
        // Reject indefinite length, leading zeroes, overflows and truncation.
        if (count == 0U || count > sizeof(std::size_t) || count > input.size() - position || input[position] == 0U)
        {
            return false;
        }
        length = 0U;
        for (std::size_t i = 0U; i < count; ++i)
        {
            if (length > (std::numeric_limits<std::size_t>::max() >> 8U))
            {
                return false;
            }
            length = (length << 8U) | input[position++];
        }
        if (length < 128U)
        {
            return false;
        }
    }
    if (length > input.size() - position)
    {
        return false;
    }
    element.content = position;
    element.end = position + length;
    position = element.end;
    return true;
}

bool Printable(unsigned char c) noexcept
{
    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == ' ' || c == '\'' ||
           c == '(' || c == ')' || c == '+' || c == ',' || c == '-' || c == '.' || c == '/' || c == ':' || c == '=' ||
           c == '?';
}

bool ValidPrimitive(unsigned tag, View value) noexcept
{
    switch (tag)
    {
        case V_ASN1_BOOLEAN:
            return value.size() == 1U && (value[0] == 0U || value[0] == 0xFFU);
        case V_ASN1_INTEGER:
        case V_ASN1_ENUMERATED:
            return !value.empty() && (value.size() == 1U || !((value[0] == 0U && (value[1] & 0x80U) == 0U) ||
                                                              (value[0] == 0xFFU && (value[1] & 0x80U) != 0U)));
        case V_ASN1_OBJECT:
        {
            if (value.empty() || (value[value.size() - 1U] & 0x80U) != 0U)
            {
                return false;
            }
            bool start = true;
            for (auto byte : value)
            {
                if (start && byte == 0x80U)
                {
                    return false;
                }
                start = (byte & 0x80U) == 0U;
            }
            return start;
        }
        case V_ASN1_BIT_STRING:
            if (value.empty() || value[0] > 7U)
            {
                return false;
            }
            if (value.size() == 1U)
            {
                return value[0] == 0U;
            }
            return (value[value.size() - 1U] & ((1U << value[0]) - 1U)) == 0U;
        case V_ASN1_OCTET_STRING:
            return true;
        case V_ASN1_NULL:
            return value.empty();
        case V_ASN1_UTF8STRING:
            return ValidText(
                std::string_view{reinterpret_cast<const char*>(value.data()), value.size()}, kMaxTemplateBytes, true);
        case V_ASN1_BMPSTRING:
        case V_ASN1_UNIVERSALSTRING:
        {
            const std::size_t width = tag == V_ASN1_BMPSTRING ? 2U : 4U;
            if (value.size() % width != 0U)
            {
                return false;
            }
            for (std::size_t i = 0U; i < value.size(); i += width)
            {
                std::uint32_t cp = 0U;
                for (std::size_t j = 0U; j < width; ++j)
                {
                    cp = (cp << 8U) | value[i + j];
                }
                if (cp == 0U || cp > 0x10FFFFU || (cp >= 0xD800U && cp <= 0xDFFFU))
                {
                    return false;
                }
            }
            return true;
        }
        case V_ASN1_NUMERICSTRING:
        case V_ASN1_PRINTABLESTRING:
        case V_ASN1_T61STRING:
        case V_ASN1_IA5STRING:
        case V_ASN1_VISIBLESTRING:
            for (auto byte : value)
            {
                if (byte == 0U || (tag == V_ASN1_NUMERICSTRING && byte != ' ' && (byte < '0' || byte > '9')) ||
                    (tag == V_ASN1_PRINTABLESTRING && !Printable(byte)) || (tag == V_ASN1_IA5STRING && byte > 0x7FU) ||
                    (tag == V_ASN1_VISIBLESTRING && (byte < 0x20U || byte > 0x7EU)))
                {
                    return false;
                }
            }
            return true;
        default:
            // These protocols have no time, real, external or reserved types.
            return false;
    }
}

bool CheckElement(View input, const Element& element, std::size_t depth) noexcept
{
    if (depth > kMaxDepth)
    {
        return false;
    }
    if (element.tag_class == 0U)
    {
        if (element.tag == V_ASN1_SEQUENCE || element.tag == V_ASN1_SET)
        {
            if (!element.constructed)
            {
                return false;
            }
        }
        else
        {
            if (element.constructed)
            {
                return false;
            }
            return ValidPrimitive(element.tag, View{input.data() + element.content, element.end - element.content});
        }
    }
    if (!element.constructed)
    {
        return true;
    }
    std::size_t cursor = element.content;
    Element previous{};
    bool has_previous = false;
    const View bounded{input.data(), element.end};
    while (cursor < element.end)
    {
        Element child{};
        if (!ReadElement(bounded, cursor, child) || !CheckElement(bounded, child, depth + 1U))
        {
            return false;
        }
        if (element.tag_class == 0U && element.tag == V_ASN1_SET && has_previous &&
            std::lexicographical_compare(input.data() + child.begin,
                                         input.data() + child.end,
                                         input.data() + previous.begin,
                                         input.data() + previous.end))
        {
            return false;
        }
        previous = child;
        has_previous = true;
    }
    return cursor == element.end;
}

template <typename T>
score::Result<Bytes> Encode(const T* value, int (*encoder)(const T*, unsigned char**), std::size_t limit)
{
    const int length = encoder(value, nullptr);
    if (length <= 0 || static_cast<std::size_t>(length) > limit)
    {
        return Invalid();
    }
    Bytes bytes(static_cast<std::size_t>(length));
    auto* cursor = bytes.data();
    if (encoder(value, &cursor) != length || cursor != bytes.data() + bytes.size() || !IsCanonicalDer(bytes))
    {
        return Invalid();
    }
    return bytes;
}

template <typename T>
bool SameEncoding(const T* value, int (*encoder)(const T*, unsigned char**), View input)
{
    const auto encoded = Encode(value, encoder, input.size());
    return encoded.has_value() && encoded->size() == input.size() &&
           std::equal(encoded->begin(), encoded->end(), input.begin());
}

bool ReadText(const ASN1_STRING* value, std::size_t limit, std::string& output, bool allow_empty = false)
{
    if (value == nullptr || ASN1_STRING_length(value) < 0)
    {
        return false;
    }
    const auto size = static_cast<std::size_t>(ASN1_STRING_length(value));
    const auto* data = ASN1_STRING_get0_data(value);
    if (size == 0U)
    {
        output.clear();
        return allow_empty;
    }
    if (data == nullptr)
    {
        return false;
    }
    const std::string_view text{reinterpret_cast<const char*>(data), size};
    if (!ValidText(text, limit, allow_empty))
    {
        return false;
    }
    output.assign(text);
    return true;
}

bool ReadDirectoryText(const ASN1_STRING* value, std::size_t limit, std::string& output)
{
    if (value == nullptr)
    {
        return false;
    }
    const int type = ASN1_STRING_type(value);
    if (type != V_ASN1_UTF8STRING && type != V_ASN1_PRINTABLESTRING && type != V_ASN1_T61STRING &&
        type != V_ASN1_BMPSTRING && type != V_ASN1_UNIVERSALSTRING && type != V_ASN1_IA5STRING)
    {
        return false;
    }
    unsigned char* bytes = nullptr;
    const int size = ASN1_STRING_to_UTF8(&bytes, value);
    std::unique_ptr<unsigned char, BufferDeleter> owned{bytes};
    if (size <= 0 || bytes == nullptr)
    {
        return false;
    }
    const std::string_view text{reinterpret_cast<const char*>(bytes), static_cast<std::size_t>(size)};
    if (!ValidText(text, limit))
    {
        return false;
    }
    output.assign(text);
    return true;
}

bool ValidEntries(const std::vector<SubjectAttribute>& entries, bool allow_empty)
{
    if ((!allow_empty && entries.empty()) || entries.size() > bounds::kMaxSubjectEntries)
    {
        return false;
    }
    for (const auto& entry : entries)
    {
        if (!ValidOid(entry.oid) || !ValidText(entry.value, bounds::kMaxValueBytes))
        {
            return false;
        }
    }
    return true;
}

bool ValidExtensions(const std::vector<ExtensionSpec>& entries)
{
    if (entries.size() > bounds::kMaxExtensions)
    {
        return false;
    }
    for (std::size_t i = 0U; i < entries.size(); ++i)
    {
        if (!ValidOid(entries[i].oid) || !ValidText(entries[i].value, bounds::kMaxValueBytes))
        {
            return false;
        }
        for (std::size_t j = 0U; j < i; ++j)
        {
            if (entries[i].oid == entries[j].oid)
            {
                return false;
            }
        }
    }
    return true;
}

bool AddSubject(X509_NAME* name, const std::vector<SubjectAttribute>& entries)
{
    for (const auto& entry : entries)
    {
        ObjectPtr oid{OBJ_txt2obj(entry.oid.c_str(), 1), ASN1_OBJECT_free};
        if (!oid || X509_NAME_add_entry_by_OBJ(name,
                                               oid.get(),
                                               MBSTRING_UTF8,
                                               reinterpret_cast<const unsigned char*>(entry.value.data()),
                                               static_cast<int>(entry.value.size()),
                                               -1,
                                               0) != 1)
        {
            return false;
        }
    }
    return true;
}

bool CopyValidatedName(const X509_NAME* source, X509_NAME* fresh)
{
    const int count = X509_NAME_entry_count(source);
    if (count <= 0 || static_cast<std::size_t>(count) > bounds::kMaxSubjectEntries)
    {
        return false;
    }
    for (int i = 0; i < count; ++i)
    {
        const auto* entry = X509_NAME_get_entry(source, i);
        if (entry == nullptr || X509_NAME_ENTRY_set(entry) != i)
        {
            return false;
        }
        const auto* oid = X509_NAME_ENTRY_get_object(entry);
        const auto* data = X509_NAME_ENTRY_get_data(entry);
        std::string oid_text;
        std::string utf8;
        if (!ReadOid(oid, oid_text) || !ReadDirectoryText(data, bounds::kMaxValueBytes, utf8))
        {
            return false;
        }
        // Reapply the current MBSTRING_UTF8 attribute-specific constraints
        // (country length, IA5 attributes, etc.) without changing the wire tag.
        Owned<X509_NAME_ENTRY, X509_NAME_ENTRY_free> checked{
            X509_NAME_ENTRY_create_by_OBJ(nullptr,
                                          oid,
                                          MBSTRING_UTF8,
                                          reinterpret_cast<const unsigned char*>(utf8.data()),
                                          static_cast<int>(utf8.size())),
            X509_NAME_ENTRY_free};
        if (!checked || X509_NAME_add_entry(fresh, entry, -1, 0) != 1)
        {
            return false;
        }
    }
    return true;
}

score::Result<std::monostate> AddExtensions(X509_REQ* request, const std::vector<ExtensionSpec>& entries)
{
    ExtensionsPtr stack{sk_X509_EXTENSION_new_null()};
    if (!stack)
    {
        return AllocationFailed();
    }
    X509V3_CTX context{};
    // A new request has an empty public-key BIT STRING. Providing it as
    // context lets OpenSSL's "hash" configuration silently hash that empty
    // placeholder. Supply request context only after a public key is bound;
    // otherwise context-dependent configuration must fail and request SPKI.
    auto* context_request = X509_REQ_get0_pubkey(request) == nullptr ? nullptr : request;
    X509V3_set_ctx(&context, nullptr, nullptr, context_request, nullptr, 0);
    X509V3_set_ctx_nodb(&context);
    for (const auto& entry : entries)
    {
        ObjectPtr oid{OBJ_txt2obj(entry.oid.c_str(), 1), ASN1_OBJECT_free};
        if (!oid)
        {
            return Invalid();
        }
        const int nid = OBJ_obj2nid(oid.get());
        const char* name = nid == NID_undef ? entry.oid.c_str() : OBJ_nid2sn(nid);
        Owned<X509_EXTENSION, X509_EXTENSION_free> extension{
            name == nullptr ? nullptr : X509V3_EXT_nconf(nullptr, &context, name, entry.value.c_str()),
            X509_EXTENSION_free};
        if (!extension || X509_EXTENSION_set_critical(extension.get(), entry.critical ? 1 : 0) != 1)
        {
            return Invalid();
        }
        for (int i = 0; i < sk_X509_EXTENSION_num(stack.get()); ++i)
        {
            if (OBJ_cmp(X509_EXTENSION_get_object(extension.get()),
                        X509_EXTENSION_get_object(sk_X509_EXTENSION_value(stack.get(), i))) == 0)
            {
                return Invalid();
            }
        }
        if (sk_X509_EXTENSION_push(stack.get(), extension.get()) == 0)
        {
            return AllocationFailed();
        }
        static_cast<void>(extension.release());
    }
    if (!entries.empty() && X509_REQ_add_extensions(request, stack.get()) != 1)
    {
        return Invalid();
    }
    return std::monostate{};
}

bool ValidateRequestedExtensions(const ASN1_TYPE* value)
{
    if (value == nullptr || ASN1_TYPE_get(value) != V_ASN1_SEQUENCE || value->value.sequence == nullptr)
    {
        return false;
    }
    const auto* sequence = value->value.sequence;
    const int size = ASN1_STRING_length(sequence);
    const auto* data = ASN1_STRING_get0_data(sequence);
    if (size <= 0 || data == nullptr || static_cast<std::size_t>(size) > bounds::kMaxInputDerBytes)
    {
        return false;
    }
    const View encoded{data, static_cast<std::size_t>(size)};
    if (!IsCanonicalDer(encoded))
    {
        return false;
    }
    const auto* cursor = data;
    ExtensionsPtr extensions{d2i_X509_EXTENSIONS(nullptr, &cursor, size)};
    if (!extensions || cursor != data + size)
    {
        return false;
    }
    const int count = sk_X509_EXTENSION_num(extensions.get());
    if (count <= 0 || static_cast<std::size_t>(count) > bounds::kMaxExtensions)
    {
        return false;
    }
    ExtensionsPtr fresh{sk_X509_EXTENSION_new_null()};
    if (!fresh)
    {
        return false;
    }
    for (int i = 0; i < count; ++i)
    {
        auto* extension = sk_X509_EXTENSION_value(extensions.get(), i);
        if (extension == nullptr)
        {
            return false;
        }
        auto* oid = X509_EXTENSION_get_object(extension);
        auto* octets = X509_EXTENSION_get_data(extension);
        std::string oid_text;
        if (!ReadOid(oid, oid_text) || octets == nullptr || ASN1_STRING_length(octets) < 0 ||
            static_cast<std::size_t>(ASN1_STRING_length(octets)) > bounds::kMaxValueBytes)
        {
            return false;
        }
        for (int j = 0; j < i; ++j)
        {
            if (OBJ_cmp(oid, X509_EXTENSION_get_object(sk_X509_EXTENSION_value(extensions.get(), j))) == 0)
            {
                return false;
            }
        }
        // Reconstruct the wrapper to reject explicitly encoded DEFAULT FALSE.
        // The extension's inner octets are intentionally NOT interpreted here.
        Owned<X509_EXTENSION, X509_EXTENSION_free> normalized{
            X509_EXTENSION_create_by_OBJ(nullptr, oid, X509_EXTENSION_get_critical(extension), octets),
            X509_EXTENSION_free};
        if (!normalized || sk_X509_EXTENSION_push(fresh.get(), normalized.get()) == 0)
        {
            return false;
        }
        static_cast<void>(normalized.release());
    }
    return SameEncoding(fresh.get(), i2d_X509_EXTENSIONS, encoded);
}

bool ValidateAttributes(const STACK_OF(X509_ATTRIBUTE) * attributes)
{
    const int count = sk_X509_ATTRIBUTE_num(attributes);
    if (count < 0 || count > 2)
    {
        return false;
    }
    bool extensions = false;
    bool password = false;
    for (int i = 0; i < count; ++i)
    {
        auto* attribute = sk_X509_ATTRIBUTE_value(attributes, i);
        if (attribute == nullptr || X509_ATTRIBUTE_count(attribute) != 1)
        {
            return false;
        }
        const int nid = OBJ_obj2nid(X509_ATTRIBUTE_get0_object(attribute));
        const auto* value = X509_ATTRIBUTE_get0_type(attribute, 0);
        if (nid == NID_ext_req)
        {
            if (extensions || !ValidateRequestedExtensions(value))
            {
                return false;
            }
            extensions = true;
        }
        else if (nid == NID_pkcs9_challengePassword)
        {
            std::string text;
            // challengePassword is DirectoryString, not IA5String.
            if (password || value == nullptr)
            {
                return false;
            }
            const int type = ASN1_TYPE_get(value);
            // Test the union discriminator before reading its string member.
            if ((type != V_ASN1_UTF8STRING && type != V_ASN1_PRINTABLESTRING && type != V_ASN1_T61STRING &&
                 type != V_ASN1_BMPSTRING && type != V_ASN1_UNIVERSALSTRING) ||
                !ReadDirectoryText(value->value.asn1_string, bounds::kMaxChallengePasswordBytes, text))
            {
                return false;
            }
            password = true;
        }
        else
        {
            return false;
        }
    }
    return true;
}

bool ValidTemplate(const TemplateRecord& value)
{
    return ValidText(value.id, kMaxTemplateIdBytes) && ValidText(value.key_resource, kMaxResourceBytes) &&
           ValidText(value.algorithm, kMaxAlgorithmBytes) &&
           ValidText(value.submission_url, bounds::kMaxValueBytes, true) && ValidEntries(value.subject, false) &&
           ValidEntries(value.issuer, true) && ValidExtensions(value.extensions);
}

bool WriteEntries(STACK_OF(TemplateEntry) * target, const std::vector<SubjectAttribute>& entries)
{
    for (const auto& value : entries)
    {
        Owned<TemplateEntry, TemplateEntry_free> entry{TemplateEntry_new(), TemplateEntry_free};
        if (!entry)
        {
            return false;
        }
        ObjectPtr oid{OBJ_txt2obj(value.oid.c_str(), 1), ASN1_OBJECT_free};
        if (!oid || ASN1_STRING_set(entry->value, value.value.data(), static_cast<int>(value.value.size())) != 1)
        {
            return false;
        }
        ASN1_OBJECT_free(entry->oid);
        entry->oid = oid.release();
        if (sk_TemplateEntry_push(target, entry.get()) == 0)
        {
            return false;
        }
        static_cast<void>(entry.release());
    }
    return true;
}

bool ReadEntries(const STACK_OF(TemplateEntry) * source, std::vector<SubjectAttribute>& output, bool allow_empty)
{
    const int count = sk_TemplateEntry_num(source);
    if (count < 0 || (!allow_empty && count == 0) || static_cast<std::size_t>(count) > bounds::kMaxSubjectEntries)
    {
        return false;
    }
    for (int i = 0; i < count; ++i)
    {
        const auto* entry = sk_TemplateEntry_value(source, i);
        SubjectAttribute value;
        if (entry == nullptr || !ReadOid(entry->oid, value.oid) ||
            !ReadText(entry->value, bounds::kMaxValueBytes, value.value))
        {
            return false;
        }
        output.push_back(std::move(value));
    }
    return true;
}
}  // namespace

bool IsCanonicalDer(View encoded) noexcept
{
    if (encoded.empty() || encoded.data() == nullptr || encoded.size() > kMaxTemplateBytes)
    {
        return false;
    }
    std::size_t cursor = 0U;
    Element root{};
    return ReadElement(encoded, cursor, root) && cursor == encoded.size() && CheckElement(encoded, root, 1U);
}

score::Result<Bytes> EncodeParameters(const std::vector<SubjectAttribute>& subject,
                                      const std::vector<ExtensionSpec>& extensions,
                                      std::string_view challenge_password,
                                      View public_key_info)
{
    if (!ValidEntries(subject, false) || !ValidExtensions(extensions) ||
        !ValidText(challenge_password, bounds::kMaxChallengePasswordBytes, true))
    {
        return Invalid();
    }
    // Bound direct codec callers too, before any configuration parsing.
    std::size_t total = challenge_password.size();
    const auto account = [&total](std::size_t size) {
        if (size > bounds::kMaxInputDerBytes - total)
        {
            return false;
        }
        total += size;
        return true;
    };
    for (const auto& entry : subject)
    {
        if (!account(entry.oid.size()) || !account(entry.value.size()))
        {
            return Invalid();
        }
    }
    for (const auto& entry : extensions)
    {
        if (!account(entry.oid.size()) || !account(entry.value.size()) || !account(1U))
        {
            return Invalid();
        }
    }
    RequestPtr request{X509_REQ_new(), X509_REQ_free};
    if (!request)
    {
        return AllocationFailed();
    }
    if (!public_key_info.empty())
    {
        if (public_key_info.size() > bounds::kMaxInputDerBytes || !IsCanonicalDer(public_key_info))
        {
            return Invalid();
        }
        const auto* cursor = public_key_info.data();
        Owned<EVP_PKEY, EVP_PKEY_free> key{d2i_PUBKEY(nullptr, &cursor, static_cast<long>(public_key_info.size())),
                                           EVP_PKEY_free};
        if (!key || cursor != public_key_info.data() + public_key_info.size() ||
            !SameEncoding(key.get(), i2d_PUBKEY, public_key_info) || X509_REQ_set_pubkey(request.get(), key.get()) != 1)
        {
            return Invalid();
        }
    }
    if (!AddSubject(X509_REQ_get_subject_name(request.get()), subject))
    {
        return Invalid();
    }
    const auto added = AddExtensions(request.get(), extensions);
    if (!added.has_value())
    {
        return score::Unexpected{added.error()};
    }
    if (!challenge_password.empty() &&
        X509_REQ_add1_attr_by_NID(request.get(),
                                  NID_pkcs9_challengePassword,
                                  MBSTRING_UTF8,
                                  reinterpret_cast<const unsigned char*>(challenge_password.data()),
                                  static_cast<int>(challenge_password.size())) != 1)
    {
        return Invalid();
    }
    Owned<Parameters, Parameters_free> envelope{Parameters_new(), Parameters_free};
    if (!envelope)
    {
        return AllocationFailed();
    }
    if (X509_NAME_set(&envelope->subject, X509_REQ_get_subject_name(request.get())) != 1)
    {
        return AllocationFailed();
    }
    for (int i = 0; i < X509_REQ_get_attr_count(request.get()); ++i)
    {
        AttributePtr attribute{X509_ATTRIBUTE_dup(X509_REQ_get_attr(request.get(), i)), X509_ATTRIBUTE_free};
        if (!attribute || sk_X509_ATTRIBUTE_push(envelope->attributes, attribute.get()) == 0)
        {
            return AllocationFailed();
        }
        static_cast<void>(attribute.release());
    }
    // Apply the same semantic bounds to our own output (not proprietary values).
    if (!ValidateAttributes(envelope->attributes))
    {
        return Invalid();
    }
    return Encode(envelope.get(), i2d_Parameters, bounds::kMaxInputDerBytes);
}

score::Result<std::monostate> PopulateRequest(X509_REQ* request, View encoded)
{
    if (request == nullptr || encoded.size() > bounds::kMaxInputDerBytes || !IsCanonicalDer(encoded))
    {
        return Invalid();
    }
    const auto* cursor = encoded.data();
    Owned<Parameters, Parameters_free> envelope{d2i_Parameters(nullptr, &cursor, static_cast<long>(encoded.size())),
                                                Parameters_free};
    if (!envelope || cursor != encoded.data() + encoded.size() || !ValidateAttributes(envelope->attributes))
    {
        return Invalid();
    }
    NamePtr fresh{X509_NAME_new(), X509_NAME_free};
    if (!fresh)
    {
        return AllocationFailed();
    }
    if (!CopyValidatedName(envelope->subject, fresh.get()))
    {
        return Invalid();
    }
    // X509_NAME caches received encodings. Replace it with a newly built Name
    // before comparing; otherwise BER/empty RDNs can survive an i2d round trip.
    if (X509_NAME_set(&envelope->subject, fresh.get()) != 1)
    {
        return AllocationFailed();
    }
    if (!SameEncoding(envelope.get(), i2d_Parameters, encoded))
    {
        return Invalid();
    }

    // No mutation on invalid input. Once validated, replace only these fields;
    // the provider's bound public key, version and signature remain untouched.
    if (X509_REQ_set_subject_name(request, fresh.get()) != 1)
    {
        return AllocationFailed();
    }
    while (X509_REQ_get_attr_count(request) > 0)
    {
        X509_ATTRIBUTE_free(X509_REQ_delete_attr(request, 0));
    }
    for (int i = 0; i < sk_X509_ATTRIBUTE_num(envelope->attributes); ++i)
    {
        if (X509_REQ_add1_attr(request, sk_X509_ATTRIBUTE_value(envelope->attributes, i)) != 1)
        {
            return AllocationFailed();
        }
    }
    return std::monostate{};
}

score::Result<Bytes> EncodeTemplate(const TemplateRecord& value)
{
    if (!ValidTemplate(value))
    {
        return Invalid();
    }
    Owned<StoredTemplate, StoredTemplate_free> stored{StoredTemplate_new(), StoredTemplate_free};
    if (!stored)
    {
        return AllocationFailed();
    }
    if (ASN1_INTEGER_set(stored->version, 1L) != 1 ||
        ASN1_STRING_set(stored->id, value.id.data(), static_cast<int>(value.id.size())) != 1 ||
        ASN1_STRING_set(stored->key_resource, value.key_resource.data(), static_cast<int>(value.key_resource.size())) !=
            1 ||
        ASN1_STRING_set(stored->algorithm, value.algorithm.data(), static_cast<int>(value.algorithm.size())) != 1 ||
        ASN1_STRING_set(
            stored->submission_url, value.submission_url.data(), static_cast<int>(value.submission_url.size())) != 1 ||
        !WriteEntries(stored->subject, value.subject) || !WriteEntries(stored->issuer, value.issuer))
    {
        return Invalid();
    }
    for (const auto& specification : value.extensions)
    {
        Owned<TemplateExtension, TemplateExtension_free> entry{TemplateExtension_new(), TemplateExtension_free};
        if (!entry)
        {
            return AllocationFailed();
        }
        ObjectPtr oid{OBJ_txt2obj(specification.oid.c_str(), 1), ASN1_OBJECT_free};
        if (!oid || ASN1_STRING_set(
                        entry->value, specification.value.data(), static_cast<int>(specification.value.size())) != 1)
        {
            return Invalid();
        }
        ASN1_OBJECT_free(entry->oid);
        entry->oid = oid.release();
        entry->critical = specification.critical ? 0xFF : 0;
        if (sk_TemplateExtension_push(stored->extensions, entry.get()) == 0)
        {
            return AllocationFailed();
        }
        static_cast<void>(entry.release());
    }
    return Encode(stored.get(), i2d_StoredTemplate, kMaxTemplateBytes);
}

score::Result<TemplateRecord> DecodeTemplate(View encoded)
{
    if (encoded.size() > kMaxTemplateBytes || !IsCanonicalDer(encoded))
    {
        return Invalid();
    }
    const auto* cursor = encoded.data();
    Owned<StoredTemplate, StoredTemplate_free> stored{
        d2i_StoredTemplate(nullptr, &cursor, static_cast<long>(encoded.size())), StoredTemplate_free};
    std::int64_t version = 0;
    if (!stored || cursor != encoded.data() + encoded.size() ||
        ASN1_INTEGER_get_int64(&version, stored->version) != 1 || version != 1)
    {
        return Invalid();
    }
    TemplateRecord value;
    if (!ReadText(stored->id, kMaxTemplateIdBytes, value.id) ||
        !ReadText(stored->key_resource, kMaxResourceBytes, value.key_resource) ||
        !ReadText(stored->algorithm, kMaxAlgorithmBytes, value.algorithm) ||
        !ReadText(stored->submission_url, bounds::kMaxValueBytes, value.submission_url, true) ||
        !ReadEntries(stored->subject, value.subject, false) || !ReadEntries(stored->issuer, value.issuer, true))
    {
        return Invalid();
    }
    const int count = sk_TemplateExtension_num(stored->extensions);
    if (count < 0 || static_cast<std::size_t>(count) > bounds::kMaxExtensions)
    {
        return Invalid();
    }
    for (int i = 0; i < count; ++i)
    {
        const auto* entry = sk_TemplateExtension_value(stored->extensions, i);
        ExtensionSpec specification;
        if (entry == nullptr || !ReadOid(entry->oid, specification.oid) ||
            !ReadText(entry->value, bounds::kMaxValueBytes, specification.value))
        {
            return Invalid();
        }
        specification.critical = entry->critical != 0;
        value.extensions.push_back(std::move(specification));
    }
    if (!ValidTemplate(value))
    {
        return Invalid();
    }
    // Rebuild through the schema, rather than trusting any decoder cache or
    // explicitly supplied DEFAULT FALSE field. Order is not sorted in templates.
    const auto normalized = EncodeTemplate(value);
    if (!normalized.has_value() || normalized->size() != encoded.size() ||
        !std::equal(normalized->begin(), normalized->end(), encoded.begin()))
    {
        return Invalid();
    }
    return value;
}
}  // namespace score::crypto::csr::der
