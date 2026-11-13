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

#include "score/crypto/src/common/csr_wire.hpp"
#include <gtest/gtest.h>
namespace score::crypto::csr::wire
{
namespace
{
Bytes Unchecked(const Document& value)
{
    flatbuffers::FlatBufferBuilder builder;
    fb::FinishDocumentBuffer(builder, fb::Document::Pack(builder, &value));
    return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
}
TEST(CsrWireTest, RejectsVersionsUnknownActionsTruncationsTrailingDataAndWrongIdentifier)
{
    Document input;
    input.action = Action::FromDn;
    input.text = "CN=device";
    auto encoded = Encode(input);
    ASSERT_TRUE(encoded.has_value());
    ASSERT_TRUE(Decode(encoded.value()).has_value());
    for (std::size_t size = 0U; size < encoded->size(); ++size)
    {
        EXPECT_FALSE(Decode({encoded->data(), size}).has_value()) << size;
    }
    auto trailing = encoded.value();
    trailing.push_back(0U);
    EXPECT_FALSE(Decode(trailing).has_value());
    auto wrong_id = encoded.value();
    ASSERT_GE(wrong_id.size(), 8U);
    wrong_id[4] ^= 1U;
    EXPECT_FALSE(Decode(wrong_id).has_value());
    input.version = 2U;
    EXPECT_FALSE(Encode(input).has_value());
    EXPECT_FALSE(Decode(Unchecked(input)).has_value());
    input.version = 1U;
    input.action = static_cast<Action>(255U);
    EXPECT_FALSE(Encode(input).has_value());
    EXPECT_FALSE(Decode(Unchecked(input)).has_value());
}
TEST(CsrWireTest, RejectsOversizedVectorsAndStringsBeforeUnpacking)
{
    EXPECT_FALSE(Decode({nullptr, 1U}).has_value());
    Document input;
    input.action = Action::FromDn;
    input.text.assign(16385U, 'x');
    EXPECT_FALSE(Encode(input).has_value());
    EXPECT_FALSE(Decode(Unchecked(input)).has_value());
    input.text.clear();
    input.action = Action::San;
    for (unsigned i = 0U; i < 65U; ++i)
    {
        input.names.push_back(std::make_unique<fb::EntryT>());
    }
    EXPECT_FALSE(Encode(input).has_value());
    EXPECT_FALSE(Decode(Unchecked(input)).has_value());
    input.names.resize(1U);
    input.names[0]->value.assign(2049U, 'x');
    EXPECT_FALSE(Encode(input).has_value());
    EXPECT_FALSE(Decode(Unchecked(input)).has_value());
}
TEST(CsrWireTest, ResponseShapesDoNotAcceptRequestOnlyFields)
{
    Document response;
    response.action = Action::Validate;
    EXPECT_TRUE(ResponseShape(response));
    response.text = "unexpected";
    EXPECT_FALSE(ResponseShape(response));
    response.text.clear();
    response.action = Action::Encode;
    EXPECT_FALSE(ResponseShape(response));
    response.bytes = {1U};
    EXPECT_TRUE(ResponseShape(response));
    response.algorithm = "unexpected";
    EXPECT_FALSE(ResponseShape(response));
}
}  // namespace
}  // namespace score::crypto::csr::wire
