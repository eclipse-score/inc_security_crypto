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

#ifndef SCORE_TESTS_IPC_POC_POC_HELPER_HPP
#define SCORE_TESTS_IPC_POC_POC_HELPER_HPP

#include <chrono>
#include <condition_variable>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <random>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <utility>
#include <vector>

#include "flatbuffers/flatbuffers.h"
#include "score/tests/ipc_poc/ipc_buffer.h"
#include "score/tests/ipc_poc/poc_control_generated.h"

namespace score::crypto::ipc::poc_helper
{

namespace control = score::crypto::ipc::control;
using Bytes = std::vector<std::uint8_t>;

class ThreadStartBarrier final
{
  public:
    explicit ThreadStartBarrier(const std::size_t participant_count) : participant_count_{participant_count} {}

    void ArriveAndWait()
    {
        std::unique_lock<std::mutex> lock{mutex_};
        ++arrived_count_;
        condition_.notify_all();
        condition_.wait(lock, [this] { return released_; });
    }

    void WaitForAll()
    {
        std::unique_lock<std::mutex> lock{mutex_};
        condition_.wait(lock, [this] { return arrived_count_ == participant_count_; });
    }

    void Release()
    {
        {
            std::lock_guard<std::mutex> lock{mutex_};
            released_ = true;
        }
        condition_.notify_all();
    }

  private:
    const std::size_t participant_count_;
    std::size_t arrived_count_{0U};
    bool released_{false};
    std::mutex mutex_;
    std::condition_variable condition_;
};

struct PocArguments final
{
    int client_count{1};
    int call_count{1000};
    int client_threads{1};
    int server_threads{1};
    int sleep_milliseconds{0};
    bool random_wait{false};
};

inline std::optional<PocArguments> ParseArguments(const int argc,
                                                  char** argv,
                                                  std::string& error,
                                                  const PocArguments defaults = {})
{
    PocArguments arguments{defaults};
    const std::string client_prefix{"--client_count="};
    const std::string call_prefix{"--call_count="};
    const std::string client_threads_prefix{"--client_threads="};
    const std::string server_threads_prefix{"--server_threads="};
    const std::string sleep_prefix{"--sleep_milliseconds="};
    const std::string random_wait_prefix{"--random_wait="};

    for (int index = 1; index < argc; ++index)
    {
        const std::string argument{argv[index]};
        try
        {
            if (argument.rfind(client_prefix, 0) == 0)
            {
                arguments.client_count = std::stoi(argument.substr(client_prefix.size()));
            }
            else if (argument.rfind(call_prefix, 0) == 0)
            {
                arguments.call_count = std::stoi(argument.substr(call_prefix.size()));
            }
            else if (argument.rfind(client_threads_prefix, 0) == 0)
            {
                arguments.client_threads = std::stoi(argument.substr(client_threads_prefix.size()));
            }
            else if (argument.rfind(server_threads_prefix, 0) == 0)
            {
                arguments.server_threads = std::stoi(argument.substr(server_threads_prefix.size()));
            }
            else if (argument.rfind(sleep_prefix, 0) == 0)
            {
                arguments.sleep_milliseconds = std::stoi(argument.substr(sleep_prefix.size()));
            }
            else if (argument.rfind(random_wait_prefix, 0) == 0)
            {
                const auto value = argument.substr(random_wait_prefix.size());
                if (value == "true" || value == "1")
                {
                    arguments.random_wait = true;
                }
                else if (value == "false" || value == "0")
                {
                    arguments.random_wait = false;
                }
                else
                {
                    throw std::invalid_argument{"random_wait must be true, false, 1, or 0"};
                }
            }
            else
            {
                throw std::invalid_argument{"unknown argument"};
            }
        }
        catch (const std::exception& exception)
        {
            error = "invalid argument '" + argument + "': " + exception.what();
            return std::nullopt;
        }
    }

    if (arguments.client_count < 1 || arguments.call_count < 1 || arguments.client_threads < 1 ||
        arguments.server_threads < 1 || arguments.sleep_milliseconds < 0)
    {
        error = "client_count, call_count, client_threads, and server_threads must be >= 1; "
                "sleep_milliseconds must be >= 0";
        return std::nullopt;
    }
    return arguments;
}

inline void WaitAfterCall(const bool random_wait)
{
    if (!random_wait)
    {
        return;
    }

    thread_local std::mt19937 generator{std::random_device{}()};
    std::uniform_int_distribution<int> distribution{0, 5};
    std::this_thread::sleep_for(std::chrono::milliseconds(distribution(generator)));
}

struct Request final
{
    std::uint64_t request_id{0U};
    std::string string_value;
    std::uint64_t uint64_value{0U};
};

struct Response final
{
    std::uint64_t request_id{0U};
    std::string string_value;
};

inline Request CreateRequest(const int client_index, const int thread_index, const int call_index)
{
    return Request{
        static_cast<std::uint64_t>(client_index + 1) * 100'000ULL +
            static_cast<std::uint64_t>(thread_index + 1) * 1'000ULL +
            static_cast<std::uint64_t>(call_index + 1),
        "client" + std::to_string(client_index + 1),
        static_cast<std::uint64_t>(call_index + 1),
    };
}

inline Response ProcessRequest(const Request& request)
{
    return Response{request.request_id, request.string_value + "_" + std::to_string(request.uint64_value)};
}

inline bool Matches(const Request& request, const Response& response)
{
    const auto expected = ProcessRequest(request);
    return response.request_id == expected.request_id && response.string_value == expected.string_value;
}

template <typename Builder>
auto CreateRequestTable(Builder& builder, const Request& request)
{
    const auto string_table = control::CreateString(builder, builder.CreateString(request.string_value));
    const auto uint64_table = control::CreateValueUint64(builder, request.uint64_value);
    const std::vector<std::uint8_t> parameter_types{
        control::OperationParameter_String,
        control::OperationParameter_ValueUint64,
    };
    const std::vector<flatbuffers::Offset<void>> parameter_values{
        string_table.Union(),
        uint64_table.Union(),
    };
    const auto operation = control::CreateSingleOperationRequest(
        builder,
        control::CreateOperationIdentifier(builder, 1U, 1U),
        builder.CreateVector(parameter_types),
        builder.CreateVector(parameter_values));
    const auto batch = control::CreateOperationRequestBatch(builder, builder.CreateVector({operation}));
    return control::CreateControlRequest(builder, request.request_id, 0U, 0U, batch);
}

template <typename Builder>
auto CreateResponseTable(Builder& builder,
                         const Response& response,
                         const std::uint32_t operation_actor = 0U,
                         const std::uint32_t operation_action = 0U)
{
    const auto result_string = control::CreateString(builder, builder.CreateString(response.string_value));
    const std::vector<std::uint8_t> parameter_types{control::OperationParameter_String};
    const std::vector<flatbuffers::Offset<void>> parameter_values{result_string.Union()};
    const auto operation = control::CreateSingleOperationResponse(
        builder,
        control::CreateOperationIdentifier(builder, operation_actor, operation_action),
        control::CreateOperationResult(builder, 0U),
        builder.CreateVector(parameter_types),
        builder.CreateVector(parameter_values));
    const auto batch = control::CreateOperationResponseBatch(builder, builder.CreateVector({operation}));
    return control::CreateControlResponse(builder, response.request_id, batch);
}

inline Bytes BuildRequestBytes(const Request& request)
{
    flatbuffers::FlatBufferBuilder builder(512);
    builder.FinishSizePrefixed(CreateRequestTable(builder, request));
    return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
}

inline Bytes BuildResponseBytes(const Response& response)
{
    flatbuffers::FlatBufferBuilder builder(512);
    builder.FinishSizePrefixed(CreateResponseTable(builder, response));
    return {builder.GetBufferPointer(), builder.GetBufferPointer() + builder.GetSize()};
}

inline bool BuildRequestInto(control::IpcBuffer& buffer, const Request& request)
{
    const auto bytes = BuildRequestBytes(request);
    return control::PackFlatBufferInto(buffer, bytes.data(), bytes.size());
}

inline control::IpcBuffer BuildResponseBuffer(const Response& response)
{
    const auto bytes = BuildResponseBytes(response);
    return control::PackFlatBuffer(bytes.data(), bytes.size());
}

inline bool ParseRequestRoot(const control::ControlRequest* root, Request& request)
{
    if (root == nullptr || root->operation_batch() == nullptr || root->operation_batch()->operations() == nullptr ||
        root->operation_batch()->operations()->size() != 1U)
    {
        return false;
    }
    const auto* operation = root->operation_batch()->operations()->Get(0U);
    if (operation == nullptr || operation->parameter() == nullptr || operation->parameter_type() == nullptr ||
        operation->parameter()->size() != 2U || operation->parameter()->size() != operation->parameter_type()->size())
    {
        return false;
    }

    Request parsed{root->request_id(), {}, 0U};
    bool found_string = false;
    bool found_uint64 = false;
    for (flatbuffers::uoffset_t index = 0U; index < operation->parameter()->size(); ++index)
    {
        const auto type = static_cast<control::OperationParameter>(operation->parameter_type()->Get(index));
        if (type == control::OperationParameter_String)
        {
            const auto* value = reinterpret_cast<const control::String*>(operation->parameter()->Get(index));
            if (value == nullptr || value->val() == nullptr || found_string)
            {
                return false;
            }
            parsed.string_value = value->val()->str();
            found_string = true;
        }
        else if (type == control::OperationParameter_ValueUint64)
        {
            const auto* value = reinterpret_cast<const control::ValueUint64*>(operation->parameter()->Get(index));
            if (value == nullptr || found_uint64)
            {
                return false;
            }
            parsed.uint64_value = value->val();
            found_uint64 = true;
        }
        else
        {
            return false;
        }
    }
    if (!found_string || !found_uint64)
    {
        return false;
    }
    request = std::move(parsed);
    return true;
}

inline bool ParseRequestBytes(const std::uint8_t* data, const std::size_t size, Request& request)
{
    flatbuffers::Verifier verifier{data, size};
    if (!control::VerifySizePrefixedControlRequestBuffer(verifier))
    {
        return false;
    }
    return ParseRequestRoot(flatbuffers::GetSizePrefixedRoot<control::ControlRequest>(data), request);
}

inline bool ProcessRequestBytes(const std::uint8_t* data, const std::size_t size, Response& response)
{
    Request request;
    if (!ParseRequestBytes(data, size, request))
    {
        return false;
    }
    response = ProcessRequest(request);
    return true;
}

inline bool ProcessRequestBuffer(const control::IpcBuffer& buffer, Response& response)
{
    if (!control::IsValid(buffer))
    {
        return false;
    }
    return ProcessRequestBytes(reinterpret_cast<const std::uint8_t*>(buffer.payload.data()),
                               control::GetPayloadSize(buffer),
                               response);
}

inline bool ParseRequestBuffer(const control::IpcBuffer& buffer, Request& request)
{
    if (!control::IsValid(buffer))
    {
        return false;
    }
    return ParseRequestBytes(reinterpret_cast<const std::uint8_t*>(buffer.payload.data()),
                             control::GetPayloadSize(buffer),
                             request);
}

inline bool ParseResponseRoot(const control::ControlResponse* root,
                              Response& response,
                              std::uint64_t* echoed_uint64 = nullptr)
{
    if (root == nullptr || root->operation_batch() == nullptr || root->operation_batch()->operations() == nullptr ||
        root->operation_batch()->operations()->size() != 1U)
    {
        return false;
    }
    const auto* operation = root->operation_batch()->operations()->Get(0U);
    if (operation == nullptr || operation->parameter() == nullptr || operation->parameter_type() == nullptr ||
        operation->parameter()->size() == 0U || operation->parameter()->size() != operation->parameter_type()->size())
    {
        return false;
    }

    bool found_string = false;
    for (flatbuffers::uoffset_t index = 0U; index < operation->parameter()->size(); ++index)
    {
        const auto type = static_cast<control::OperationParameter>(operation->parameter_type()->Get(index));
        if (type == control::OperationParameter_String)
        {
            const auto* value = reinterpret_cast<const control::String*>(operation->parameter()->Get(index));
            if (value == nullptr || value->val() == nullptr || found_string)
            {
                return false;
            }
            response.string_value = value->val()->str();
            found_string = true;
        }
        else if (type == control::OperationParameter_ValueUint64 && echoed_uint64 != nullptr)
        {
            const auto* value = reinterpret_cast<const control::ValueUint64*>(operation->parameter()->Get(index));
            if (value == nullptr)
            {
                return false;
            }
            *echoed_uint64 = value->val();
        }
        else
        {
            return false;
        }
    }
    if (!found_string)
    {
        return false;
    }
    response.request_id = root->request_id();
    return true;
}

inline bool ParseResponseBytes(const std::uint8_t* data, const std::size_t size, Response& response)
{
    flatbuffers::Verifier verifier{data, size};
    if (!verifier.template VerifySizePrefixedBuffer<control::ControlResponse>(nullptr))
    {
        return false;
    }
    return ParseResponseRoot(flatbuffers::GetSizePrefixedRoot<control::ControlResponse>(data), response);
}

inline bool ParseResponseBuffer(const control::IpcBuffer& buffer, Response& response)
{
    if (!control::IsValid(buffer))
    {
        return false;
    }
    return ParseResponseBytes(reinterpret_cast<const std::uint8_t*>(buffer.payload.data()),
                              control::GetPayloadSize(buffer),
                              response);
}

inline std::string SettingsSummary(const std::string_view poc_name,
                                   const int client_count,
                                   const int call_count,
                                   const int client_threads,
                                   const int worker_threads,
                                   const std::optional<bool> random_wait = std::nullopt)
{
    auto summary = "[POC settings] name=" + std::string{poc_name} + " client_count=" +
                   std::to_string(client_count) + " call_count=" + std::to_string(call_count) +
                   " client_threads=" + std::to_string(client_threads) +
                   " worker_threads=" + std::to_string(worker_threads);
    if (random_wait.has_value())
    {
        summary += " random_wait=" + std::string{*random_wait ? "true" : "false"};
    }
    return summary;
}

} // namespace score::crypto::ipc::poc_helper

#endif // SCORE_TESTS_IPC_POC_POC_HELPER_HPP
