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

#include "score/crypto/daemon/config/inc/config.hpp"
#include "score/crypto/daemon/config/src/flatbuffer_config_parser.hpp"

#include "score/mw/log/logging.h"
#include <cstdlib>
#include <filesystem>

#include <map>
#include <string>
#include <vector>

namespace score::crypto::daemon::config
{

std::string Config::GetEnvVar(const char* name, const std::map<std::string, std::string>& env) const
{
    // If env map is provided (testing), use it
    if (!env.empty())
    {
        auto it = env.find(name);
        return (it != env.end()) ? it->second : "";
    }
    // Otherwise, read from actual environment
    const char* value = std::getenv(name);
    return value ? value : "";
}

bool Config::ParseEnvironment(const std::map<std::string, std::string>& env)
{
    // TODO: Implement environment variable parsing
    // Example:
    // std::string threads = GetEnvVar("CRYPTO_IPC_THREADS", env);
    // if (!threads.empty()) {
    //     m_ipc.SetNumOfIPCThreads(std::stoul(threads));
    // }
    return true;
}

bool Config::ParseStringArg(const std::string& arg,
                            const std::string& value,
                            const std::string& option,
                            std::string& target)
{
    // TODO: Implement string argument parsing
    return false;
}

bool Config::ParseUint32Arg(const std::string& arg,
                            const std::string& value,
                            const std::string& option,
                            uint32_t& target)
{
    // TODO: Implement uint32 argument parsing
    return false;
}

bool Config::ParseUint16Arg(const std::string& arg,
                            const std::string& value,
                            const std::string& option,
                            uint16_t& target)
{
    // TODO: Implement uint16 argument parsing
    return false;
}

bool Config::ParseCommandLine(int argc, char** argv)
{
    // TODO: Implement command line parsing
    return true;
}

bool Config::ParseConfig()
{
    auto config_file_path = std::getenv(CRYPTO_CONFIG_FILE_ENV.data());
    if (config_file_path)
    {
        if (!std::filesystem::exists(config_file_path))
        {
            score::mw::log::LogError() << "[CONFIG] Configuration file does not exist:" << config_file_path;
            return false;
        }
        score::mw::log::LogDebug() << "[CONFIG] Parsing configuration from:" << config_file_path;
        auto result = FlatBufferConfigParser::ParseFromFile(config_file_path, m_key);
        if (!result.has_value())
        {
            score::mw::log::LogError() << "[CONFIG] Failed to parse FlatBuffers configuration file: "
                                       << config_file_path;
            return false;
        }
        return true;
    }

    // Try default paths (in order of preference)
    for (const auto& path : DEFAULT_CONFIG_PATHS)
    {
        if (std::filesystem::exists(path))
        {
            score::mw::log::LogDebug() << "[CONFIG] Found configuration at default path:" << path;
            auto result = FlatBufferConfigParser::ParseFromFile(path, m_key);
            if (!result.has_value())
            {
                score::mw::log::LogError() << "[CONFIG] Failed to parse configuration from:" << path;
                return false;
            }
            return true;
        }
    }

    score::mw::log::LogError() << "[CONFIG] ERROR: No configuration file found in default paths:";
    for (const auto& path : DEFAULT_CONFIG_PATHS)
    {
        score::mw::log::LogError() << "  -" << path;
    }
    return false;
}

bool Config::Validate() const
{
    // TODO: Implement validation
    return true;
}

}  // namespace score::crypto::daemon::config
