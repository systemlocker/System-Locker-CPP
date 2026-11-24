#include "syslocker/management.hpp"
#include "syslocker/http.hpp"
#include "util.hpp"
#include "json.hpp"

#include <limits>

namespace syslocker
{
    Management::Management(IHttpClient &http, std::string baseUrl, std::string apiKey, std::string systemId)
        : http_(http), baseUrl_(std::move(baseUrl)), apiKey_(std::move(apiKey)), systemId_(std::move(systemId))
    {
        while (!baseUrl_.empty() && baseUrl_.back() == '/')
            baseUrl_.pop_back();
    }

    Result<std::string> Management::request(std::string_view method, std::string_view path, std::string_view body)
    {
        if (apiKey_.empty() || apiKey_.find_first_of("\r\n") != std::string::npos)
            return Result<std::string>::fail("management bearer credential not configured");
        if (!detail::startsWith(baseUrl_, "https://"))
            return Result<std::string>::fail("management base URL must use HTTPS");
        std::string jsonBody(body);
        if (jsonBody.empty() && (method == "POST" || method == "PUT" || method == "PATCH"))
            jsonBody = "{}";
        const auto response = http_.request(method, baseUrl_ + "/api/v2" + std::string(path), jsonBody,
                                            {{"Authorization", "Bearer " + apiKey_}, {"Accept", "application/json"}, {"Content-Type", "application/json"}});
        // Mutations are never retried: the server may already have committed.
        if (!response.error.empty())
            return Result<std::string>::fail(response.error);
        if (response.body.size() > 1024 * 1024)
            return Result<std::string>::fail("management response exceeded the size limit");
        auto payload = nlohmann::json::parse(response.body, nullptr, false);
        if (!response.ok())
        {
            std::string message = "management HTTP " + std::to_string(response.status);
            if (payload.is_object() && payload.contains("error") && payload["error"].is_object())
            {
                const auto &error = payload["error"];
                if (error.contains("code") && error["code"].is_string())
                    message += " " + error["code"].get<std::string>();
                if (error.contains("message") && error["message"].is_string())
                    message += ": " + error["message"].get<std::string>();
            }
            return Result<std::string>::fail(std::move(message));
        }
        if (!payload.is_object() || !payload.contains("data") || payload["data"].is_null())
            return Result<std::string>::fail("invalid management JSON data envelope");
        return payload["data"].dump();
    }

    Result<std::string> Management::systemPath()
    {
        if (systemId_.empty())
        {
            // Older callers construct Management directly with only a key.
            // A v2 credential is bound to one system; discover it when needed.
            auto data = request("GET", "/systems");
            if (!data)
                return data;
            auto systems = nlohmann::json::parse(*data);
            if (!systems.is_array() || systems.size() != 1 || !systems[0].is_object() ||
                !systems[0].contains("id") || !systems[0]["id"].is_string())
                return Result<std::string>::fail("pass the system ID to Management or use Client::management()");
            systemId_ = systems[0]["id"].get<std::string>();
        }
        if (systemId_.empty())
            return Result<std::string>::fail("management system ID is required");
        return "/systems/" + detail::urlEncode(systemId_);
    }

    Result<std::string> Management::keyPath(std::string_view license)
    {
        if (license.empty())
            return Result<std::string>::fail("license key is required");
        auto path = systemPath();
        if (!path)
            return path;
        return *path + "/keys/" + detail::urlEncode(license);
    }

    Result<std::size_t> Management::redeemedUserCount()
    {
        auto path = systemPath();
        if (!path)
            return Result<std::size_t>::fail(path.error());
        auto data = request("GET", *path + "/statistics");
        if (!data)
            return Result<std::size_t>::fail(data.error());
        auto json = nlohmann::json::parse(*data);
        if (!json.is_object() || !json.contains("total_users") || !json["total_users"].is_number_integer())
            return Result<std::size_t>::fail("invalid management user count");
        const auto &value = json["total_users"];
        if ((!value.is_number_unsigned() && value.get<std::int64_t>() < 0) ||
            value.get<std::uint64_t>() > std::numeric_limits<std::size_t>::max())
            return Result<std::size_t>::fail("management user count is out of range");
        return value.get<std::size_t>();
    }

    Result<std::string> Management::keyStatus(std::string_view license)
    {
        auto path = keyPath(license);
        if (!path)
            return path;
        auto data = request("GET", *path);
        if (!data)
            return data;
        auto key = nlohmann::json::parse(*data);
        if (!key.is_object() || !key.contains("claim_type") || !key["claim_type"].is_string())
            return Result<std::string>::fail("invalid management key status");
        return key["claim_type"].get<std::string>();
    }

    Result<KeyExpiration> Management::keyExpiration(std::string_view license)
    {
        auto path = keyPath(license);
        if (!path)
            return Result<KeyExpiration>::fail(path.error());
        auto data = request("GET", *path);
        if (!data)
            return Result<KeyExpiration>::fail(data.error());
        auto key = nlohmann::json::parse(*data);
        if (!key.is_object() || !key.contains("expires_at") || !key.contains("redeemed_at") ||
            (!key["expires_at"].is_null() && !key["expires_at"].is_string()) ||
            (!key["redeemed_at"].is_null() && !key["redeemed_at"].is_string()))
            return Result<KeyExpiration>::fail("invalid management key expiration");
        // Null also describes an unredeemed duration key. Only redemption
        // establishes that a null expiry means a perpetual key.
        return KeyExpiration{key["expires_at"].is_null() ? "" : key["expires_at"].get<std::string>(),
                             key["expires_at"].is_null() && !key["redeemed_at"].is_null()};
    }

    Result<std::string> Management::resetHwid(std::string_view license, bool asAdmin)
    {
        if (!asAdmin)
        {
            auto path = keyPath(license);
            if (!path)
                return path;
            if (!detail::startsWith(baseUrl_, "https://"))
                return Result<std::string>::fail("base URL must use HTTPS");
            // V2 resets are administrative. Keep the old false branch's
            // cooldown semantics using the current self-service auth intent.
            const auto response = http_.post(baseUrl_ + "/auth", {{"system", systemId_}, {"key", std::string(license)}, {"hwid", "1"}, {"version", "bypass"}, {"intent", "hwidreset"}, {"clean", "1"}});
            if (!response.ok())
                return Result<std::string>::fail(response.error.empty() ? "http " + std::to_string(response.status) : response.error);
            if (response.header("intent") != "true")
                return Result<std::string>::fail("self-service HWID reset rejected: " + response.body);
            return response.body;
        }
        auto path = keyPath(license);
        return path ? request("POST", *path + "/hwid-reset") : path;
    }

    Result<std::string> Management::resetAllHwids()
    {
        auto path = systemPath();
        return path ? request("POST", *path + "/keys/hwid-reset") : path;
    }

    Result<std::string> Management::generateKeys(KeyExpiry expiry, std::size_t count, std::string_view note)
    {
        if (count < 1 || count > 100)
            return Result<std::string>::fail("count must be in [1, 100]");
        if (note.size() > 250)
            return Result<std::string>::fail("note must be at most 250 characters");
        const int preset = static_cast<int>(expiry);
        const int durations[] = {0, 86400, 604800, 2592000, 7776000, 31536000};
        if (preset < 0 || preset > 5)
            return Result<std::string>::fail("invalid expiry preset");
        auto path = systemPath();
        if (!path)
            return path;
        nlohmann::json policy = {{"type", "perpetual"}};
        if (preset)
            policy = {{"type", "after_redemption"}, {"seconds", durations[preset]}};
        auto data = request("POST", *path + "/keys", nlohmann::json{{"count", count}, {"expiry", policy}, {"notes", note}}.dump());
        if (!data)
            return data;
        auto json = nlohmann::json::parse(*data);
        if (!json.is_object() || !json.contains("keys") || !json["keys"].is_array())
            return Result<std::string>::fail("invalid generated keys data");
        std::string keys;
        for (const auto &key : json["keys"])
        {
            if (!key.is_string())
                return Result<std::string>::fail("invalid generated keys data");
            if (!keys.empty())
                keys += '\n';
            keys += key.get<std::string>();
        }
        return keys;
    }

    Result<std::string> Management::banKey(std::string_view license)
    {
        auto path = keyPath(license);
        return path ? request("DELETE", *path) : path;
    }

    Result<std::string> Management::adjustExpiry(std::string_view license, std::string_view newExpiry, std::string_view tz)
    {
        (void)license;
        (void)newExpiry;
        (void)tz;
        return Result<std::string>::fail("Management v2 cannot set an existing key's absolute expiry; migrate this operation to the current API's add-time operation");
    }
}
