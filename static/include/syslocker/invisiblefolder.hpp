#pragma once

#include "result.hpp"

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <mutex>
#include <string>
#include <string_view>
#include <vector>

namespace syslocker
{

    class Client;
    class IHttpClient;

    /// Authenticated access to Invisible Folder downloads.
    class InvisibleFolder
    {
    public:
        InvisibleFolder(IHttpClient &http,
                        std::string systemLockerBaseUrl,
                        std::string invisibleFolderBaseUrl,
                        std::string systemId,
                        std::string hwid,
                        std::function<bool()> sessionActive,
                        std::string programDigest = {});

        /// True if a cached Invisible Folder token is present. A rejected token is refreshed
        /// from the next scheduled Bedrock heartbeat.
        bool hasValidToken() const;

        /// Ensure a valid Invisible Folder token exists, refreshing it from
        /// the next scheduled Bedrock heartbeat when needed.
        Result<void> ensureToken();

        /// Download a protected file into memory.
        Result<std::vector<std::uint8_t>> download(std::string_view referenceId);

        /// Download a protected file directly to disk, overwriting any
        /// existing file at `destination`.
        Result<void> downloadToFile(std::string_view referenceId,
                                    const std::filesystem::path &destination);

    private:
        friend class Client;

        void cacheToken(std::string_view token, std::string_view expiresAt);
        void clearCachedToken() noexcept;
        void clearSessionState() noexcept;

        IHttpClient &http_;
        const std::string invisibleFolderBaseUrl_;
        std::function<bool()> sessionActive_;
        std::function<Result<std::string>()> fetchToken_;

        mutable std::mutex stateMtx_;
        std::string token_;
        bool refreshInFlight_ = false;
        std::uint64_t stateVersion_ = 0;
        std::string lastRefreshError_;
        std::condition_variable stateCv_;
    };

} // namespace syslocker
