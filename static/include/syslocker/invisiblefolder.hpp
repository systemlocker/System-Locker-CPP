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
                        std::function<bool()> sessionActive);

        /// True if a cached Invisible Folder token is present and not within
        /// the local expiry buffer.
        bool hasValidToken() const;

        /// Ensure a valid Invisible Folder token exists, refreshing it from
        /// System Locker when needed.
        Result<void> ensureToken();

        /// Download a protected file into memory.
        Result<std::vector<std::uint8_t>> download(std::string_view referenceId);

        /// Download a protected file directly to disk, overwriting any
        /// existing file at `destination`.
        Result<void> downloadToFile(std::string_view referenceId,
                                    const std::filesystem::path &destination);

    private:
        friend class Client;

        enum class AuthMode
        {
            None,
            Password,
            Key,
        };

        void setPasswordAuth(std::string_view username, std::string_view password);
        void setKeyAuth(std::string_view licenseKey);
        void cacheToken(std::string_view token, std::string_view expiresAt);
        void clearCachedToken() noexcept;
        void clearSessionState() noexcept;

        IHttpClient &http_;
        const std::string systemLockerBaseUrl_;
        const std::string invisibleFolderBaseUrl_;
        const std::string systemId_;
        const std::string hwid_;
        std::function<bool()> sessionActive_;

        mutable std::mutex stateMtx_;
        AuthMode authMode_ = AuthMode::None;
        std::string username_;
        std::string password_;
        std::string licenseKey_;
        std::string token_;
        std::string tokenExpiresAt_;
        std::chrono::system_clock::time_point tokenExpiresAtTime_{};
        bool hasTokenExpiry_ = false;
        bool refreshInFlight_ = false;
        std::uint64_t stateVersion_ = 0;
        std::condition_variable stateCv_;
    };

} // namespace syslocker