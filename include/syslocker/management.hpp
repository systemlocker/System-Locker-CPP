#pragma once

#include "result.hpp"

#include <cstddef>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace syslocker
{

    class IHttpClient;

    /// UTC expiration timestamp, or an empty raw value when no date is set.
    /// An unredeemed duration key has no date yet and is not known permanent.
    struct KeyExpiration
    {
        std::string raw; ///< expires_at timestamp, empty when null
        bool permanent = false;
    };

    enum class KeyExpiry : int
    {
        Permanent = 0,
        OneDay = 1,
        OneWeek = 2,
        OneMonth = 3,
        ThreeMonths = 4,
        OneYear = 5,
    };

    /// Compatibility wrapper around the Management v2 API.
    ///
    /// Management calls require an slm_ bearer credential (Config::apiKey). Treat that key as a
    /// secret — Management is intentionally exposed via Client::management() so
    /// the API key only has to live in one place.
    class Management
    {
    public:
        Management(IHttpClient &http, std::string baseUrl, std::string apiKey, std::string systemId = {});

        // ---- queries -------------------------------------------------------

        /// Periodically refreshed total of accounts and key-only redemptions.
        Result<std::size_t> redeemedUserCount();

        /// Redemption status: "user", "mikros", or "unclaimed".
        Result<std::string> keyStatus(std::string_view license);

        /// Expiration date of `license`.
        Result<KeyExpiration> keyExpiration(std::string_view license);

        // ---- actions -------------------------------------------------------

        /// Reset HWID for a single key. When `asAdmin` is false the 30-day
        /// self-service cooldown is enforced through /auth.
        Result<std::string> resetHwid(std::string_view license, bool asAdmin = true);

        /// Reset HWID for every key in the system. Be careful.
        Result<std::string> resetAllHwids();

        /// Generate one or more license keys. Returns the raw server response
        /// (typically the keys, one per line).
        Result<std::string> generateKeys(KeyExpiry expiry,
                                         std::size_t count = 1,
                                         std::string_view note = {});

        /// Permanently delete a key.
        Result<std::string> banKey(std::string_view license);

        /// Retained for source compatibility. Management v2 cannot set an
        /// existing key's absolute expiry; always returns a migration error.
        Result<std::string> adjustExpiry(std::string_view license,
                                         std::string_view newExpiry,
                                         std::string_view tz);

    private:
        Result<std::string> request(std::string_view method, std::string_view path, std::string_view body = {});
        Result<std::string> systemPath();
        Result<std::string> keyPath(std::string_view license);

        IHttpClient &http_;
        std::string baseUrl_;
        std::string apiKey_;
        std::string systemId_;
    };

} // namespace syslocker
