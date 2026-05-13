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

    /// Expiration token returned by the management API. The wire value is a
    /// human-readable string; we expose it raw and also try to surface a
    /// stable boolean for the common "permanent" / "expired" cases.
    struct KeyExpiration
    {
        std::string raw; ///< unmodified server response
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

    /// Wrapper around the /api/v1 management endpoint.
    ///
    /// All calls require an API key (Config::apiKey). Treat that key as a
    /// secret — Management is intentionally exposed via Client::management() so
    /// the API key only has to live in one place.
    class Management
    {
    public:
        Management(IHttpClient &http, std::string baseUrl, std::string apiKey);

        // ---- queries -------------------------------------------------------

        /// Number of redeemed keys for this system.
        Result<std::size_t> redeemedUserCount();

        /// Redemption status of `license` (server returns a human-readable
        /// string; we forward it).
        Result<std::string> keyStatus(std::string_view license);

        /// Expiration date of `license`.
        Result<KeyExpiration> keyExpiration(std::string_view license);

        // ---- actions -------------------------------------------------------

        /// Reset HWID for a single key. When `asAdmin` is false the 30-day
        /// cooldown is enforced.
        Result<std::string> resetHwid(std::string_view license, bool asAdmin = true);

        // TOXIC
        /// Reset HWID for every key in the system. Be careful.
        Result<std::string> resetAllHwids();

        /// Generate one or more license keys. Returns the raw server response
        /// (typically the keys, one per line).
        Result<std::string> generateKeys(KeyExpiry expiry,
                                         std::size_t count = 1,
                                         std::string_view note = {});

        /// Permanently delete a key.
        Result<std::string> banKey(std::string_view license);

        /// Adjust a key's expiry. `newExpiry` is a date string the server
        /// understands (e.g. "2026-12-31"); set it to "0" to make a key
        /// permanent. `tz` is an IANA timezone such as "America/Chicago".
        Result<std::string> adjustExpiry(std::string_view license,
                                         std::string_view newExpiry,
                                         std::string_view tz);
        // TOXIC

    private:
        IHttpClient &http_;
        std::string baseUrl_;
        std::string apiKey_;
    };

} // namespace syslocker
