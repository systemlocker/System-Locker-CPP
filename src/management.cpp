#include "syslocker/management.hpp"

#include "syslocker/http.hpp"
#include "util.hpp"

#include <charconv>

namespace syslocker
{

    namespace
    {

        constexpr const char *kPath = "/api/v1";

        const char *expiryWire(KeyExpiry e) noexcept
        {
            switch (e)
            {
            case KeyExpiry::Permanent:
                return "0";
            case KeyExpiry::OneDay:
                return "1";
            case KeyExpiry::OneWeek:
                return "2";
            case KeyExpiry::OneMonth:
                return "3";
            case KeyExpiry::ThreeMonths:
                return "4";
            case KeyExpiry::OneYear:
                return "5";
            }
            return "0";
        }

    } // namespace

    Management::Management(IHttpClient &http, std::string baseUrl, std::string apiKey)
        : http_(http), baseUrl_(std::move(baseUrl)), apiKey_(std::move(apiKey)) {}

    namespace
    {

        Result<std::string> doPost(IHttpClient &http,
                                   const std::string &url,
                                   const FormFields &fields)
        {
            const auto resp = http.post(url, fields);
            if (!resp.error.empty())
            {
                return Result<std::string>::fail(resp.error);
            }
            if (resp.status < 200 || resp.status >= 300)
            {
                return Result<std::string>::fail(
                    "http " + std::to_string(resp.status) + ": " + resp.body);
            }
            return std::string(detail::trim(resp.body));
        }

    } // namespace

    Result<std::size_t> Management::redeemedUserCount()
    {
        if (apiKey_.empty())
            return Result<std::size_t>::fail("management api key not configured");
        auto raw = doPost(http_, baseUrl_ + kPath, {{"key", apiKey_}, {"select", "users"}});
        if (!raw)
            return Result<std::size_t>::fail(raw.error());

        std::size_t value = 0;
        auto sv = detail::trim(*raw);
        auto [ptr, ec] = std::from_chars(sv.data(), sv.data() + sv.size(), value);
        if (ec != std::errc{})
        {
            return Result<std::size_t>::fail("non-numeric users response: " + *raw);
        }
        return value;
    }

    Result<std::string> Management::keyStatus(std::string_view license)
    {
        if (apiKey_.empty())
            return Result<std::string>::fail("management api key not configured");
        return doPost(http_, baseUrl_ + kPath, {
                                                   {"key", apiKey_},
                                                   {"select", "key"},
                                                   {"lkey", std::string(license)},
                                               });
    }

    Result<KeyExpiration> Management::keyExpiration(std::string_view license)
    {
        if (apiKey_.empty())
            return Result<KeyExpiration>::fail("management api key not configured");
        auto raw = doPost(http_, baseUrl_ + kPath, {
                                                       {"key", apiKey_},
                                                       {"select", "expiration"},
                                                       {"lkey", std::string(license)},
                                                   });
        if (!raw)
            return Result<KeyExpiration>::fail(raw.error());

        KeyExpiration k;
        k.raw = *raw;
        auto lower = detail::toLowerCopy(k.raw);
        k.permanent = (lower == "permanent" || lower == "0" || lower == "never");
        return k;
    }

    Result<std::string> Management::resetHwid(std::string_view license, bool asAdmin)
    {
        if (apiKey_.empty())
            return Result<std::string>::fail("management api key not configured");
        FormFields f = {
            {"key", apiKey_},
            {"command", "hwidreset"},
            {"license", std::string(license)},
        };
        if (!asAdmin)
            f.push_back({"as_admin", "false"});
        return doPost(http_, baseUrl_ + kPath, f);
    }

    // TOXIC
    Result<std::string> Management::resetAllHwids()
    {
        if (apiKey_.empty())
            return Result<std::string>::fail("management api key not configured");
        return doPost(http_, baseUrl_ + kPath, {
                                                   {"key", apiKey_},
                                                   {"command", "systemhwidreset"},
                                               });
    }

    Result<std::string> Management::generateKeys(KeyExpiry expiry,
                                                 std::size_t count,
                                                 std::string_view note)
    {
        if (apiKey_.empty())
            return Result<std::string>::fail("management api key not configured");
        if (count == 0 || count > 100)
        {
            return Result<std::string>::fail("count must be in [1, 100]");
        }
        FormFields f = {
            {"key", apiKey_},
            {"command", "genkeys"},
            {"expire", expiryWire(expiry)},
            {"count", std::to_string(count)},
        };
        if (!note.empty())
        {
            if (note.size() > 250)
            {
                return Result<std::string>::fail("note must be at most 250 characters");
            }
            f.push_back({"note", std::string(note)});
        }
        return doPost(http_, baseUrl_ + kPath, f);
    }

    Result<std::string> Management::banKey(std::string_view license)
    {
        if (apiKey_.empty())
            return Result<std::string>::fail("management api key not configured");
        return doPost(http_, baseUrl_ + kPath, {
                                                   {"key", apiKey_},
                                                   {"command", "bankey"},
                                                   {"license", std::string(license)},
                                               });
    }

    Result<std::string> Management::adjustExpiry(std::string_view license,
                                                 std::string_view newExpiry,
                                                 std::string_view tz)
    {
        if (apiKey_.empty())
            return Result<std::string>::fail("management api key not configured");
        return doPost(http_, baseUrl_ + kPath, {
                                                   {"key", apiKey_},
                                                   {"command", "adjustexpiry"},
                                                   {"license", std::string(license)},
                                                   {"newexpiry", std::string(newExpiry)},
                                                   {"tz", std::string(tz)},
                                               });
    }
    // TOXIC

} // namespace syslocker
