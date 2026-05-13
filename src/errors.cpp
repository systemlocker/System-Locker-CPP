#include "syslocker/errors.hpp"

#include "util.hpp"

#include <string_view>

namespace syslocker
{

    namespace
    {

        struct InitMap
        {
            std::string_view wire;
            InitError code;
        };

        constexpr InitMap kInit[] = {
            {"false", InitError::MissingField},
            {"no u/p", InitError::NoUserPass},
            {"no sys", InitError::NoSystem},
            {"dbe", InitError::DatabaseError},
            {"not verified", InitError::NotVerified},
            {"bad u/p", InitError::BadCredentials},
            {"bad keys", InitError::BadKeys},
            {"frozen", InitError::Frozen},
            {"spoofsuspected", InitError::SpoofSuspected},
            {"expired key", InitError::ExpiredKey},
            {"hwid", InitError::HwidMismatch},
            {"outdated", InitError::Outdated},
        };

        struct BeatMap
        {
            std::string_view wire;
            BeatError code;
        };

        constexpr BeatMap kBeat[] = {
            {"bad request", BeatError::BadRequest},
            {"bad session token", BeatError::BadSessionToken},
            {"stale token", BeatError::StaleToken},
            {"rate limit", BeatError::RateLimit},
            {"expired key", BeatError::ExpiredKey},
        };

    } // namespace

    const char *toString(InitError e) noexcept
    {
        switch (e)
        {
        case InitError::None:
            return "ok";
        case InitError::MissingField:
            return "missing field";
        case InitError::NoUserPass:
            return "no username or password";
        case InitError::NoSystem:
            return "no system id";
        case InitError::DatabaseError:
            return "server database error";
        case InitError::NotVerified:
            return "account not verified";
        case InitError::BadCredentials:
            return "bad credentials";
        case InitError::BadKeys:
            return "no key for this system";
        case InitError::Frozen:
            return "key is frozen";
        case InitError::SpoofSuspected:
            return "hwid is suspected of being spoofed";
        case InitError::ExpiredKey:
            return "expired key";
        case InitError::HwidMismatch:
            return "hwid mismatch";
        case InitError::Outdated:
            return "client outdated";
        case InitError::BadBeatRate:
            return "beat rate out of range";
        case InitError::Transport:
            return "transport error";
        case InitError::HashMismatch:
            return "response hash mismatch";
        case InitError::UsernameMismatch:
            return "username mismatch in response";
        case InitError::TimestampMismatch:
            return "timestamp mismatch in response";
        case InitError::Unknown:
            return "unknown response";
        }
        return "unknown";
    }

    const char *toString(BeatError e) noexcept
    {
        switch (e)
        {
        case BeatError::None:
            return "ok";
        case BeatError::BadRequest:
            return "bad request";
        case BeatError::BadSessionToken:
            return "bad session token";
        case BeatError::StaleToken:
            return "stale token";
        case BeatError::RateLimit:
            return "rate limit";
        case BeatError::ExpiredKey:
            return "expired key";
        case BeatError::Transport:
            return "transport error";
        case BeatError::TamperDetected:
            return "tamper detected";
        case BeatError::Unknown:
            return "unknown response";
        }
        return "unknown";
    }

    const char *toString(HeartbeatFailureCode c) noexcept
    {
        switch (c)
        {
        case HeartbeatFailureCode::BeatRejected:
            return "beat rejected";
        case HeartbeatFailureCode::Transport:
            return "transport error";
        case HeartbeatFailureCode::TamperDetected:
            return "tamper detected";
        }
        return "unknown";
    }

    InitError parseInitError(std::string_view body) noexcept
    {
        auto trimmed = detail::trim(body);
        if (trimmed.empty())
            return InitError::Unknown;

        // success token always begins with "TT"
        if (detail::startsWith(trimmed, "TT"))
            return InitError::None;

        // "beat rate ..." can have many tail variants
        auto lower = detail::toLowerCopy(trimmed);
        if (detail::startsWith(lower, "beat rate"))
            return InitError::BadBeatRate;

        for (const auto &[wire, code] : kInit)
        {
            if (lower == wire)
                return code;
        }
        return InitError::Unknown;
    }

    BeatError parseBeatError(std::string_view body) noexcept
    {
        auto trimmed = detail::trim(body);
        if (trimmed.empty())
            return BeatError::Unknown;
        if (detail::startsWith(trimmed, "TTr"))
            return BeatError::None;

        auto lower = detail::toLowerCopy(trimmed);
        for (const auto &[wire, code] : kBeat)
        {
            if (lower == wire)
                return code;
        }
        return BeatError::Unknown;
    }

} // namespace syslocker
