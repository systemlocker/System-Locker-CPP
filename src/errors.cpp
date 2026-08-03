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
            {"no key", InitError::NoKey},
            {"no sys", InitError::NoSystem},
            {"dbe", InitError::DatabaseError},
            {"not verified", InitError::NotVerified},
            {"bad u/p", InitError::BadCredentials},
            {"bad key", InitError::BadKey},
            {"bad keys", InitError::BadKeys},
            {"paused", InitError::Paused},
            {"frozen", InitError::Frozen},
            {"banned", InitError::Banned},
            {"hwid banned", InitError::HwidBanned},
            {"spoofsuspected", InitError::SpoofSuspected},
            {"destitute", InitError::DeveloperPlanInactive},
            {"no production", InitError::NoProductionAccess},
            {"user limit", InitError::UserLimit},
            {"expired key", InitError::ExpiredKey},
            {"hwid", InitError::HwidMismatch},
            {"outdated", InitError::Outdated},
            {"digest", InitError::DigestMismatch},
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
            return "Authentication succeeded";
        case InitError::MissingField:
            return "Required authentication information is missing";
        case InitError::NoUserPass:
            return "A username and password are required";
        case InitError::NoKey:
            return "A license key is required";
        case InitError::NoSystem:
            return "A System Locker system ID is required";
        case InitError::DatabaseError:
            return "System Locker could not complete authentication";
        case InitError::NotVerified:
            return "The email for this account must be verified before signing in";
        case InitError::BadCredentials:
            return "The username or password is incorrect";
        case InitError::BadKey:
            return "This license key is invalid for the selected system";
        case InitError::BadKeys:
            return "This account does not have a valid key for this system";
        case InitError::Paused:
            return "This system is currently paused by its creator";
        case InitError::Frozen:
            return "This license key has been frozen";
        case InitError::Banned:
            return "This device was blocked by the application creator";
        case InitError::HwidBanned:
            return "This device was blocked by the application creator";
        case InitError::SpoofSuspected:
            return "This device was blocked by the application creator";
        case InitError::DeveloperPlanInactive:
            return "Authentication is unavailable; please contact the application creator";
        case InitError::NoProductionAccess:
            return "This system is not enabled for production authentication";
        case InitError::UserLimit:
            return "This system has reached its active-user limit; please contact the application creator";
        case InitError::ExpiredKey:
            return "This license key has expired";
        case InitError::HwidMismatch:
            return "This license key is registered to a different device";
        case InitError::Outdated:
            return "This application version is no longer supported";
        case InitError::DigestMismatch:
            return "The application integrity check did not match";
        case InitError::BadBeatRate:
            return "The requested heartbeat interval is outside the allowed range";
        case InitError::Transport:
            return "System Locker could not be reached";
        case InitError::HashMismatch:
            return "The authentication response failed its integrity check";
        case InitError::UsernameMismatch:
            return "Invalid indentification";
        case InitError::TimestampMismatch:
            return "A critical error occurred and the application could not be authenticated; please restart the application and try again";
        case InitError::Unknown:
            return "System Locker returned an unrecognized authentication response";
        }
        return "Authentication failed for an unknown reason";
    }

    const char *toString(BeatError e) noexcept
    {
        switch (e)
        {
        case BeatError::None:
            return "Heartbeat accepted";
        case BeatError::BadRequest:
            return "The heartbeat request is missing required information";
        case BeatError::BadSessionToken:
            return "The authentication session is no longer valid";
        case BeatError::StaleToken:
            return "The authentication session expired after a missed heartbeat";
        case BeatError::Terminated:
            return "The developer ended this authentication session";
        case BeatError::RateLimit:
            return "The heartbeat was sent too soon";
        case BeatError::ExpiredKey:
            return "The license key expired during this session";
        case BeatError::Transport:
            return "System Locker could not be reached for the heartbeat";
        case BeatError::TamperDetected:
            return "The application integrity check detected tampering";
        case BeatError::Unknown:
            return "System Locker returned an unrecognized heartbeat response";
        }
        return "The heartbeat failed for an unknown reason";
    }

    const char *toString(HeartbeatFailureCode c) noexcept
    {
        switch (c)
        {
        case HeartbeatFailureCode::BeatRejected:
            return "The heartbeat was rejected by System Locker";
        case HeartbeatFailureCode::Transport:
            return "The heartbeat could not reach System Locker";
        case HeartbeatFailureCode::TamperDetected:
            return "The application integrity check detected tampering";
        }
        return "The heartbeat failed for an unknown reason";
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
        if (detail::startsWith(lower, "terminated ") || lower == "terminated")
            return BeatError::Terminated;
        for (const auto &[wire, code] : kBeat)
        {
            if (lower == wire)
                return code;
        }
        return BeatError::Unknown;
    }

} // namespace syslocker
