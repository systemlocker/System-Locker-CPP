#pragma once

#include <string>

namespace syslocker
{

    /// Documented Quicksilver init-time errors plus a transport bucket and an
    /// "unknown" bucket for forward compatibility. Convert to/from the wire
    /// strings via the helpers below.
    enum class InitError
    {
        None = 0,
        MissingField,      ///< "false"
        NoUserPass,        ///< "no u/p"
        NoSystem,          ///< "no sys"
        DatabaseError,     ///< "dbe"
        NotVerified,       ///< "not verified"
        BadCredentials,    ///< "bad u/p"
        BadKeys,           ///< "bad keys"
        Frozen,            ///< "frozen"
        SpoofSuspected,    ///< "spoofsuspected"
        ExpiredKey,        ///< "expired key"
        HwidMismatch,      ///< "hwid"
        Outdated,          ///< "outdated"
        BadBeatRate,       ///< "beat rate ..."
        Transport,         ///< network / TLS / non-2xx
        HashMismatch,      ///< response failed local SHA-1 verification
        UsernameMismatch,  ///< server's username didn't match request
        TimestampMismatch, ///< response timestamp drift exceeded tolerance
        Unknown,
    };

    /// Documented Quicksilver heartbeat errors.
    enum class BeatError
    {
        None = 0,
        BadRequest,      ///< "bad request"
        BadSessionToken, ///< "bad session token"
        StaleToken,      ///< "stale token"
        RateLimit,       ///< "rate limit"
        ExpiredKey,      ///< "expired key"
        Transport,       ///< network / TLS / non-2xx
        TamperDetected,  ///< local debugger / spoof detection tripped
        Unknown,
    };

    /// Reason a heartbeat failure hook was invoked.
    enum class HeartbeatFailureCode
    {
        BeatRejected, ///< server rejected the heartbeat for any reason
        Transport,
        TamperDetected,
    };

    struct HeartbeatFailure
    {
        HeartbeatFailureCode code;
        BeatError beatError;      ///< populated when code == BeatRejected
        std::string message;      ///< raw server response or diagnostic text
        std::uint64_t beatNumber; ///< how many heartbeats had succeeded
    };

    const char *toString(InitError) noexcept;
    const char *toString(BeatError) noexcept;
    const char *toString(HeartbeatFailureCode) noexcept;

    /// Map a server response string to an InitError, ignoring case and trailing
    /// whitespace. Returns InitError::Unknown if no match.
    InitError parseInitError(std::string_view body) noexcept;

    /// Same, for the heartbeat endpoint.
    BeatError parseBeatError(std::string_view body) noexcept;

} // namespace syslocker
