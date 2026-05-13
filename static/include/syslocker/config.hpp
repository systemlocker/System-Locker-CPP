#pragma once

#include <chrono>
#include <optional>
#include <string>

namespace syslocker
{

    /// User-controlled configuration for a Client. The Client takes a copy at
    /// construction; mutating this struct afterwards has no effect on the live
    /// session.
    struct Config
    {
        /// Hexadecimal system identifier from the System Locker dashboard.
        std::string systemId;

        /// Version string. Default of "bypass" disables version checking on
        /// Quicksilver, which is the documented recommendation. Set to a real
        /// version string to enforce.
        std::string version = "bypass";

        /// Hardware identifier. Use "1" (or any fixed value) to disable device
        /// locking entirely.
        std::string hwid = "1";

        /// Heartbeat cadence. Must be in [25, 3600] seconds. Default 30s.
        std::chrono::seconds beatRate{30};

        /// Per-request timeout for the underlying HTTP client.
        std::chrono::milliseconds requestTimeout{15000};

        /// Optional: base64-encoded SHA-256 of the System Locker server's
        /// public key (subject public key info). Format compatible with curl's
        /// CURLOPT_PINNEDPUBLICKEY: "sha256//<base64>". When set, any TLS
        /// session that does not match this pin will be aborted, which defends
        /// against attackers spoofing the systemlocker.net certificate.
        std::optional<std::string> pinnedPublicKeySha256Base64;

        /// User-Agent string sent with every request.
        std::string userAgent = "syslocker-cpp/1.0";

        /// When true (default) the heartbeat thread will check for attached
        /// debuggers each beat. Detection terminates the session and fires
        /// the failure hook with HeartbeatFailureCode::TamperDetected.
        bool enableAntiDebug = true;

        /// API key for the management API (NOT the user's license key, NOT the
        /// system ID). Required only if you call Client::management() functions.
        std::string apiKey;

        /// Override the API base URL. Defaults to https://systemlocker.net.
        /// Useful for testing against staging environments. Plain http:// is
        /// rejected unless you also disable strict TLS via a custom HTTP client.
        std::string baseUrl = "https://systemlocker.net";
    };

} // namespace syslocker
