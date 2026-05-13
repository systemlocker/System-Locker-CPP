#pragma once

#include <chrono>
#include <memory>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace syslocker
{

    struct HttpResponse
    {
        long status = 0; ///< HTTP status code, 0 if request never reached the server
        std::string body;
        std::string error; ///< non-empty if a transport-level failure occurred

        bool ok() const noexcept { return status >= 200 && status < 300 && error.empty(); }
    };

    using FormFields = std::vector<std::pair<std::string, std::string>>;

    /// Abstraction over HTTP so transport details (libcurl, mocks, custom
    /// stacks) can be swapped without touching the API logic. All System Locker
    /// endpoints take POST with application/x-www-form-urlencoded bodies.
    class IHttpClient
    {
    public:
        virtual ~IHttpClient() = default;

        /// Perform an HTTPS POST. Implementations MUST refuse plain HTTP unless
        /// the caller has explicitly opted in.
        virtual HttpResponse post(std::string_view url,
                                  const FormFields &form) = 0;
    };

    /// Settings for the libcurl-backed HTTP client.
    struct CurlHttpOptions
    {
        std::chrono::milliseconds timeout{15000};
        std::string userAgent = "syslocker-cpp/1.0";
        /// Optional curl-style pinned public key, e.g. "sha256//abc...=".
        std::string pinnedPublicKey;
    };

    /// Construct the default libcurl-backed client. Uses the system CA bundle,
    /// enforces TLS 1.2+, and (when configured) pins the server public key.
    std::unique_ptr<IHttpClient> makeCurlHttpClient(CurlHttpOptions opts = {});

} // namespace syslocker
