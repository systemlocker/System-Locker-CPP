#pragma once

#include <chrono>
#include <memory>
#include <map>
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

        std::map<std::string, std::string> headers; ///< response headers, case-insensitive lookup

        std::string header(std::string_view name) const;

        bool ok() const noexcept { return status >= 200 && status < 300 && error.empty(); }
    };

    using FormFields = std::vector<std::pair<std::string, std::string>>;

    /// Abstraction over HTTP so transport details (libcurl, mocks, custom
    /// stacks) can be swapped without touching the API logic. All System Locker
    /// authentication uses forms; Management v2 uses JSON and bearer headers.
    using HttpHeaders = std::vector<std::pair<std::string, std::string>>;

    class IHttpClient
    {
    public:
        virtual ~IHttpClient() = default;

        /// Perform an HTTPS POST. Implementations MUST refuse plain HTTP unless
        /// the caller has explicitly opted in.
        virtual HttpResponse post(std::string_view url,
                                  const FormFields &form) = 0;

        /// HTTPS request with explicit headers and an optional JSON body.
        /// Override for Management v2 and Invisible Folder downloads. The
        /// default preserves source compatibility for form-only transports.
        virtual HttpResponse request(std::string_view method, std::string_view url,
                                     std::string_view body, const HttpHeaders &headers)
        {
            (void)method; (void)url; (void)body; (void)headers;
            HttpResponse response;
            response.error = "HTTP client must implement request() for this operation";
            return response;
        }
    };

    /// Settings for the libcurl-backed HTTP client.
    struct CurlHttpOptions
    {
        std::chrono::milliseconds timeout{15000};
        std::string userAgent = "syslocker-cpp/2.0.0";
        /// Optional curl-style pinned public key, e.g. "sha256//abc...=".
        std::string pinnedPublicKey;
    };

    /// Construct the default libcurl-backed client. Uses the system CA bundle,
    /// enforces TLS 1.2+, and (when configured) pins the server public key.
    std::unique_ptr<IHttpClient> makeCurlHttpClient(CurlHttpOptions opts = {});

} // namespace syslocker
