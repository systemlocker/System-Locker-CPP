#pragma once

#include "result.hpp"

#include <optional>
#include <string>

namespace syslocker
{

    class IHttpClient;

    struct VariableValue
    {
        bool intent = false; ///< true if the variable was found
        std::string value;   ///< only valid if intent == true
    };

    /// Wrapper around the /auth/variable endpoint.
    class Variables
    {
    public:
        Variables(IHttpClient &http, std::string baseUrl, std::string systemId);

        /// Fetch a server-side variable. If `licenseKey` is supplied it is sent
        /// with the request, allowing access to protected variables.
        Result<VariableValue> get(std::string_view name,
                                  std::optional<std::string> licenseKey = std::nullopt);

    private:
        IHttpClient &http_;
        std::string baseUrl_;
        std::string systemId_;
    };

} // namespace syslocker
