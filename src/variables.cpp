#include "syslocker/variables.hpp"

#include "syslocker/http.hpp"
#include "util.hpp"

namespace syslocker
{

    namespace
    {

        constexpr const char *kPath = "/auth/variable";

    } // namespace

    Variables::Variables(IHttpClient &http, std::string baseUrl, std::string systemId)
        : http_(http), baseUrl_(std::move(baseUrl)), systemId_(std::move(systemId)) {}

    Result<VariableValue> Variables::get(std::string_view name,
                                         std::optional<std::string> licenseKey)
    {
        FormFields form = {
            {"system", systemId_},
            {"variable", std::string(name)},
            {"clean", "1"}, // get a plain text response, not JSON
        };
        if (licenseKey)
        {
            form.push_back({"key", *licenseKey});
        }

        const auto resp = http_.post(baseUrl_ + kPath, form);
        if (!resp.ok())
        {
            return Result<VariableValue>::fail(
                resp.error.empty() ? ("http " + std::to_string(resp.status)) : resp.error);
        }

        auto body = std::string(detail::trim(resp.body));
        auto lower = detail::toLowerCopy(body);

        if (lower == "no sys" || lower == "no var" || lower == "dbe")
        {
            return Result<VariableValue>::fail(body);
        }
        if (lower == "false")
        {
            return VariableValue{false, {}};
        }
        return VariableValue{true, std::move(body)};
    }

} // namespace syslocker
