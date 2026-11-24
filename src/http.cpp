#include "syslocker/http.hpp"
#include <algorithm>
#include <cctype>

namespace syslocker
{
    std::string HttpResponse::header(std::string_view name) const
    {
        std::string normalized(name);
        std::transform(normalized.begin(), normalized.end(), normalized.begin(), [](unsigned char character)
                       { return static_cast<char>(std::tolower(character)); });
        const auto found = headers.find(normalized);
        if (found != headers.end())
            return found->second;

        for (const auto &[headerName, value] : headers)
        {
            if (headerName.size() != normalized.size())
                continue;
            const bool matches = std::equal(headerName.begin(), headerName.end(), normalized.begin(),
                                            [](unsigned char left, unsigned char right)
                                            {
                                                return std::tolower(left) == std::tolower(right);
                                            });
            if (matches)
                return value;
        }
        return {};
    }
}
