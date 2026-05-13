#include "util.hpp"

#include <cctype>

namespace syslocker::detail
{

    std::string toLowerCopy(std::string_view sv)
    {
        std::string out(sv);
        for (auto &c : out)
        {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        return out;
    }

    std::string_view trim(std::string_view sv) noexcept
    {
        auto isSpace = [](unsigned char c)
        {
            return c == ' ' || c == '\t' || c == '\r' || c == '\n';
        };
        while (!sv.empty() && isSpace(static_cast<unsigned char>(sv.front())))
            sv.remove_prefix(1);
        while (!sv.empty() && isSpace(static_cast<unsigned char>(sv.back())))
            sv.remove_suffix(1);
        return sv;
    }

    std::string urlEncode(std::string_view sv)
    {
        static constexpr char hex[] = "0123456789ABCDEF";
        std::string out;
        out.reserve(sv.size());
        for (unsigned char c : sv)
        {
            const bool unreserved = (c >= 'A' && c <= 'Z') ||
                                    (c >= 'a' && c <= 'z') ||
                                    (c >= '0' && c <= '9') ||
                                    c == '-' || c == '_' || c == '.' || c == '~';
            if (unreserved)
            {
                out.push_back(static_cast<char>(c));
            }
            else
            {
                out.push_back('%');
                out.push_back(hex[c >> 4]);
                out.push_back(hex[c & 0x0F]);
            }
        }
        return out;
    }

    std::string encodeForm(const std::vector<std::pair<std::string, std::string>> &fields)
    {
        std::string body;
        bool first = true;
        for (const auto &[k, v] : fields)
        {
            if (!first)
                body.push_back('&');
            first = false;
            body += urlEncode(k);
            body.push_back('=');
            body += urlEncode(v);
        }
        return body;
    }

    std::pair<std::string_view, std::string_view> splitFirst(std::string_view sv, char delim) noexcept
    {
        auto pos = sv.find(delim);
        if (pos == std::string_view::npos)
            return {sv, {}};
        return {sv.substr(0, pos), sv.substr(pos + 1)};
    }

    bool startsWith(std::string_view sv, std::string_view prefix) noexcept
    {
        return sv.size() >= prefix.size() &&
               sv.compare(0, prefix.size(), prefix) == 0;
    }

} // namespace syslocker::detail
