#pragma once

#include <string>
#include <string_view>
#include <utility>
#include <vector>

namespace syslocker::detail
{

    /// Lowercase ASCII view-of helpers — locale-free, no allocation in trim.
    std::string toLowerCopy(std::string_view sv);
    std::string_view trim(std::string_view sv) noexcept;

    /// RFC 3986 percent-encoder for application/x-www-form-urlencoded values.
    /// Spaces are encoded as %20 (NOT '+') for safety with both web servers
    /// and CGI dispatchers.
    std::string urlEncode(std::string_view sv);

    /// Build "k1=v1&k2=v2..." from form fields with proper escaping.
    std::string encodeForm(const std::vector<std::pair<std::string, std::string>> &fields);

    /// Split helper — splits at the FIRST occurrence of `delim`. Returns the
    /// part before and after; if not found, second is empty.
    std::pair<std::string_view, std::string_view> splitFirst(std::string_view sv, char delim) noexcept;

    /// True if `sv` starts with `prefix` (case-sensitive).
    bool startsWith(std::string_view sv, std::string_view prefix) noexcept;

} // namespace syslocker::detail
