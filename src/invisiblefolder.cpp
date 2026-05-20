#include "syslocker/invisiblefolder.hpp"

#include "sha1.hpp"
#include "syslocker/http.hpp"
#include "util.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <optional>
#include <sstream>
#include <string>
#include <utility>

namespace syslocker
{

    namespace
    {

        constexpr const char *kInitIfPath = "/auth/quicksilver/init-if";
        constexpr const char *kDownloadPrefix = "/a/";
        constexpr auto kExpiryBuffer = std::chrono::seconds(10);

        void wipeString(std::string &value) noexcept
        {
            std::fill(value.begin(), value.end(), '\0');
            value.clear();
        }

        void wipeFormFields(FormFields &fields) noexcept
        {
            for (auto &field : fields)
            {
                wipeString(field.second);
            }
            fields.clear();
        }

        bool eqIgnoreCase(std::string_view a, std::string_view b)
        {
            if (a.size() != b.size())
                return false;
            for (std::size_t i = 0; i < a.size(); ++i)
            {
                const unsigned char ca = static_cast<unsigned char>(a[i]);
                const unsigned char cb = static_cast<unsigned char>(b[i]);
                if (std::tolower(ca) != std::tolower(cb))
                    return false;
            }
            return true;
        }

        struct WrappedPayload
        {
            bool ok = false;
            std::vector<std::string_view> fields;
        };

        WrappedPayload parseWrapped(std::string_view body)
        {
            WrappedPayload wrapped;

            const auto colon = body.rfind(':');
            if (colon == std::string_view::npos)
                return wrapped;

            const auto payload = body.substr(0, colon);
            const auto hash = detail::trim(body.substr(colon + 1));
            if (!eqIgnoreCase(detail::Sha1::hex(payload), hash))
                return wrapped;

            std::string_view rest = payload;
            while (true)
            {
                const auto bar = rest.find('|');
                if (bar == std::string_view::npos)
                {
                    wrapped.fields.push_back(rest);
                    break;
                }
                wrapped.fields.push_back(rest.substr(0, bar));
                rest.remove_prefix(bar + 1);
            }

            wrapped.ok = true;
            return wrapped;
        }

        std::optional<std::chrono::system_clock::time_point> parseUtcTimestamp(std::string_view raw)
        {
            raw = detail::trim(raw);
            if (raw.empty())
                return std::nullopt;

            const auto parseWithFormat = [&](std::string_view value, const char *format) -> std::optional<std::chrono::system_clock::time_point>
            {
                std::tm tm{};
                std::istringstream input{std::string(value)};
                input >> std::get_time(&tm, format);
                if (input.fail())
                    return std::nullopt;

#if defined(_WIN32)
                const std::time_t asTimeT = _mkgmtime(&tm);
#else
                const std::time_t asTimeT = timegm(&tm);
#endif
                if (asTimeT == static_cast<std::time_t>(-1))
                    return std::nullopt;

                return std::chrono::system_clock::from_time_t(asTimeT);
            };

            const auto allDigits = std::all_of(raw.begin(), raw.end(), [](unsigned char ch)
                                               { return std::isdigit(ch) != 0; });
            if (allDigits)
            {
                try
                {
                    const auto parsed = std::stoll(std::string(raw));
                    if (raw.size() >= 13)
                    {
                        return std::chrono::system_clock::time_point{std::chrono::milliseconds(parsed)};
                    }
                    return std::chrono::system_clock::time_point{std::chrono::seconds(parsed)};
                }
                catch (...)
                {
                    return std::nullopt;
                }
            }

            std::string normalized(raw);

            if (!normalized.empty() && (normalized.back() == 'Z' || normalized.back() == 'z'))
            {
                normalized.pop_back();
            }

            const auto dot = normalized.find('.');
            if (dot != std::string::npos)
            {
                normalized.erase(dot);
            }

            if (auto parsed = parseWithFormat(normalized, "%Y-%m-%d %H:%M:%S"))
                return parsed;
            if (auto parsed = parseWithFormat(normalized, "%Y-%m-%dT%H:%M:%S"))
                return parsed;

            return std::nullopt;
        }

        std::string decodeJsonString(std::string_view raw)
        {
            std::string decoded;
            decoded.reserve(raw.size());

            bool escape = false;
            for (char ch : raw)
            {
                if (!escape)
                {
                    if (ch == '\\')
                    {
                        escape = true;
                        continue;
                    }
                    decoded.push_back(ch);
                    continue;
                }

                switch (ch)
                {
                case '\\':
                case '"':
                case '/':
                    decoded.push_back(ch);
                    break;
                case 'b':
                    decoded.push_back('\b');
                    break;
                case 'f':
                    decoded.push_back('\f');
                    break;
                case 'n':
                    decoded.push_back('\n');
                    break;
                case 'r':
                    decoded.push_back('\r');
                    break;
                case 't':
                    decoded.push_back('\t');
                    break;
                default:
                    decoded.push_back(ch);
                    break;
                }
                escape = false;
            }

            return decoded;
        }

        std::string extractJsonString(std::string_view json, std::string_view key)
        {
            const std::string pattern = "\"" + std::string(key) + "\"";
            const auto keyPos = json.find(pattern);
            if (keyPos == std::string_view::npos)
                return {};

            auto colon = json.find(':', keyPos + pattern.size());
            if (colon == std::string_view::npos)
                return {};
            ++colon;
            while (colon < json.size() && std::isspace(static_cast<unsigned char>(json[colon])))
                ++colon;
            if (colon >= json.size() || json[colon] != '"')
                return {};

            ++colon;
            std::size_t end = colon;
            bool escape = false;
            for (; end < json.size(); ++end)
            {
                const char ch = json[end];
                if (escape)
                {
                    escape = false;
                    continue;
                }
                if (ch == '\\')
                {
                    escape = true;
                    continue;
                }
                if (ch == '"')
                    break;
            }
            if (end >= json.size())
                return {};

            return decodeJsonString(json.substr(colon, end - colon));
        }

        std::string formatDownloadError(const HttpResponse &resp)
        {
            if (!resp.error.empty())
                return resp.error;

            const auto body = detail::trim(resp.body);
            const std::string human = extractJsonString(body, "error_human");
            if (!human.empty())
                return "http " + std::to_string(resp.status) + ": " + human;

            const std::string machine = extractJsonString(body, "error");
            if (!machine.empty())
                return "http " + std::to_string(resp.status) + ": " + machine;

            if (!body.empty())
                return "http " + std::to_string(resp.status) + ": " + std::string(body);

            return "http " + std::to_string(resp.status);
        }

        bool shouldRefreshAfterDownloadFailure(const HttpResponse &resp) noexcept
        {
            return resp.error.empty() && resp.status == 403;
        }

    } // namespace

    InvisibleFolder::InvisibleFolder(IHttpClient &http,
                                     std::string systemLockerBaseUrl,
                                     std::string invisibleFolderBaseUrl,
                                     std::string systemId,
                                     std::string hwid,
                                     std::function<bool()> sessionActive)
        : http_(http),
          systemLockerBaseUrl_(std::move(systemLockerBaseUrl)),
          invisibleFolderBaseUrl_(std::move(invisibleFolderBaseUrl)),
          systemId_(std::move(systemId)),
          hwid_(std::move(hwid)),
          sessionActive_(std::move(sessionActive))
    {
    }

    bool InvisibleFolder::hasValidToken() const
    {
        std::lock_guard<std::mutex> lk(stateMtx_);
        if (token_.empty() || !hasTokenExpiry_)
            return false;
        return std::chrono::system_clock::now() + kExpiryBuffer < tokenExpiresAtTime_;
    }

    Result<void> InvisibleFolder::ensureToken()
    {
        if (!sessionActive_ || !sessionActive_())
            return Result<void>::fail("client is not authenticated");

        struct RefreshSnapshot
        {
            AuthMode authMode = AuthMode::None;
            std::string username;
            std::string password;
            std::string licenseKey;
            std::uint64_t stateVersion = 0;
            std::uint64_t refreshGeneration = 0;

            ~RefreshSnapshot()
            {
                wipeString(username);
                wipeString(password);
                wipeString(licenseKey);
            }
        };

        struct ScopedFormWipe
        {
            FormFields &fields;

            ~ScopedFormWipe()
            {
                wipeFormFields(fields);
            }
        };

        struct ScopedStringWipe
        {
            std::string &value;

            ~ScopedStringWipe()
            {
                wipeString(value);
            }
        };

        auto finalizeRefreshFailure = [this](std::uint64_t expectedVersion,
                                             std::uint64_t expectedRefreshGeneration,
                                             std::string message) -> Result<void>
        {
            {
                std::lock_guard<std::mutex> lk(stateMtx_);
                if (stateVersion_ == expectedVersion && refreshGeneration_ == expectedRefreshGeneration)
                {
                    refreshInFlight_ = false;
                    lastRefreshGeneration_ = expectedRefreshGeneration;
                    lastRefreshSucceeded_ = false;
                    lastRefreshError_ = message;
                }
            }
            stateCv_.notify_all();
            return Result<void>::fail(std::move(message));
        };

        RefreshSnapshot snapshot;
        {
            std::unique_lock<std::mutex> lk(stateMtx_);
            while (true)
            {
                if (!token_.empty() && hasTokenExpiry_ &&
                    std::chrono::system_clock::now() + kExpiryBuffer < tokenExpiresAtTime_)
                {
                    return Result<void>{};
                }

                if (refreshInFlight_)
                {
                    const auto observedRefreshGeneration = refreshGeneration_;
                    stateCv_.wait(lk, [this]
                                  { return !refreshInFlight_; });
                    if (!sessionActive_ || !sessionActive_())
                        return Result<void>::fail("client is not authenticated");

                    if (!token_.empty() && hasTokenExpiry_ &&
                        std::chrono::system_clock::now() + kExpiryBuffer < tokenExpiresAtTime_)
                    {
                        return Result<void>{};
                    }

                    if (lastRefreshGeneration_ == observedRefreshGeneration && !lastRefreshSucceeded_)
                    {
                        const std::string msg = lastRefreshError_.empty()
                                                    ? std::string("Invisible Folder token refresh failed")
                                                    : lastRefreshError_;
                        return Result<void>::fail(msg);
                    }
                    continue;
                }

                switch (authMode_)
                {
                case AuthMode::Password:
                    if (username_.empty() || password_.empty())
                        return Result<void>::fail("missing cached account credentials for Invisible Folder refresh");
                    snapshot.authMode = authMode_;
                    snapshot.username = username_;
                    snapshot.password = password_;
                    snapshot.stateVersion = stateVersion_;
                    break;
                case AuthMode::Key:
                    if (licenseKey_.empty())
                        return Result<void>::fail("missing cached license key for Invisible Folder refresh");
                    snapshot.authMode = authMode_;
                    snapshot.licenseKey = licenseKey_;
                    snapshot.stateVersion = stateVersion_;
                    break;
                case AuthMode::None:
                    return Result<void>::fail("client has not authenticated for Invisible Folder access");
                }

                refreshInFlight_ = true;
                snapshot.refreshGeneration = ++refreshGeneration_;
                break;
            }
        }

        FormFields form = {{"system", systemId_}, {"hwid", hwid_}};
        ScopedFormWipe wipeForm{form};
        std::string expectedIdentity;
        ScopedStringWipe wipeExpectedIdentity{expectedIdentity};
        if (snapshot.authMode == AuthMode::Password)
        {
            form.emplace_back("username", snapshot.username);
            form.emplace_back("password", snapshot.password);
            expectedIdentity = snapshot.username;
        }
        else if (snapshot.authMode == AuthMode::Key)
        {
            form.emplace_back("key", snapshot.licenseKey);
            expectedIdentity = snapshot.licenseKey;
        }

        if (!sessionActive_ || !sessionActive_())
            return finalizeRefreshFailure(snapshot.stateVersion,
                                          snapshot.refreshGeneration,
                                          "client is not authenticated");

        const auto resp = http_.post(systemLockerBaseUrl_ + kInitIfPath, form);
        if (!resp.ok())
        {
            return finalizeRefreshFailure(
                snapshot.stateVersion,
                snapshot.refreshGeneration,
                resp.error.empty() ? ("http " + std::to_string(resp.status)) : resp.error);
        }

        const auto body = std::string(detail::trim(resp.body));
        const auto wrapped = parseWrapped(body);
        if (!wrapped.ok)
        {
            if (body.find(':') != std::string::npos)
                return finalizeRefreshFailure(snapshot.stateVersion,
                                              snapshot.refreshGeneration,
                                              "Invisible Folder token response failed sha1 integrity check");
            return finalizeRefreshFailure(snapshot.stateVersion,
                                          snapshot.refreshGeneration,
                                          "Invisible Folder token response was not wrapped");
        }
        if (wrapped.fields.size() != 5)
            return finalizeRefreshFailure(snapshot.stateVersion,
                                          snapshot.refreshGeneration,
                                          "Invisible Folder token response had an unexpected field count");
        if (!eqIgnoreCase(wrapped.fields[2], systemId_))
            return finalizeRefreshFailure(snapshot.stateVersion,
                                          snapshot.refreshGeneration,
                                          "Invisible Folder token response returned a different system id");
        if (!expectedIdentity.empty() && !eqIgnoreCase(wrapped.fields[3], expectedIdentity))
            return finalizeRefreshFailure(snapshot.stateVersion,
                                          snapshot.refreshGeneration,
                                          "Invisible Folder token response returned a different identity than requested");

        const auto expiresAt = parseUtcTimestamp(wrapped.fields[1]);
        if (!expiresAt)
            return finalizeRefreshFailure(snapshot.stateVersion,
                                          snapshot.refreshGeneration,
                                          "Invisible Folder token response had an invalid expires_at timestamp");

        bool completed = false;
        bool authLost = false;
        {
            std::lock_guard<std::mutex> lk(stateMtx_);
            if (stateVersion_ != snapshot.stateVersion ||
                refreshGeneration_ != snapshot.refreshGeneration ||
                !sessionActive_ || !sessionActive_())
            {
                if (refreshGeneration_ == snapshot.refreshGeneration)
                {
                    refreshInFlight_ = false;
                    lastRefreshGeneration_ = snapshot.refreshGeneration;
                    lastRefreshSucceeded_ = false;
                    lastRefreshError_ = "client is not authenticated";
                }
                completed = true;
                authLost = true;
            }
            else
            {
                token_ = std::string(wrapped.fields[0]);
                tokenExpiresAt_ = std::string(wrapped.fields[1]);
                tokenExpiresAtTime_ = *expiresAt;
                hasTokenExpiry_ = true;
                refreshInFlight_ = false;
                lastRefreshGeneration_ = snapshot.refreshGeneration;
                lastRefreshSucceeded_ = true;
                wipeString(lastRefreshError_);
                completed = true;
            }
        }
        if (completed)
            stateCv_.notify_all();
        if (authLost)
            return Result<void>::fail("client is not authenticated");
        return Result<void>{};
    }

    Result<std::vector<std::uint8_t>> InvisibleFolder::download(std::string_view referenceId)
    {
        if (referenceId.empty())
            return Result<std::vector<std::uint8_t>>::fail("reference id is required");

        for (int attempt = 0; attempt < 2; ++attempt)
        {
            auto tokenReady = ensureToken();
            if (!tokenReady.ok())
                return Result<std::vector<std::uint8_t>>::fail(tokenReady.error());

            if (!sessionActive_ || !sessionActive_())
                return Result<std::vector<std::uint8_t>>::fail("client is not authenticated");

            std::string token;
            {
                std::lock_guard<std::mutex> lk(stateMtx_);
                if (token_.empty() || !hasTokenExpiry_ ||
                    std::chrono::system_clock::now() + kExpiryBuffer >= tokenExpiresAtTime_)
                {
                    return Result<std::vector<std::uint8_t>>::fail(
                        "Invisible Folder token is not available");
                }
                token = token_;
            }

            if (!sessionActive_ || !sessionActive_())
                return Result<std::vector<std::uint8_t>>::fail("client is not authenticated");

            const FormFields form = {{"invisiblefolder_token", token}};
            const auto resp = http_.post(
                invisibleFolderBaseUrl_ + kDownloadPrefix + detail::urlEncode(referenceId),
                form);
            if (resp.ok())
            {
                const auto *begin = reinterpret_cast<const std::uint8_t *>(resp.body.data());
                return std::vector<std::uint8_t>(begin, begin + resp.body.size());
            }

            if (shouldRefreshAfterDownloadFailure(resp))
            {
                clearCachedToken();
                if (attempt == 0)
                    continue;
            }

            return Result<std::vector<std::uint8_t>>::fail(formatDownloadError(resp));
        }

        return Result<std::vector<std::uint8_t>>::fail("Invisible Folder download retry limit reached");
    }

    Result<void> InvisibleFolder::downloadToFile(std::string_view referenceId,
                                                 const std::filesystem::path &destination)
    {
        const auto bytes = download(referenceId);
        if (!bytes.ok())
            return Result<void>::fail(bytes.error());

        const auto parent = destination.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent))
            return Result<void>::fail("destination directory does not exist");

        std::ofstream output(destination, std::ios::binary | std::ios::trunc);
        if (!output)
            return Result<void>::fail("failed to open destination file for writing");

        const auto *data = reinterpret_cast<const char *>(bytes->data());
        output.write(data, static_cast<std::streamsize>(bytes->size()));
        if (!output)
            return Result<void>::fail("failed to write downloaded bytes to disk");

        return Result<void>{};
    }

    void InvisibleFolder::setPasswordAuth(std::string_view username, std::string_view password)
    {
        std::lock_guard<std::mutex> lk(stateMtx_);
        ++stateVersion_;
        authMode_ = AuthMode::Password;
        username_ = std::string(username);
        password_ = std::string(password);
        wipeString(licenseKey_);
    }

    void InvisibleFolder::setKeyAuth(std::string_view licenseKey)
    {
        std::lock_guard<std::mutex> lk(stateMtx_);
        ++stateVersion_;
        authMode_ = AuthMode::Key;
        licenseKey_ = std::string(licenseKey);
        wipeString(username_);
        wipeString(password_);
    }

    void InvisibleFolder::cacheToken(std::string_view token, std::string_view expiresAt)
    {
        std::lock_guard<std::mutex> lk(stateMtx_);
        ++stateVersion_;
        token_ = std::string(token);
        tokenExpiresAt_ = std::string(expiresAt);
        const auto parsed = parseUtcTimestamp(tokenExpiresAt_);
        hasTokenExpiry_ = parsed.has_value();
        if (parsed)
            tokenExpiresAtTime_ = *parsed;
    }

    void InvisibleFolder::clearCachedToken() noexcept
    {
        std::lock_guard<std::mutex> lk(stateMtx_);
        wipeString(token_);
        wipeString(tokenExpiresAt_);
        tokenExpiresAtTime_ = {};
        hasTokenExpiry_ = false;
    }

    void InvisibleFolder::clearSessionState() noexcept
    {
        {
            std::lock_guard<std::mutex> lk(stateMtx_);
            ++stateVersion_;
            authMode_ = AuthMode::None;
            wipeString(username_);
            wipeString(password_);
            wipeString(licenseKey_);
            wipeString(token_);
            wipeString(tokenExpiresAt_);
            tokenExpiresAtTime_ = {};
            hasTokenExpiry_ = false;
            refreshInFlight_ = false;
            ++refreshGeneration_;
            lastRefreshGeneration_ = refreshGeneration_;
            lastRefreshSucceeded_ = true;
            wipeString(lastRefreshError_);
        }
        stateCv_.notify_all();
    }

} // namespace syslocker