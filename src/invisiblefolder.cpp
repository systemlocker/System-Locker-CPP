#include "syslocker/invisiblefolder.hpp"
#include "syslocker/http.hpp"
#include "util.hpp"
#include "json.hpp"

#include <algorithm>
#include <fstream>

namespace syslocker
{
    namespace
    {
        void wipe(std::string &value) noexcept
        {
            std::fill(value.begin(), value.end(), '\0');
            value.clear();
        }

        bool validReference(std::string_view ref)
        {
            return ref.size() >= 4 && ref.size() <= 128 &&
                std::all_of(ref.begin(), ref.end(), [](unsigned char c) {
                    return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                           (c >= '0' && c <= '9') || c == '-' || c == '_';
                });
        }
    }

    InvisibleFolder::InvisibleFolder(IHttpClient &http, std::string systemLockerBaseUrl,
        std::string invisibleFolderBaseUrl, std::string systemId, std::string hwid,
        std::function<bool()> sessionActive, std::string programDigest)
        : http_(http), invisibleFolderBaseUrl_(std::move(invisibleFolderBaseUrl)),
          sessionActive_(std::move(sessionActive))
    {
        // The constructor shape is retained; Bedrock owns credentials and
        // supplies signed tokens, so downloads no longer cache passwords.
        (void)systemLockerBaseUrl; (void)systemId; (void)hwid; (void)programDigest;
    }

    bool InvisibleFolder::hasValidToken() const
    {
        std::lock_guard<std::mutex> lock(stateMtx_);
        return !token_.empty() && sessionActive_ && sessionActive_();
    }

    Result<void> InvisibleFolder::ensureToken()
    {
        std::uint64_t version;
        {
            std::unique_lock<std::mutex> lock(stateMtx_);
            if (!sessionActive_ || !sessionActive_())
                return Result<void>::fail("client is not authenticated");
            if (!token_.empty()) return {};
            if (refreshInFlight_)
            {
                const auto observedVersion = stateVersion_;
                stateCv_.wait(lock, [&] { return !refreshInFlight_ || stateVersion_ != observedVersion; });
                if (stateVersion_ != observedVersion || !sessionActive_ || !sessionActive_())
                    return Result<void>::fail("client is not authenticated");
                if (!token_.empty()) return {};
                return Result<void>::fail(lastRefreshError_);
            }
            if (!fetchToken_) return Result<void>::fail("Invisible Folder requires a Bedrock Client session");
            refreshInFlight_ = true;
            version = stateVersion_;
        }
        // Do not hold stateMtx_ while waiting: a failed heartbeat must be able
        // to clear the token and wake every concurrent download.
        auto refreshed = Result<std::string>::fail("Invisible Folder token refresh failed");
        try { refreshed = fetchToken_(); }
        catch (const std::exception &error) { refreshed = Result<std::string>::fail(error.what()); }
        catch (...) { refreshed = Result<std::string>::fail("Invisible Folder token refresh failed"); }
        std::string error;
        {
            std::lock_guard<std::mutex> lock(stateMtx_);
            if (stateVersion_ != version || !sessionActive_ || !sessionActive_())
                return Result<void>::fail("client is not authenticated");
            if (refreshed && !refreshed->empty()) token_ = std::move(*refreshed);
            else error = refreshed ? "Bedrock did not return an Invisible Folder token" : refreshed.error();
            lastRefreshError_ = error;
            refreshInFlight_ = false;
        }
        stateCv_.notify_all();
        if (!error.empty()) return Result<void>::fail(std::move(error));
        return {};
    }

    Result<std::vector<std::uint8_t>> InvisibleFolder::download(std::string_view referenceId)
    {
        if (!validReference(referenceId))
            return Result<std::vector<std::uint8_t>>::fail("reference id must contain 4-128 letters, digits, underscores or hyphens");
        for (int attempt = 0; attempt < 2; ++attempt)
        {
            auto ready = ensureToken();
            if (!ready) return Result<std::vector<std::uint8_t>>::fail(ready.error());
            std::string token;
            {
                std::lock_guard<std::mutex> lock(stateMtx_);
                if (!sessionActive_ || !sessionActive_() || token_.empty())
                    return Result<std::vector<std::uint8_t>>::fail("client is not authenticated");
                token = token_;
            }
            const auto response = http_.request("GET", invisibleFolderBaseUrl_ + "/a/" + std::string(referenceId), "",
                {{"X-Invisiblefolder-Download", "1"}, {"X-Invisiblefolder-Token", token}});
            wipe(token);
            if (response.ok())
            {
                const auto *begin = reinterpret_cast<const std::uint8_t *>(response.body.data());
                return std::vector<std::uint8_t>(begin, begin + response.body.size());
            }
            // Private-file authorization failures are deliberately concealed
            // as not_found. Refresh once for that response as well as the
            // legacy 401/403 denials; never loop on a genuinely missing file.
            auto json = nlohmann::json::parse(response.body, nullptr, false);
            std::string code;
            if (json.is_object() && json.contains("error") && json["error"].is_string())
                code = json["error"].get<std::string>();
            const bool tokenRejected = response.error.empty() &&
                (response.status == 401 || response.status == 403 ||
                 (response.status == 404 && detail::toLowerCopy(code) == "not_found"));
            if (tokenRejected)
            {
                clearCachedToken();
                if (attempt == 0) continue;
            }
            return Result<std::vector<std::uint8_t>>::fail(response.error.empty()
                ? "http " + std::to_string(response.status) + ": " + response.body : response.error);
        }
        return Result<std::vector<std::uint8_t>>::fail("Invisible Folder download retry limit reached");
    }

    Result<void> InvisibleFolder::downloadToFile(std::string_view referenceId, const std::filesystem::path &destination)
    {
        auto bytes = download(referenceId);
        if (!bytes) return Result<void>::fail(bytes.error());
        const auto parent = destination.parent_path();
        if (!parent.empty() && !std::filesystem::exists(parent))
            return Result<void>::fail("destination directory does not exist");
        std::ofstream output(destination, std::ios::binary | std::ios::trunc);
        if (!output) return Result<void>::fail("failed to open destination file for writing");
        output.write(reinterpret_cast<const char *>(bytes->data()), static_cast<std::streamsize>(bytes->size()));
        if (!output) return Result<void>::fail("failed to write downloaded bytes to disk");
        return {};
    }

    void InvisibleFolder::cacheToken(std::string_view token, std::string_view expiresAt)
    {
        (void)expiresAt; // Bedrock tokens carry no public expiry field.
        std::lock_guard<std::mutex> lock(stateMtx_);
        wipe(token_);
        token_ = token;
    }

    void InvisibleFolder::clearCachedToken() noexcept
    {
        std::lock_guard<std::mutex> lock(stateMtx_);
        wipe(token_);
    }

    void InvisibleFolder::clearSessionState() noexcept
    {
        {
            std::lock_guard<std::mutex> lock(stateMtx_);
            ++stateVersion_;
            wipe(token_);
            refreshInFlight_ = false;
            lastRefreshError_.clear();
        }
        stateCv_.notify_all();
    }
}
