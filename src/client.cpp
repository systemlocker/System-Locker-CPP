#include "syslocker/client.hpp"

#include "integrity.hpp"
#include "security.hpp"
#include "bedrock_crypto.hpp"
#include "util.hpp"

#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <string>
#include <algorithm>
#include <stdexcept>

namespace syslocker
{

    namespace
    {

        constexpr const char *kInitPath = "/auth/bedrock/init";
        constexpr const char *kInitMikrosPath = kInitPath;

        Config normalize(Config cfg)
        {
            for (auto *url : {&cfg.baseUrl, &cfg.invisibleFolderBaseUrl})
                while (!url->empty() && url->back() == '/') url->pop_back();
            return cfg;
        }

        std::unique_ptr<IHttpClient> requireHttp(std::unique_ptr<IHttpClient> http)
        {
            if (!http) throw std::invalid_argument("HTTP client is required");
            return http;
        }

        CurlHttpOptions optionsFrom(const Config &cfg)
        {
            CurlHttpOptions o;
            o.timeout = cfg.requestTimeout;
            o.userAgent = cfg.userAgent;
            o.pinnedPublicKey = cfg.pinnedPublicKeySha256Base64.value_or(std::string{});
            return o;
        }

    } // namespace

    Client::Client(Config cfg)
        : Client(cfg, makeCurlHttpClient(optionsFrom(cfg))) {}

    Client::Client(Config cfg, std::unique_ptr<IHttpClient> http)
        : cfg_(normalize(std::move(cfg))),
          http_(requireHttp(std::move(http))),
          variables_(std::make_unique<Variables>(*http_, cfg_.baseUrl, cfg_.systemId)),
          management_(std::make_unique<Management>(*http_, cfg_.baseUrl, cfg_.apiKey, cfg_.systemId)),
          invisibleFolder_(std::make_unique<InvisibleFolder>(
              *http_, cfg_.baseUrl, cfg_.invisibleFolderBaseUrl, cfg_.systemId, cfg_.hwid,
              [this]
              { return isAuthenticated(); },
              cfg_.programDigest.value_or(std::string{})))
    {
        invisibleFolder_->fetchToken_ = [this]() -> Result<std::string>
        {
            auto current = session();
            if (!current || !current->isAlive())
                return Result<std::string>::fail("client is not authenticated");
            return current->nextInvisibleFolderToken();
        };
    }

    Client::~Client() { shutdown(); }

    void Client::onHeartbeatFailure(HeartbeatFailureHook hook)
    {
        pendingHook_ = hook;
        if (auto current = session())
        {
            current->onFailure([this, hook = std::move(hook)](const HeartbeatFailure &failure)
                                {
                                    invisibleFolder_->clearSessionState();
                                    if (hook)
                                        hook(failure); });
        }
    }

    bool Client::isAuthenticated() const noexcept
    {
        const auto current = session();
        return current && current->isAlive();
    }

    std::uint64_t Client::heartbeatCount() const noexcept
    {
        const auto current = session();
        return current ? current->beatCount() : 0;
    }

    std::string Client::identity() const
    {
        const auto current = session();
        return current ? current->identity() : std::string{};
    }

    std::string Client::username() const
    {
        return identity();
    }

    void Client::shutdown() noexcept
    {
        std::shared_ptr<QuicksilverSession> previous;
        {
            std::lock_guard<std::mutex> lock(sessionMtx_);
            previous = std::move(session_);
        }
        if (previous)
        {
            previous->stop();
            // A download can retain the session while awaiting its next token.
            // Finish the worker before any callback-owned Client state is freed.
            if (previous->thread_.joinable()) previous->thread_.join();
        }
        invisibleFolder_->clearSessionState();
    }

    std::shared_ptr<QuicksilverSession> Client::session() const
    {
        std::lock_guard<std::mutex> lock(sessionMtx_);
        return session_;
    }

    Variables &Client::variables() { return *variables_; }
    Management &Client::management() { return *management_; }
    InvisibleFolder &Client::invisibleFolder() { return *invisibleFolder_; }

    Result<InitSuccess> Client::doInit(std::string_view path, std::string identifier, const FormFields &fields)
    {
        if (cfg_.enableAntiDebug)
        {
            detail::securityBarrier();
            if (detail::isDebuggerPresent())
            {
                return Result<InitSuccess>::fail("debugger detected");
            }
        }
        const auto alphanumeric = [](unsigned char c) {
            return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9');
        };
        if (cfg_.systemId.size() != 20 || !std::all_of(cfg_.systemId.begin(), cfg_.systemId.end(), alphanumeric))
            return Result<InitSuccess>::fail("Config::systemId must be 20 alphanumeric characters");
        if (cfg_.beatRate.count() < 25 || cfg_.beatRate.count() > 3600)
            return Result<InitSuccess>::fail("Config::beatRate must be in [25, 3600]");
        if (!detail::startsWith(cfg_.baseUrl, "https://") ||
            !detail::startsWith(cfg_.invisibleFolderBaseUrl, "https://"))
            return Result<InitSuccess>::fail("API base URLs must use HTTPS");
        const auto key = legacy_bedrock::detail::base64UrlDecode(cfg_.signingPublicKey);
        if (!key || key->size() != 32)
            return Result<InitSuccess>::fail("Config::signingPublicKey must be the base64url raw 32-byte Bedrock Ed25519 public key");
        if (identifier.empty())
            return Result<InitSuccess>::fail("authentication identity is required");
        for (const auto &[name, value] : fields)
            if (name == "password" && value.empty())
                return Result<InitSuccess>::fail("password is required");

        shutdown();
        auto challenge = legacy_bedrock::detail::generateChallenge();
        if (!challenge) return Result<InitSuccess>::fail(challenge.error().message);
        auto form = fields;
        form.emplace_back("challenge", *challenge);
        const auto resp = http_->post(cfg_.baseUrl + std::string(path), form);
        if (!resp.ok())
            return Result<InitSuccess>::fail(resp.error.empty() ? "http " + std::to_string(resp.status) : resp.error);
        auto verified = legacy_bedrock::detail::verifySignedResponse(cfg_, resp, *challenge);
        if (!verified) return Result<InitSuccess>::fail(verified.error().message);
        if (!verified->authed && (!verified->variables.empty() || verified->invisibleFolderToken))
            return Result<InitSuccess>::fail("Rejected Bedrock initialization included protected data");
        if (!verified->authed)
        {
            // Preserve the legacy string error channel while retaining codes
            // and SSO guidance that older enums cannot describe.
            std::string message = verified->responseCode + ": " + verified->humanResponse;
            if (verified->ssoUrl) message += " " + *verified->ssoUrl;
            return Result<InitSuccess>::fail(std::move(message));
        }
        const bool keyAuth = std::any_of(fields.begin(), fields.end(), [](const auto &f) { return f.first == "key"; });
        const auto identityHash = legacy_bedrock::detail::sha256Hex(identifier);
        const auto &serverHash = keyAuth ? verified->licenseKeyHash : verified->usernameHash;
        if (!identityHash || !serverHash || *serverHash != *identityHash ||
            !verified->sessionToken || !detail::startsWith(*verified->sessionToken, "BRK_") ||
            verified->sessionToken->size() <= 4)
            return Result<InitSuccess>::fail("Bedrock initialization identity or session token is invalid");

        // Keep the original result shape: identity comes from the credential
        // whose hash was verified; the old 29-second bucket is derived locally.
        InitSuccess success{*verified->sessionToken, std::move(identifier), verified->serverTime / 29};
        detail::IntegrityBaseline baseline;
        std::string integrityError;
        (void)detail::integrityCapture(baseline, integrityError);
        const bool requestIfToken = std::any_of(fields.begin(), fields.end(), [](const auto &f) { return f.first == "init-if"; });
        auto current = std::make_shared<QuicksilverSession>(
            *http_, cfg_.baseUrl, cfg_.systemId, cfg_.beatRate,
            success.token, success.username, cfg_.enableAntiDebug,
            std::move(baseline.sha1Hex), baseline.codeSize, baseline.segmentCount,
            cfg_.signingPublicKey, requestIfToken);
        current->onFailure([this, hook = pendingHook_](const HeartbeatFailure &failure) {
            invisibleFolder_->clearSessionState();
            if (hook) hook(failure);
        });
        {
            std::lock_guard<std::mutex> lock(sessionMtx_);
            session_ = std::move(current);
        }
        if (verified->invisibleFolderToken)
            invisibleFolder_->cacheToken(*verified->invisibleFolderToken, {});
        return success;
    }

    Result<InitSuccess> Client::authenticateWithPassword(std::string_view username,
                                                         std::string_view password,
                                                         AuthenticationOptions options)
    {
        FormFields fields = {
            {"username", std::string(username)},
            {"password", std::string(password)},
            {"system", cfg_.systemId},
            {"hwid", cfg_.hwid},
            {"version", cfg_.version},
            {"beatrate", std::to_string(cfg_.beatRate.count())},
        };
        if (cfg_.programDigest)
            fields.emplace_back("digest", *cfg_.programDigest);
        if (options.prefetchInvisibleFolderToken)
            fields.emplace_back("init-if", "true");
        auto r = doInit(kInitPath, std::string(username), fields);
        if (!r.ok())
            return r;

        return r;
    }

    Result<InitSuccess> Client::authenticateWithKey(std::string_view licenseKey,
                                                    AuthenticationOptions options)
    {
        FormFields fields = {
            {"key", std::string(licenseKey)},
            {"system", cfg_.systemId},
            {"hwid", cfg_.hwid},
            {"version", cfg_.version},
            {"beatrate", std::to_string(cfg_.beatRate.count())},
        };
        if (cfg_.programDigest)
            fields.emplace_back("digest", *cfg_.programDigest);
        if (options.prefetchInvisibleFolderToken)
            fields.emplace_back("init-if", "true");
        auto r = doInit(kInitMikrosPath, std::string(licenseKey), fields);
        if (!r.ok())
            return r;

        return r;
    }

} // namespace syslocker
