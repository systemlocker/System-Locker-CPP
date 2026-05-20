#include "syslocker/client.hpp"

#include "integrity.hpp"
#include "security.hpp"
#include "sha1.hpp"
#include "util.hpp"

#include <chrono>
#include <cctype>
#include <cstdint>
#include <cstdlib>
#include <string>

namespace syslocker
{

    namespace
    {

        constexpr const char *kInitPath = "/auth/quicksilver/init";
        constexpr const char *kInitMikrosPath = "/auth/quicksilver/init";

        // Quicksilver protocol time bucket: floor(unix_time / 29).
        constexpr std::int64_t kEpochBucketSeconds = 29;

        bool validBeatRate(std::chrono::seconds s) noexcept
        {
            return s.count() >= 25 && s.count() <= 3600;
        }

        std::int64_t bucketedNow()
        {
            using namespace std::chrono;
            const auto secondsSinceEpoch = duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
            return static_cast<std::int64_t>(secondsSinceEpoch / kEpochBucketSeconds);
        }

        bool eqIgnoreCase(std::string_view a, std::string_view b)
        {
            if (a.size() != b.size())
                return false;
            for (std::size_t i = 0; i < a.size(); ++i)
            {
                unsigned char ca = static_cast<unsigned char>(a[i]);
                unsigned char cb = static_cast<unsigned char>(b[i]);
                if (std::tolower(ca) != std::tolower(cb))
                    return false;
            }
            return true;
        }

        struct Wrapped
        {
            bool ok = false;
            std::string_view var1;
            std::string_view username;
            std::string_view timestamp;
        };

        Wrapped parseWrapped(std::string_view body)
        {
            Wrapped w;
            auto colon = body.rfind(':');
            if (colon == std::string_view::npos)
                return w;
            auto payload = body.substr(0, colon);
            auto hash = detail::trim(body.substr(colon + 1));
            auto computed = detail::Sha1::hex(payload);
            if (!eqIgnoreCase(computed, hash))
                return w;
            auto firstBar = payload.find('|');
            if (firstBar == std::string_view::npos)
                return w;
            auto secondBar = payload.find('|', firstBar + 1);
            if (secondBar == std::string_view::npos)
                return w;
            w.ok = true;
            w.var1 = payload.substr(0, firstBar);
            w.username = payload.substr(firstBar + 1, secondBar - firstBar - 1);
            w.timestamp = payload.substr(secondBar + 1);
            return w;
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
        : cfg_(std::move(cfg)),
          http_(std::move(http)),
          variables_(std::make_unique<Variables>(*http_, cfg_.baseUrl, cfg_.systemId)),
          management_(std::make_unique<Management>(*http_, cfg_.baseUrl, cfg_.apiKey)),
          invisibleFolder_(std::make_unique<InvisibleFolder>(
              *http_, cfg_.baseUrl, cfg_.invisibleFolderBaseUrl, cfg_.systemId, cfg_.hwid,
              [this]
              { return isAuthenticated(); }))
    {
    }

    Client::~Client() { shutdown(); }

    void Client::onHeartbeatFailure(HeartbeatFailureHook hook)
    {
        pendingHook_ = hook;
        if (session_)
        {
            session_->onFailure([this, hook = std::move(hook)](const HeartbeatFailure &failure)
                                {
                                    invisibleFolder_->clearSessionState();
                                    if (hook)
                                        hook(failure); });
        }
    }

    bool Client::isAuthenticated() const noexcept
    {
        return session_ && session_->isAlive();
    }

    std::uint64_t Client::heartbeatCount() const noexcept
    {
        return session_ ? session_->beatCount() : 0;
    }

    std::string Client::identity() const
    {
        return session_ ? session_->identity() : std::string{};
    }

    std::string Client::username() const
    {
        return identity();
    }

    void Client::shutdown() noexcept
    {
        if (session_)
            session_->stop();
        session_.reset();
        invisibleFolder_->clearSessionState();
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
        if (cfg_.systemId.empty())
        {
            return Result<InitSuccess>::fail("Config::systemId is required");
        }
        if (!validBeatRate(cfg_.beatRate))
        {
            return Result<InitSuccess>::fail("Config::beatRate must be in [25, 3600]");
        }

        const auto resp = http_->post(std::string(cfg_.baseUrl) + std::string(path), fields);
        if (!resp.ok())
        {
            return Result<InitSuccess>::fail(
                resp.error.empty() ? ("http " + std::to_string(resp.status)) : resp.error);
        }

        const auto body = std::string(detail::trim(resp.body));

        auto w = parseWrapped(body);
        std::string_view var1View;
        std::string serverIdentity; // username for account auth, key for key-only auth
        std::int64_t serverTs = 0;
        bool wrapped = false;

        if (w.ok)
        {
            wrapped = true;
            var1View = w.var1;
            serverIdentity = std::string(w.username);
            try
            {
                serverTs = std::stoll(std::string(w.timestamp));
            }
            catch (...)
            {
                return Result<InitSuccess>::fail("malformed timestamp from server");
            }

            if (!identifier.empty() && !eqIgnoreCase(serverIdentity, identifier))
            {
                return Result<InitSuccess>::fail("request tampering detected");
            }
        }
        else
        {
            if (body.find(':') != std::string::npos)
            {
                return Result<InitSuccess>::fail("response failed sha1 integrity check");
            }
            var1View = body;
        }

        const InitError err = parseInitError(var1View);
        if (err == InitError::None)
        {
            if (!wrapped)
            {
                return Result<InitSuccess>::fail(
                    "server returned token without the wrapped username|timestamp:hash envelope");
            }
            for (const auto &[k, v] : fields)
            {
                if (k == "username")
                {
                    if (!eqIgnoreCase(serverIdentity, v))
                    {
                        return Result<InitSuccess>::fail(
                            "server returned a different username than was requested");
                    }
                    break;
                }
            }
            const auto local = bucketedNow();
            if (std::abs(local - serverTs) > 1)
            {
                return Result<InitSuccess>::fail("server timestamp drift exceeds tolerance");
            }
            InitSuccess s{std::string(var1View), std::move(serverIdentity), serverTs};

            // Capture a hash of our own code section so the heartbeat
            // can detect runtime patching (e.g. WriteProcessMemory).
            std::string integritySha1;
            std::size_t integritySize = 0;
            std::size_t integritySegmentCount = 0;
            {
                detail::IntegrityBaseline bl;
                std::string integrityError;
                if (detail::integrityCapture(bl, integrityError))
                {
                    integritySha1 = std::move(bl.sha1Hex);
                    integritySize = bl.codeSize;
                    integritySegmentCount = bl.segmentCount;
                }
                // If capture fails (unsupported platform), we proceed
                // without integrity checks rather than blocking auth.
            }

            session_ = std::make_unique<QuicksilverSession>(
                *http_, cfg_.baseUrl, cfg_.systemId, cfg_.beatRate,
                s.token, s.username, cfg_.enableAntiDebug,
                std::move(integritySha1), integritySize, integritySegmentCount);
            session_->onFailure([this, hook = pendingHook_](const HeartbeatFailure &failure)
                                {
                                    invisibleFolder_->clearSessionState();
                                    if (hook)
                                        hook(failure); });
            return s;
        }

        return Result<InitSuccess>::fail(std::string(toString(err)) + ": " + body);
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
        auto r = doInit(kInitPath, std::string(username), fields);
        if (!r.ok())
            return r;

        invisibleFolder_->clearSessionState();
        invisibleFolder_->setPasswordAuth(username, password);
        if (options.prefetchInvisibleFolderToken)
            (void)invisibleFolder_->ensureToken();
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
        auto r = doInit(kInitMikrosPath, std::string(licenseKey), fields);
        if (!r.ok())
            return r;

        invisibleFolder_->clearSessionState();
        invisibleFolder_->setKeyAuth(licenseKey);
        if (options.prefetchInvisibleFolderToken)
            (void)invisibleFolder_->ensureToken();
        return r;
    }

} // namespace syslocker
