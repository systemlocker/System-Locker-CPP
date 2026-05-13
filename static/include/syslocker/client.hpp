#pragma once

#include "config.hpp"
#include "errors.hpp"
#include "http.hpp"
#include "management.hpp"
#include "quicksilver.hpp"
#include "result.hpp"
#include "variables.hpp"

#include <memory>
#include <string>
#include <string_view>

namespace syslocker
{

    /// The single stateful entry point for the library. One Client per system
    /// and per authenticated user. Construct, then call exactly one of the
    /// authenticate*() methods. After success, isAuthenticated() reflects the
    /// live heartbeat session.
    ///
    /// Thread-safety: authenticate*() and shutdown() are not safe to call
    /// concurrently with themselves; once authenticated all const queries are
    /// safe to call from any thread.
    class Client
    {
    public:
        /// Construct with the default libcurl HTTP client.
        explicit Client(Config cfg);

        /// Construct with a caller-supplied HTTP client. Useful for tests and
        /// for plugging in alternative TLS stacks. The Client takes ownership.
        Client(Config cfg, std::unique_ptr<IHttpClient> http);

        ~Client();

        Client(const Client &) = delete;
        Client &operator=(const Client &) = delete;

        /// Install a hook that fires when the heartbeat thread fails for any
        /// reason. Safe to call before or after authentication. Replaces any
        /// prior hook.
        void onHeartbeatFailure(HeartbeatFailureHook hook);

        /// Username + password Quicksilver flow (POST /auth/quicksilver/init).
        Result<InitSuccess> authenticateWithPassword(std::string_view username,
                                                     std::string_view password);

        /// Key-only Quicksilver flow (POST /quicksilver/init).
        Result<InitSuccess> authenticateWithKey(std::string_view licenseKey);

        /// True iff a heartbeat session has been established and no failure
        /// has been recorded since.
        bool isAuthenticated() const noexcept;

        /// How many heartbeats have completed successfully.
        std::uint64_t heartbeatCount() const noexcept;

        /// Wrapped identity confirmed by the server during init. This is the
        /// username for account auth and the license key for key-only auth.
        std::string identity() const;

        /// Compatibility alias for account-auth callers. For key-only auth,
        /// this returns the license key because that is what Quicksilver
        /// currently echoes in the wrapped response.
        std::string username() const;

        /// Tear down the heartbeat session. Idempotent. Called automatically
        /// at destruction.
        void shutdown() noexcept;

        /// Direct access to the variables sub-API. Available before auth.
        Variables &variables();

        /// Direct access to the management sub-API. Requires Config::apiKey.
        Management &management();

    private:
        Result<InitSuccess> doInit(std::string_view path, std::string identifier, const FormFields &fields);

        Config cfg_;
        std::unique_ptr<IHttpClient> http_;
        std::unique_ptr<Variables> variables_;
        std::unique_ptr<Management> management_;
        std::unique_ptr<QuicksilverSession> session_;
        HeartbeatFailureHook pendingHook_;
    };

} // namespace syslocker
