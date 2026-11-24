#pragma once

#include "errors.hpp"
#include "result.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>

namespace syslocker
{

    class Client;
    class IHttpClient;

    /// The data returned by a successful Bedrock init request.
    struct InitSuccess
    {
        std::string token;          ///< first heartbeat token (begins with "BRK_")
        std::string username;       ///< verified identity: username for account auth, key for key-only auth
        std::int64_t serverEpoch29; ///< floor(unix_time / 29) derived from signed server_time for compatibility
    };

    using HeartbeatFailureHook = std::function<void(const HeartbeatFailure &)>;

    /// Legacy class name retained for source compatibility; uses Bedrock.
    /// Holds the live heartbeat state and runs the background heartbeat thread.
    /// Owned by the Client; not constructed directly by user code.
    class QuicksilverSession
    {
    public:
        QuicksilverSession(IHttpClient &http,
                           std::string baseUrl,
                           std::string systemId,
                           std::chrono::seconds beatRate,
                           std::string initialToken,
                           std::string username,
                           bool enableAntiDebug,
                           std::string integrityBaselineSha1,
                           std::size_t integrityCodeSize,
                           std::size_t integritySegmentCount = 1,
                           std::string signingPublicKey = {},
                           bool requestInvisibleFolderToken = false);

        ~QuicksilverSession();

        QuicksilverSession(const QuicksilverSession &) = delete;
        QuicksilverSession &operator=(const QuicksilverSession &) = delete;

        /// Cooperatively stops the heartbeat thread. Idempotent.
        void stop() noexcept;

        /// True if no failure has occurred and the heartbeat thread is still
        /// running. Safe to call from any thread.
        bool isAlive() const noexcept { return alive_.load(std::memory_order_acquire); }

        /// Number of successful heartbeats since authenticate().
        std::uint64_t beatCount() const noexcept { return beats_.load(std::memory_order_relaxed); }

        /// Identity confirmed by its signed hash at init time. This is the
        /// username for account auth and the license key for key-only auth.
        const std::string &identity() const noexcept { return username_; }

        /// Compatibility alias for account-auth callers. For key-only auth,
        /// this returns the license key after Bedrock verifies its SHA-256 identity hash.
        const std::string &username() const noexcept { return username_; }

        /// Replace the failure hook. Calling thread is the heartbeat thread,
        /// so the hook should be quick and not throw. May be called before or
        /// after authentication; will not invoke the previous hook.
        void onFailure(HeartbeatFailureHook hook);

    private:
        friend class Client;
        Result<std::string> nextInvisibleFolderToken();
        void run();
        void fail(HeartbeatFailureCode code, BeatError be, std::string msg);

        IHttpClient &http_;
        const std::string baseUrl_;
        const std::string systemId_;
        const std::chrono::seconds beatRate_;
        const std::string username_;
        const bool antiDebug_;

        mutable std::mutex tokenMtx_;
        std::string token_;
        const std::string signingPublicKey_;
        std::atomic<bool> requestIfToken_{false};
        std::string ifToken_;
        std::uint64_t ifGeneration_ = 0;
        std::condition_variable tokenCv_;

        std::mutex hookMtx_;
        HeartbeatFailureHook hook_;

        std::atomic<bool> alive_{true};
        std::atomic<bool> stop_{false};
        std::atomic<std::uint64_t> beats_{0};

        std::mutex cvMtx_;
        std::condition_variable cv_;
        std::thread thread_;

        // Integrity self-check baseline (captured at library init)
        const std::string integrityBaseline_;
        const std::size_t integrityCodeSize_;
        const std::size_t integritySegmentCount_;
    };

} // namespace syslocker
