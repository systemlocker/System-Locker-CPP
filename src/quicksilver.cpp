#include "syslocker/quicksilver.hpp"

#include "syslocker/http.hpp"
#include "integrity.hpp"
#include "security.hpp"
#include "util.hpp"

#include <chrono>

namespace syslocker
{

    namespace
    {

        constexpr const char *kBeatPath = "/auth/quicksilver/beat";

    } // namespace

    QuicksilverSession::QuicksilverSession(IHttpClient &http,
                                           std::string baseUrl,
                                           std::string systemId,
                                           std::chrono::seconds beatRate,
                                           std::string initialToken,
                                           std::string username,
                                           bool enableAntiDebug,
                                           std::string integrityBaselineSha1,
                                           std::size_t integrityCodeSize)
        : http_(http), baseUrl_(std::move(baseUrl)), systemId_(std::move(systemId)), beatRate_(beatRate), username_(std::move(username)), antiDebug_(enableAntiDebug), token_(std::move(initialToken)), integrityBaseline_(std::move(integrityBaselineSha1)), integrityCodeSize_(integrityCodeSize)
    {
        thread_ = std::thread([this]
                              { run(); });
    }

    QuicksilverSession::~QuicksilverSession()
    {
        stop();
        if (thread_.joinable())
            thread_.join();
    }

    void QuicksilverSession::stop() noexcept
    {
        bool expected = false;
        if (stop_.compare_exchange_strong(expected, true))
        {
            std::lock_guard<std::mutex> lk(cvMtx_);
            cv_.notify_all();
        }
        alive_.store(false, std::memory_order_release);
    }

    void QuicksilverSession::onFailure(HeartbeatFailureHook hook)
    {
        std::lock_guard<std::mutex> lk(hookMtx_);
        hook_ = std::move(hook);
    }

    void QuicksilverSession::fail(HeartbeatFailureCode code, BeatError be, std::string msg)
    {
        alive_.store(false, std::memory_order_release);
        HeartbeatFailureHook copy;
        {
            std::lock_guard<std::mutex> lk(hookMtx_);
            copy = hook_;
        }
        if (copy)
        {
            HeartbeatFailure f{
                code,
                be,
                std::move(msg),
                beats_.load(std::memory_order_relaxed),
            };
            // Defensively swallow exceptions from the user hook so we never
            // tear down the heartbeat thread with a live exception.
            try
            {
                copy(f);
            }
            catch (...)
            {
            }
        }
    }

    void QuicksilverSession::run()
    {
        while (true)
        {
            {
                std::unique_lock<std::mutex> lk(cvMtx_);
                cv_.wait_for(lk, beatRate_, [this]
                             { return stop_.load(std::memory_order_acquire); });
            }
            if (stop_.load(std::memory_order_acquire))
                return;

            if (antiDebug_)
            {
                detail::securityBarrier();
                if (detail::isDebuggerPresent())
                {
                    detail::securityBarrier();
                    fail(HeartbeatFailureCode::TamperDetected,
                         BeatError::TamperDetected,
                         "debugger detected");
                    return;
                }
            }

            // Integrity self-check: re-hash the code section and compare
            // against the baseline captured at library init. If the hash
            // differs, someone has patched the code in memory (e.g. via
            // WriteProcessMemory or mprotect + memcpy).
            if (!integrityBaseline_.empty())
            {
                detail::IntegrityBaseline bl;
                bl.sha1Hex = integrityBaseline_;
                bl.codeSize = integrityCodeSize_;
                std::string integrityError;
                if (!detail::integrity_verify(bl, integrityError))
                {
                    fail(HeartbeatFailureCode::TamperDetected,
                         BeatError::TamperDetected,
                         integrityError);
                    return;
                }
            }

            std::string sentToken;
            {
                std::lock_guard<std::mutex> lk(tokenMtx_);
                sentToken = token_;
            }

            const FormFields form = {
                {"token", sentToken},
                {"system", systemId_},
            };

            const auto resp = http_.post(baseUrl_ + kBeatPath, form);
            if (!resp.ok())
            {
                fail(HeartbeatFailureCode::Transport,
                     BeatError::Transport,
                     resp.error.empty()
                         ? ("http " + std::to_string(resp.status))
                         : resp.error);
                return;
            }

            const auto trimmed = std::string(detail::trim(resp.body));
            const BeatError be = parseBeatError(trimmed);
            if (be != BeatError::None)
            {
                fail(HeartbeatFailureCode::BeatRejected, be, trimmed);
                return;
            }

            // success — rotate the token
            {
                std::lock_guard<std::mutex> lk(tokenMtx_);
                token_ = trimmed;
            }
            beats_.fetch_add(1, std::memory_order_relaxed);
        }
    }

} // namespace syslocker
