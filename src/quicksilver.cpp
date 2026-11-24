#include "syslocker/quicksilver.hpp"

#include "syslocker/http.hpp"
#include "integrity.hpp"
#include "security.hpp"
#include "util.hpp"
#include "bedrock_crypto.hpp"

#include <chrono>
#include <cstdlib>

namespace syslocker
{

    namespace
    {

        constexpr const char *kBeatPath = "/auth/bedrock/beat";
        constexpr auto kClockJumpTolerance = std::chrono::seconds(2);

    } // namespace

    QuicksilverSession::QuicksilverSession(IHttpClient &http,
                                           std::string baseUrl,
                                           std::string systemId,
                                           std::chrono::seconds beatRate,
                                           std::string initialToken,
                                           std::string username,
                                           bool enableAntiDebug,
                                           std::string integrityBaselineSha1,
                                           std::size_t integrityCodeSize,
                                           std::size_t integritySegmentCount,
                                           std::string signingPublicKey,
                                           bool requestInvisibleFolderToken)
        : http_(http), baseUrl_(std::move(baseUrl)), systemId_(std::move(systemId)), beatRate_(beatRate), username_(std::move(username)), antiDebug_(enableAntiDebug), token_(std::move(initialToken)), signingPublicKey_(std::move(signingPublicKey)), requestIfToken_(requestInvisibleFolderToken), integrityBaseline_(std::move(integrityBaselineSha1)), integrityCodeSize_(integrityCodeSize), integritySegmentCount_(integritySegmentCount)
    {
        thread_ = std::thread([this]
                              {
                                  try
                                  {
                                      run();
                                  }
                                  catch (...)
                                  {
                                      fail(HeartbeatFailureCode::TamperDetected,
                                           BeatError::TamperDetected,
                                           "heartbeat thread exception");
                                  } });
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
        {
            std::lock_guard<std::mutex> lock(tokenMtx_);
            alive_.store(false, std::memory_order_release);
        }
        tokenCv_.notify_all();
    }

    void QuicksilverSession::onFailure(HeartbeatFailureHook hook)
    {
        std::lock_guard<std::mutex> lk(hookMtx_);
        hook_ = std::move(hook);
    }

    void QuicksilverSession::fail(HeartbeatFailureCode code, BeatError be, std::string msg)
    {
        {
            std::lock_guard<std::mutex> lock(tokenMtx_);
            alive_.store(false, std::memory_order_release);
        }
        tokenCv_.notify_all();
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
            if (be == BeatError::Terminated)
            {
                constexpr std::string_view prefix = "terminated ";
                const auto raw = std::string_view(f.message);
                if (raw.size() >= prefix.size() &&
                    detail::toLowerCopy(raw.substr(0, prefix.size())) == prefix)
                {
                    f.terminationReason = std::string(raw.substr(prefix.size()));
                }
            }
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
        auto previousSteady = std::chrono::steady_clock::now();
        auto previousSystem = std::chrono::system_clock::now();

        while (true)
        {
            {
                std::unique_lock<std::mutex> lk(cvMtx_);
                cv_.wait_for(lk, beatRate_, [this]
                             { return stop_.load(std::memory_order_acquire); });
            }
            if (stop_.load(std::memory_order_acquire))
                return;

            // Compare wall-clock passage against monotonic passage. Any
            // backward jump or large skew indicates local clock tampering.
            const auto currentSteady = std::chrono::steady_clock::now();
            const auto currentSystem = std::chrono::system_clock::now();
            const auto steadyElapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                             currentSteady - previousSteady)
                                             .count();
            const auto systemElapsedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
                                             currentSystem - previousSystem)
                                             .count();
            const auto driftMs = systemElapsedMs - steadyElapsedMs;
            const auto toleranceMs = std::chrono::duration_cast<std::chrono::milliseconds>(kClockJumpTolerance).count();
            if (systemElapsedMs < 0 || std::llabs(driftMs) > toleranceMs)
            {
                fail(HeartbeatFailureCode::TamperDetected,
                     BeatError::TamperDetected,
                     "system clock jump detected (possible tamper)");
                return;
            }
            previousSteady = currentSteady;
            previousSystem = currentSystem;

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
                bl.segmentCount = integritySegmentCount_;
                std::string integrityError;
                if (!detail::integrityVerify(bl, integrityError))
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

            auto challenge = legacy_bedrock::detail::generateChallenge();
            if (!challenge)
            {
                fail(HeartbeatFailureCode::TamperDetected, BeatError::TamperDetected, challenge.error().message);
                return;
            }
            FormFields form = {
                {"session_token", sentToken}, {"system", systemId_}, {"challenge", *challenge},
            };
            const bool requestedIfToken = requestIfToken_.load();
            if (requestedIfToken)
                form.emplace_back("init-if", "true");

            auto resp = http_.post(baseUrl_ + kBeatPath, form);
            // A lost response may already have rotated the server token. Retry
            // only transport failures, with the exact same token and challenge.
            if (!resp.error.empty())
                resp = http_.post(baseUrl_ + kBeatPath, form);
            if (!resp.ok())
            {
                fail(HeartbeatFailureCode::Transport, BeatError::Transport,
                     resp.error.empty() ? "http " + std::to_string(resp.status) : resp.error);
                return;
            }
            Config config;
            config.systemId = systemId_;
            config.signingPublicKey = signingPublicKey_;
            auto verified = resp.header("x-bedrock-signed") == "false"
                ? legacy_bedrock::detail::parseUnsignedRevocation(config, resp, *challenge)
                : legacy_bedrock::detail::verifySignedResponse(config, resp, *challenge);
            if (!verified)
            {
                fail(HeartbeatFailureCode::TamperDetected, BeatError::TamperDetected, verified.error().message);
                return;
            }
            using Code = legacy_bedrock::ResponseCode;
            if (verified->code != Code::Ok)
            {
                BeatError error = BeatError::Terminated;
                if (verified->code == Code::InvalidSession) error = BeatError::BadSessionToken;
                else if (verified->code == Code::StaleSession) error = BeatError::StaleToken;
                else if (verified->code == Code::HeartbeatTooEarly || verified->code == Code::ConcurrentHeartbeat)
                    error = BeatError::RateLimit;
                else if (verified->code == Code::ExpiredKey) error = BeatError::ExpiredKey;
                const auto message = verified->terminationMessage.value_or(verified->humanResponse);
                fail(HeartbeatFailureCode::BeatRejected, error,
                     error == BeatError::Terminated ? "terminated " + message : message);
                return;
            }
            if (!verified->authed || !verified->sessionToken ||
                !detail::startsWith(*verified->sessionToken, "BRF_") || verified->sessionToken->size() <= 4)
            {
                fail(HeartbeatFailureCode::TamperDetected, BeatError::TamperDetected,
                     "Bedrock heartbeat did not return a rotated session token");
                return;
            }
            {
                std::lock_guard<std::mutex> lk(tokenMtx_);
                token_ = *verified->sessionToken;
                if (requestedIfToken)
                {
                    ifToken_ = verified->invisibleFolderToken.value_or("");
                    ++ifGeneration_;
                }
            }
            beats_.fetch_add(1, std::memory_order_relaxed);
            tokenCv_.notify_all();
        }
    }

    Result<std::string> QuicksilverSession::nextInvisibleFolderToken()
    {
        std::unique_lock<std::mutex> lock(tokenMtx_);
        const auto generation = ifGeneration_;
        requestIfToken_.store(true);
        // Never send an extra heartbeat: Bedrock rejects early beats. Waiting
        // here lets concurrent downloads share the next scheduled signed token.
        tokenCv_.wait(lock, [&] { return ifGeneration_ != generation || !isAlive(); });
        if (!isAlive())
            return Result<std::string>::fail("client is not authenticated");
        if (ifToken_.empty())
            return Result<std::string>::fail("Bedrock did not return an Invisible Folder token");
        return ifToken_;
    }

} // namespace syslocker
