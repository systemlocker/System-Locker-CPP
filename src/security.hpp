#pragma once

namespace syslocker::detail
{

    /// Returns true if a debugger is currently attached to this process. Best
    /// effort, cross-platform. We use this to refuse to talk to the auth API
    /// when a debugger is present, which raises the bar for attackers trying
    /// to lift tokens out of memory or patch the heartbeat thread mid-flight.
    bool isDebuggerPresent() noexcept;

    /// Volatile no-op that the optimizer is forbidden to remove. Used to tie
    /// security checks together so they cannot be elided as dead code.
    void securityBarrier() noexcept;

} // namespace syslocker::detail
