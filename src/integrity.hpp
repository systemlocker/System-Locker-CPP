#pragma once

#include <cstdint>
#include <string>

namespace syslocker::detail
{

    /// Opaque handle to a captured code-section hash. Created once at library
    /// load; verified later by integrity_verify().
    struct IntegrityBaseline
    {
        std::string sha1Hex;      // 40-char lowercase hex
        std::size_t codeSize = 0; // bytes covered by the hash
    };

    /// Capture a SHA-1 hash of the library's own loaded code pages at call time.
    /// On Windows this hashes the .text section of the containing module.
    /// On Linux/macOS this hashes the range [dli_saddr, dli_saddr + code_length)
    /// reported by dladdr for a known symbol.
    ///
    /// Returns false (and sets an error message) if the platform doesn't support
    /// self-hashing or if the code region can't be located.
    bool integrity_capture(IntegrityBaseline &out, std::string &error) noexcept;

    /// Re-hash the same code region and compare against the baseline captured by
    /// integrity_capture(). Returns true if the hash matches, false if it has
    /// changed (indicating runtime patching) or if an error occurs.
    bool integrity_verify(const IntegrityBaseline &baseline, std::string &error) noexcept;

} // namespace syslocker::detail
