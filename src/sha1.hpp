#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>

namespace syslocker::detail
{

    /// Streaming SHA-1 (Steve Reid, public domain — re-implemented in modern
    /// C++). NOT cryptographically suitable for new designs, but the System
    /// Locker Quicksilver protocol uses SHA-1 for response integrity, so we
    /// need a working implementation. Constant-time properties are NOT
    /// required here.
    class Sha1
    {
    public:
        static constexpr std::size_t DigestSize = 20;
        using Digest = std::array<std::uint8_t, DigestSize>;

        Sha1() noexcept { reset(); }

        void reset() noexcept;
        void update(const void *data, std::size_t len) noexcept;
        void update(std::string_view sv) noexcept { update(sv.data(), sv.size()); }
        Digest finalize() noexcept;

        /// One-shot helper. Returns the lowercase hex representation.
        static std::string hex(std::string_view input);

    private:
        void transform(const std::uint8_t block[64]) noexcept;

        std::uint32_t state_[5]{};
        std::uint64_t bitCount_ = 0;
        std::uint8_t buffer_[64]{};
        std::size_t bufferLen_ = 0;
    };

    /// Lowercase hex encode.
    std::string hexEncode(const Sha1::Digest &d);

} // namespace syslocker::detail
