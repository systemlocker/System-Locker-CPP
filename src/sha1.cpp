#include "sha1.hpp"

#include <cstring>

namespace syslocker::detail
{

    namespace
    {

        constexpr std::uint32_t rol(std::uint32_t v, int n) noexcept
        {
            return (v << n) | (v >> (32 - n));
        }

        constexpr std::uint32_t blk0(const std::uint8_t b[64], int i) noexcept
        {
            return (std::uint32_t(b[i * 4]) << 24) | (std::uint32_t(b[i * 4 + 1]) << 16) | (std::uint32_t(b[i * 4 + 2]) << 8) | std::uint32_t(b[i * 4 + 3]);
        }

        constexpr char hexChar(std::uint8_t nibble) noexcept
        {
            return static_cast<char>(nibble < 10 ? '0' + nibble : 'a' + (nibble - 10));
        }

    } // namespace

    void Sha1::reset() noexcept
    {
        state_[0] = 0x67452301;
        state_[1] = 0xEFCDAB89;
        state_[2] = 0x98BADCFE;
        state_[3] = 0x10325476;
        state_[4] = 0xC3D2E1F0;
        bitCount_ = 0;
        bufferLen_ = 0;
    }

    void Sha1::transform(const std::uint8_t block[64]) noexcept
    {
        std::uint32_t w[80];
        for (int i = 0; i < 16; ++i)
            w[i] = blk0(block, i);
        for (int i = 16; i < 80; ++i)
        {
            w[i] = rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        std::uint32_t a = state_[0];
        std::uint32_t b = state_[1];
        std::uint32_t c = state_[2];
        std::uint32_t d = state_[3];
        std::uint32_t e = state_[4];

        auto round = [&](int i, std::uint32_t f, std::uint32_t k)
        {
            std::uint32_t t = rol(a, 5) + f + e + k + w[i];
            e = d;
            d = c;
            c = rol(b, 30);
            b = a;
            a = t;
        };

        for (int i = 0; i < 20; ++i)
            round(i, (b & c) | ((~b) & d), 0x5A827999);
        for (int i = 20; i < 40; ++i)
            round(i, b ^ c ^ d, 0x6ED9EBA1);
        for (int i = 40; i < 60; ++i)
            round(i, (b & c) | (b & d) | (c & d), 0x8F1BBCDC);
        for (int i = 60; i < 80; ++i)
            round(i, b ^ c ^ d, 0xCA62C1D6);

        state_[0] += a;
        state_[1] += b;
        state_[2] += c;
        state_[3] += d;
        state_[4] += e;
    }

    void Sha1::update(const void *data, std::size_t len) noexcept
    {
        const auto *in = static_cast<const std::uint8_t *>(data);
        bitCount_ += static_cast<std::uint64_t>(len) * 8u;

        if (bufferLen_)
        {
            std::size_t take = std::min<std::size_t>(64 - bufferLen_, len);
            std::memcpy(buffer_ + bufferLen_, in, take);
            bufferLen_ += take;
            in += take;
            len -= take;
            if (bufferLen_ == 64)
            {
                transform(buffer_);
                bufferLen_ = 0;
            }
        }

        while (len >= 64)
        {
            transform(in);
            in += 64;
            len -= 64;
        }

        if (len)
        {
            std::memcpy(buffer_, in, len);
            bufferLen_ = len;
        }
    }

    Sha1::Digest Sha1::finalize() noexcept
    {
        std::uint64_t bits = bitCount_;

        // append 0x80, pad with zeros until length % 64 == 56, then 8-byte length
        std::uint8_t pad = 0x80;
        update(&pad, 1);
        std::uint8_t zero = 0;
        while (bufferLen_ != 56)
        {
            update(&zero, 1);
        }

        std::uint8_t lengthBytes[8];
        for (int i = 0; i < 8; ++i)
        {
            lengthBytes[i] = static_cast<std::uint8_t>((bits >> (56 - i * 8)) & 0xFF);
        }
        update(lengthBytes, 8);

        Digest out{};
        for (int i = 0; i < 5; ++i)
        {
            out[i * 4] = static_cast<std::uint8_t>((state_[i] >> 24) & 0xFF);
            out[i * 4 + 1] = static_cast<std::uint8_t>((state_[i] >> 16) & 0xFF);
            out[i * 4 + 2] = static_cast<std::uint8_t>((state_[i] >> 8) & 0xFF);
            out[i * 4 + 3] = static_cast<std::uint8_t>(state_[i] & 0xFF);
        }

        reset(); // wipe interior state to avoid leaving secrets in memory
        return out;
    }

    std::string hexEncode(const Sha1::Digest &d)
    {
        std::string out;
        out.resize(Sha1::DigestSize * 2);
        for (std::size_t i = 0; i < Sha1::DigestSize; ++i)
        {
            out[i * 2] = hexChar(d[i] >> 4);
            out[i * 2 + 1] = hexChar(d[i] & 0x0F);
        }
        return out;
    }

    std::string Sha1::hex(std::string_view input)
    {
        Sha1 h;
        h.update(input);
        return hexEncode(h.finalize());
    }

} // namespace syslocker::detail
