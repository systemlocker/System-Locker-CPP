#pragma once

#include <optional>
#include <string>
#include <type_traits>
#include <utility>

namespace syslocker
{

    /// Lightweight Result<T> that carries either a value or a human-readable
    /// error string. Modeled after std::expected (C++23) but kept C++20-clean.
    template <class T>
    class Result
    {
        std::optional<T> value_;
        std::string error_;

    public:
        Result() = default;
        Result(T v) : value_(std::move(v)) {}

        static Result fail(std::string e)
        {
            Result r;
            r.error_ = std::move(e);
            return r;
        }

        explicit operator bool() const noexcept { return value_.has_value(); }
        bool ok() const noexcept { return value_.has_value(); }

        T &operator*() { return *value_; }
        const T &operator*() const { return *value_; }
        T *operator->() { return &*value_; }
        const T *operator->() const { return &*value_; }

        const std::string &error() const noexcept { return error_; }

        template <class U>
        T value_or(U &&fallback) const
        {
            return value_ ? *value_ : static_cast<T>(std::forward<U>(fallback));
        }
    };

    /// Specialization for operations that produce no value, only success/failure.
    template <>
    class Result<void>
    {
        bool ok_ = true;
        std::string error_;

    public:
        Result() = default;

        static Result fail(std::string e)
        {
            Result r;
            r.ok_ = false;
            r.error_ = std::move(e);
            return r;
        }

        explicit operator bool() const noexcept { return ok_; }
        bool ok() const noexcept { return ok_; }

        const std::string &error() const noexcept { return error_; }
    };

} // namespace syslocker
