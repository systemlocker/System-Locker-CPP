#include "security.hpp"

#if defined(_WIN32)
#include <windows.h>
#include <intrin.h>
#elif defined(__linux__)
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <unistd.h>
#elif defined(__APPLE__)
#include <sys/sysctl.h>
#include <sys/types.h>
#include <unistd.h>
#endif

namespace syslocker::detail
{

    namespace
    {

#if defined(__linux__)
        bool linuxTracerPidIsSet() noexcept
        {
            int fd = ::open("/proc/self/status", O_RDONLY | O_CLOEXEC);
            if (fd < 0)
                return false;
            char buf[4096];
            ssize_t n = ::read(fd, buf, sizeof(buf) - 1);
            ::close(fd);
            if (n <= 0)
                return false;
            buf[n] = '\0';
            const char *p = std::strstr(buf, "TracerPid:");
            if (!p)
                return false;
            p += sizeof("TracerPid:") - 1;
            while (*p == ' ' || *p == '\t')
                ++p;
            // any non-zero value means a tracer is attached
            return *p != '0';
        }
#endif

#if defined(__APPLE__)
        bool macKernelReportsTraced() noexcept
        {
            int mib[4]{CTL_KERN, KERN_PROC, KERN_PROC_PID, ::getpid()};
            struct kinfo_proc info{};
            size_t size = sizeof(info);
            if (::sysctl(mib, 4, &info, &size, nullptr, 0) != 0)
                return false;
            return (info.kp_proc.p_flag & P_TRACED) != 0;
        }
#endif

    } // namespace

    bool isDebuggerPresent() noexcept
    {
#if defined(_WIN32)
        if (::IsDebuggerPresent())
            return true;
        BOOL remote = FALSE;
        if (::CheckRemoteDebuggerPresent(::GetCurrentProcess(), &remote) && remote)
        {
            return true;
        }
        return false;
#elif defined(__linux__)
        return linuxTracerPidIsSet();
#elif defined(__APPLE__)
        return macKernelReportsTraced();
#else
        return false;
#endif
    }

    void securityBarrier() noexcept
    {
        // The empty asm with a memory clobber prevents the compiler from
        // reordering or removing surrounding security checks.
#if defined(__GNUC__) || defined(__clang__)
        __asm__ __volatile__("" ::: "memory");
#elif defined(_MSC_VER)
        _ReadWriteBarrier();
#endif
    }

} // namespace syslocker::detail
