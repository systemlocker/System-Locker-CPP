#include "integrity.hpp"
#include "sha1.hpp"

#if defined(_WIN32)
#include <windows.h>
#include <dbghelp.h>
#elif defined(__linux__) || defined(__APPLE__)
#include <dlfcn.h>
#endif

namespace syslocker::detail
{

    namespace
    {

        /// Locate the start address and size of the code section that contains
        /// the syslocker library. Returns false if the platform doesn't support
        /// this or if the lookup fails.
        bool findCodeRegion(const void *&start, std::size_t &size, std::string &error) noexcept
        {
#if defined(_WIN32)
            // Get the module handle that contains this function itself.
            HMODULE mod = nullptr;
            if (!::GetModuleHandleExA(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCSTR>(&findCodeRegion),
                    &mod))
            {
                error = "GetModuleHandleEx failed";
                return false;
            }

            auto dosHeader = reinterpret_cast<const IMAGE_DOS_HEADER *>(mod);
            if (dosHeader->e_magic != IMAGE_DOS_SIGNATURE)
            {
                error = "invalid DOS header";
                return false;
            }

            auto ntHeaders = reinterpret_cast<const IMAGE_NT_HEADERS *>(
                reinterpret_cast<const std::uint8_t *>(mod) + dosHeader->e_lfanew);
            if (ntHeaders->Signature != IMAGE_NT_SIGNATURE)
            {
                error = "invalid NT header";
                return false;
            }

            // Hash the .text section specifically — this is where the executable
            // code lives and the most valuable patching target.
            // Walk the section headers to find ".text" by name rather than
            // relying on IMAGE_DIRECTORY_ENTRY_CODE, which was removed from
            // newer Windows SDKs.
            auto secStart = reinterpret_cast<const IMAGE_SECTION_HEADER *>(
                ntHeaders + 1);
            bool found = false;
            for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
            {
                if (secStart[i].Characteristics & IMAGE_SCN_CNT_CODE)
                {
                    start = reinterpret_cast<const void *>(
                        reinterpret_cast<const std::uint8_t *>(mod) + secStart[i].VirtualAddress);
                    size = secStart[i].Misc.VirtualSize;
                    found = true;
                    break;
                }
            }
            if (!found || size == 0)
            {
                error = "could not locate code section";
                return false;
            }
            return true;

#elif defined(__linux__) || defined(__APPLE__)
            // Use dladdr to find the base address of the shared object (or the
            // main executable if statically linked) that contains this function.
            Dl_info info{};
            if (::dladdr(reinterpret_cast<const void *>(&findCodeRegion), &info) == 0)
            {
                error = "dladdr failed";
                return false;
            }

            if (!info.dli_fbase || !info.dli_fname)
            {
                error = "dladdr returned incomplete info";
                return false;
            }

            // On ELF/Mach-O we don't have a convenient way to find just .text
            // from user space, so we hash a generous region starting from the
            // base address. The size is heuristic: 512 KB covers most auth
            // libraries. If the library is larger, the hash still covers the
            // first portion which is where the critical code lives.
            start = info.dli_fbase;
            size = 512 * 1024;
            return true;

#else
            (void)start;
            (void)size;
            error = "integrity self-check not supported on this platform";
            return false;
#endif
        }

    } // namespace

    bool integrity_capture(IntegrityBaseline &out, std::string &error) noexcept
    {
        const void *start = nullptr;
        std::size_t size = 0;

        if (!findCodeRegion(start, size, error))
        {
            return false;
        }

        out.codeSize = size;
        out.sha1Hex = Sha1::hex(std::string_view(
            static_cast<const char *>(start), size));
        return true;
    }

    bool integrity_verify(const IntegrityBaseline &baseline, std::string &error) noexcept
    {
        const void *start = nullptr;
        std::size_t size = 0;

        if (!findCodeRegion(start, size, error))
        {
            return false;
        }

        if (size != baseline.codeSize)
        {
            error = "code section size changed";
            return false;
        }

        auto current = Sha1::hex(std::string_view(
            static_cast<const char *>(start), size));

        if (current != baseline.sha1Hex)
        {
            error = "code section hash mismatch — runtime patching detected";
            return false;
        }

        return true;
    }

} // namespace syslocker::detail
