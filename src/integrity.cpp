#include "integrity.hpp"
#include "sha1.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>

#if defined(_WIN32)
#include <windows.h>
#include <dbghelp.h>
#elif defined(__linux__)
#include <dlfcn.h>
#include <link.h>
#elif defined(__APPLE__)
#include <dlfcn.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/vm_prot.h>
#endif

namespace syslocker::detail
{

    namespace
    {

        struct CodeRegion
        {
            const std::uint8_t *address = nullptr;
            std::size_t regionBytes = 0;
        };

        constexpr std::size_t kMaxCodeRegions = 16;

        bool appendCodeRegion(std::array<CodeRegion, kMaxCodeRegions> &codeRegions,
                              std::size_t &codeRegionCount,
                              const std::uint8_t *start,
                              std::size_t size,
                              std::string &error) noexcept
        {
            if (!start || size == 0)
            {
                return true;
            }

            if (codeRegionCount >= codeRegions.size())
            {
                error = "too many executable code regions";
                return false;
            }

            codeRegions[codeRegionCount++] = CodeRegion{start, size};
            return true;
        }

#if defined(__linux__)
        struct LinuxRegionScanContext
        {
            std::array<CodeRegion, kMaxCodeRegions> *codeRegions = nullptr;
            std::size_t *codeRegionCount = nullptr;
            std::string *error = nullptr;
            std::uintptr_t symbolAddress = 0;
            bool found = false;
            bool failed = false;
        };

        int linuxRegionScanCallback(dl_phdr_info *info, std::size_t, void *opaque)
        {
            auto *ctx = static_cast<LinuxRegionScanContext *>(opaque);
            if (!ctx || !info || !info->dlpi_phdr)
            {
                return 0;
            }

            bool moduleContainsSymbol = false;
            for (std::size_t i = 0; i < static_cast<std::size_t>(info->dlpi_phnum); ++i)
            {
                const auto &phdr = info->dlpi_phdr[i];
                if (phdr.p_type != PT_LOAD || phdr.p_memsz == 0)
                {
                    continue;
                }

                const auto segmentStart = static_cast<std::uintptr_t>(info->dlpi_addr) +
                                          static_cast<std::uintptr_t>(phdr.p_vaddr);
                const auto segmentSize = static_cast<std::uintptr_t>(phdr.p_memsz);
                if (ctx->symbolAddress >= segmentStart &&
                    (ctx->symbolAddress - segmentStart) < segmentSize)
                {
                    moduleContainsSymbol = true;
                    break;
                }
            }

            if (!moduleContainsSymbol)
            {
                return 0;
            }

            ctx->found = true;
            for (std::size_t i = 0; i < static_cast<std::size_t>(info->dlpi_phnum); ++i)
            {
                const auto &phdr = info->dlpi_phdr[i];
                if (phdr.p_type != PT_LOAD || (phdr.p_flags & PF_X) == 0 || phdr.p_memsz == 0)
                {
                    continue;
                }

                const auto segmentStart = static_cast<std::uintptr_t>(info->dlpi_addr) +
                                          static_cast<std::uintptr_t>(phdr.p_vaddr);
                const auto segmentSize = static_cast<std::uint64_t>(phdr.p_memsz);
                if (segmentSize > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
                {
                    *(ctx->error) = "executable segment size overflow";
                    ctx->failed = true;
                    return 1;
                }

                if (!appendCodeRegion(*(ctx->codeRegions),
                                      *(ctx->codeRegionCount),
                                      reinterpret_cast<const std::uint8_t *>(segmentStart),
                                      static_cast<std::size_t>(segmentSize),
                                      *(ctx->error)))
                {
                    ctx->failed = true;
                    return 1;
                }
            }

            return 1; // found target module; stop scanning
        }
#endif

        /// Locate executable code regions for the syslocker module.
        bool locateCodeRegions(std::array<CodeRegion, kMaxCodeRegions> &codeRegions,
                               std::size_t &codeRegionCount,
                               std::string &error) noexcept
        {
#if defined(_WIN32)
            codeRegionCount = 0;

            // Get the module handle that contains this function itself.
            HMODULE mod = nullptr;
            if (!::GetModuleHandleExA(
                    GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                    reinterpret_cast<LPCSTR>(&locateCodeRegions),
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
            for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; ++i)
            {
                if (secStart[i].Characteristics & IMAGE_SCN_CNT_CODE)
                {
                    const auto *regionStart = reinterpret_cast<const std::uint8_t *>(mod) +
                                              secStart[i].VirtualAddress;
                    const auto regionSize = static_cast<std::size_t>(secStart[i].Misc.VirtualSize);
                    if (regionSize == 0)
                    {
                        continue;
                    }

                    if (!appendCodeRegion(codeRegions, codeRegionCount, regionStart, regionSize, error))
                    {
                        return false;
                    }
                }
            }
            if (codeRegionCount == 0)
            {
                error = "could not locate code section";
                return false;
            }
            return true;

#elif defined(__linux__)
            codeRegionCount = 0;

            Dl_info info{};
            if (::dladdr(reinterpret_cast<const void *>(&locateCodeRegions), &info) == 0)
            {
                error = "dladdr failed";
                return false;
            }

            const auto symbolAddress = reinterpret_cast<std::uintptr_t>(
                info.dli_saddr ? info.dli_saddr : reinterpret_cast<const void *>(&locateCodeRegions));

            LinuxRegionScanContext ctx;
            ctx.codeRegions = &codeRegions;
            ctx.codeRegionCount = &codeRegionCount;
            ctx.error = &error;
            ctx.symbolAddress = symbolAddress;

            (void)::dl_iterate_phdr(&linuxRegionScanCallback, &ctx);
            if (ctx.failed)
            {
                return false;
            }
            if (!ctx.found)
            {
                error = "failed to locate module program headers";
                return false;
            }
            if (codeRegionCount == 0)
            {
                error = "no executable segments found for module";
                return false;
            }
            return true;

#elif defined(__APPLE__)
            codeRegionCount = 0;

            Dl_info info{};
            if (::dladdr(reinterpret_cast<const void *>(&locateCodeRegions), &info) == 0)
            {
                error = "dladdr failed";
                return false;
            }
            if (!info.dli_fbase)
            {
                error = "dladdr returned incomplete info";
                return false;
            }

            const auto *header = reinterpret_cast<const mach_header *>(info.dli_fbase);

            std::intptr_t slide = 0;
            bool foundImage = false;
            const std::uint32_t imageCount = _dyld_image_count();
            for (std::uint32_t i = 0; i < imageCount; ++i)
            {
                if (_dyld_get_image_header(i) == header)
                {
                    slide = _dyld_get_image_vmaddr_slide(i);
                    foundImage = true;
                    break;
                }
            }
            if (!foundImage)
            {
                error = "failed to resolve Mach-O image slide";
                return false;
            }

            const auto *commandCursor = reinterpret_cast<const std::uint8_t *>(header);
            std::uint32_t commandCount = 0;

            if (header->magic == MH_MAGIC_64)
            {
                const auto *h64 = reinterpret_cast<const mach_header_64 *>(header);
                commandCount = h64->ncmds;
                commandCursor += sizeof(mach_header_64);
            }
            else if (header->magic == MH_MAGIC)
            {
                commandCount = header->ncmds;
                commandCursor += sizeof(mach_header);
            }
            else
            {
                error = "unsupported Mach-O header";
                return false;
            }

            for (std::uint32_t i = 0; i < commandCount; ++i)
            {
                const auto *cmd = reinterpret_cast<const load_command *>(commandCursor);
                if (!cmd || cmd->cmdsize < sizeof(load_command))
                {
                    error = "invalid Mach-O load command";
                    return false;
                }

                if (cmd->cmd == LC_SEGMENT_64)
                {
                    const auto *seg = reinterpret_cast<const segment_command_64 *>(cmd);
                    if ((seg->initprot & VM_PROT_EXECUTE) != 0 && seg->vmsize != 0)
                    {
                        const auto runtimeStart = static_cast<std::uintptr_t>(
                            static_cast<std::intptr_t>(seg->vmaddr) + slide);
                        const auto segmentSize = static_cast<std::uint64_t>(seg->vmsize);
                        if (segmentSize > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
                        {
                            error = "executable segment size overflow";
                            return false;
                        }

                        if (!appendCodeRegion(codeRegions,
                                              codeRegionCount,
                                              reinterpret_cast<const std::uint8_t *>(runtimeStart),
                                              static_cast<std::size_t>(segmentSize),
                                              error))
                        {
                            return false;
                        }
                    }
                }
                else if (cmd->cmd == LC_SEGMENT)
                {
                    const auto *seg = reinterpret_cast<const segment_command *>(cmd);
                    if ((seg->initprot & VM_PROT_EXECUTE) != 0 && seg->vmsize != 0)
                    {
                        const auto runtimeStart = static_cast<std::uintptr_t>(
                            static_cast<std::intptr_t>(seg->vmaddr) + slide);
                        const auto segmentSize = static_cast<std::uint64_t>(seg->vmsize);
                        if (segmentSize > static_cast<std::uint64_t>((std::numeric_limits<std::size_t>::max)()))
                        {
                            error = "executable segment size overflow";
                            return false;
                        }

                        if (!appendCodeRegion(codeRegions,
                                              codeRegionCount,
                                              reinterpret_cast<const std::uint8_t *>(runtimeStart),
                                              static_cast<std::size_t>(segmentSize),
                                              error))
                        {
                            return false;
                        }
                    }
                }

                commandCursor += cmd->cmdsize;
            }

            if (codeRegionCount == 0)
            {
                error = "no executable segments found for module";
                return false;
            }
            return true;

#else
            (void)codeRegions;
            (void)codeRegionCount;
            error = "integrity self-check not supported on this platform";
            return false;
#endif
        }

        bool hashCodeRegions(const std::array<CodeRegion, kMaxCodeRegions> &codeRegions,
                             std::size_t codeRegionCount,
                             std::string &sha1Hex,
                             std::size_t &totalSize,
                             std::string &error) noexcept
        {
            if (codeRegionCount == 0)
            {
                error = "no executable regions available";
                return false;
            }

            Sha1 hasher;
            totalSize = 0;

            for (std::size_t i = 0; i < codeRegionCount; ++i)
            {
                const auto &regionEntry = codeRegions[i];
                if (!regionEntry.address || regionEntry.regionBytes == 0)
                {
                    error = "invalid executable region";
                    return false;
                }

                hasher.update(regionEntry.address, regionEntry.regionBytes);
                totalSize += regionEntry.regionBytes;
            }

            sha1Hex = hexEncode(hasher.finalize());
            return true;
        }

    } // namespace

    bool integrityCapture(IntegrityBaseline &out, std::string &error) noexcept
    {
        std::array<CodeRegion, kMaxCodeRegions> codeRegions{};
        std::size_t codeRegionCount = 0;

        if (!locateCodeRegions(codeRegions, codeRegionCount, error))
        {
            return false;
        }

        std::size_t totalSize = 0;
        std::string digest;
        if (!hashCodeRegions(codeRegions, codeRegionCount, digest, totalSize, error))
        {
            return false;
        }

        out.sha1Hex = std::move(digest);
        out.codeSize = totalSize;
        out.segmentCount = codeRegionCount;
        return true;
    }

    bool integrityVerify(const IntegrityBaseline &baseline, std::string &error) noexcept
    {
        std::array<CodeRegion, kMaxCodeRegions> codeRegions{};
        std::size_t codeRegionCount = 0;

        if (!locateCodeRegions(codeRegions, codeRegionCount, error))
        {
            return false;
        }

        std::size_t totalSize = 0;
        std::string digest;
        if (!hashCodeRegions(codeRegions, codeRegionCount, digest, totalSize, error))
        {
            return false;
        }

        if (codeRegionCount != baseline.segmentCount)
        {
            error = "code region layout changed";
            return false;
        }

        if (totalSize != baseline.codeSize)
        {
            error = "code section size changed";
            return false;
        }

        if (digest != baseline.sha1Hex)
        {
            error = "code section hash mismatch — runtime patching detected";
            return false;
        }

        return true;
    }

} // namespace syslocker::detail
