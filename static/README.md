# SystemLocker C++ Static Package

This folder contains the prebuilt static-link package for Visual Studio on
Windows.

## Package contents

```text
include/syslocker/*.hpp   public headers
lib/syslocker.lib         SystemLocker static library
lib/libcurl.lib           libcurl import library
bin/*.dll                 libcurl runtime DLL set
```

`syslocker` itself is already built into `syslocker.lib`.

## Visual Studio setup

After extracting or copying this `static/` folder somewhere on disk:

1. Set your project to C++20.
2. Add `static/include/` to C/C++ -> General -> Additional Include Directories.
3. Add `static/lib/` to Linker -> General -> Additional Library Directories.
4. Add `syslocker.lib;libcurl.lib;ws2_32.lib` to Linker -> Input -> Additional Dependencies.
5. Copy every DLL from `static/bin/` beside your final `.exe`.

## Minimal code

```cpp
#include <syslocker/syslocker.hpp>
```

## Example

```cpp
#include <syslocker/syslocker.hpp>
#include <iostream>

int main()
{
    // Super basic HWID implementation - not recommended
    string hwid = Environment.MachineName.ToString() + GetMachineGuid();
    hwid = hwid.Trim();

    syslocker::Config cfg;
    cfg.systemId = "YOUR_SYSTEM_ID";
    cfg.version = "1.0";
    cfg.hwid = hwid; // Set to "bypass" if you are ok with key reuse.
    // You may opt to use Free Trial keys instead, which bypass hwid
    // without compromising HWID checks for the rest of your keys.

    syslocker::Client client(cfg);
    auto result = client.authenticateWithKey("YOUR_LICENSE_KEY");
    if (!result)
    {
        std::cerr << result.error() << '\n';
        return 1;
    }

    return 0;
}
```

## Notes

- Build your application as the same architecture as this package, typically
  `x64`.
- `ws2_32.lib` is supplied by the Windows SDK. Do not redistribute it.
- The complete curl runtime set from `static/bin/` must be deployed beside your
  application at runtime unless you switch to a statically linked curl build.
- If your curl build depends on additional DLLs, ship those too.

## Refreshing this package

Maintainers can rebuild and restage this folder from the main repository with:

```powershell
./package-publish.ps1
```

If `cmake` is not on `PATH` on the current machine, pass the directory that
contains `cmake.exe`:

```powershell
./package-publish.ps1 -CMakeBinDir "C:\Program Files\CMake\bin"
```

If the library is already built and you only want to refresh the staged files:

```powershell
./package-publish.ps1 -SkipBuild
```
