# SystemLocker C++ Static Package

This folder contains the prebuilt static-link package for Visual Studio on
Windows.

## Package contents

```text
include/syslocker/*.hpp   public headers
lib/syslocker.lib         SystemLocker static library
lib/libcurl.lib           custom static libcurl build
COPYING-curl.txt          libcurl license
```

`syslocker` itself is already built into `syslocker.lib`.

## Visual Studio setup

After extracting or copying this `static/` folder somewhere on disk:

1. Set your project to C++20.
2. Add `static/include/` to C/C++ -> General -> Additional Include Directories.
3. Add `static/lib/` to Linker -> General -> Additional Library Directories.
4. Add `syslocker.lib;libcurl.lib;bcrypt.lib;advapi32.lib;crypt32.lib;secur32.lib;ws2_32.lib;iphlpapi.lib` to Linker -> Input -> Additional Dependencies.

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
