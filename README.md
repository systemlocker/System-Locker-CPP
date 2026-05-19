# SystemLocker C++ Implementation

![System Locker Logo](logo.png)

Welcome to the System Locker C++ Reference implementation, written in C++20.

It supports two ways to integrate the library into a Visual Studio project:

1. Use the prebuilt static package in `static/`
2. Copy the raw source from `include/` and `src/` directly into your project

If you want the fastest setup, use the **static package**.

If you do not want to link against `syslocker.lib`, use the **source-embed** path.
Source-embedding may provide additional security against common attack vectors.
Add the library's public headers and implementation files directly to your
Visual Studio project and build them as part of your app.

## Repository layout

```text
static/                  prebuilt package for Visual Studio consumers
include/syslocker/       public headers for source integration
src/                     implementation files for source integration
third_party/curl/        bundled custom curl headers, static library, and license
```

## Option 1: Prebuilt static package

Use this when you want the simplest Visual Studio setup and are fine linking a
prebuilt `syslocker.lib`.

The package lives under `static/`:

```text
static/
  include/syslocker/*.hpp
  lib/syslocker.lib
  lib/libcurl.lib
  COPYING-curl.txt
```

Setup instructions are in `static/README.md`.

## Option 2: Source-embed integration

Use this when you want to compile SystemLocker directly into your own project
instead of linking `syslocker.lib`.

### Files to copy into your Visual Studio project

At minimum, bring these folders into your solution or vendor directory:

```text
include/syslocker/
src/
third_party/curl/include/curl/
third_party/curl/lib/libcurl.lib
third_party/curl/COPYING
```

### Visual Studio setup

1. Set your project to C++20.
2. Add all `.cpp` files from `src/` to your project.
3. Keep the private headers from `src/` beside those `.cpp` files.
4. Add `include/` to C/C++ -> General -> Additional Include Directories.
5. Add `third_party/curl/include/` to C/C++ -> General -> Additional Include Directories.
6. Add `third_party/curl/lib/` to Linker -> General -> Additional Library Directories.
7. Add `libcurl.lib;bcrypt.lib;advapi32.lib;crypt32.lib;secur32.lib;ws2_32.lib;iphlpapi.lib` to Linker -> Input -> Additional Dependencies.

### Files that must be compiled

Add every `.cpp` under `src/`:

```text
client.cpp
curl_http.cpp
errors.cpp
integrity.cpp
invisiblefolder.cpp
management.cpp
quicksilver.cpp
security.cpp
sha1.cpp
util.cpp
variables.cpp
```

Invisible Folder Advanced downloads are included in the public API through
`Client::invisibleFolder()`. Startup token prefetch is best-effort and silent;
downloads request a token on demand when needed, and a server-rejected cached
token is refreshed and retried once per download call.

### Minimal include

In your application code, include:

```cpp
#include <syslocker/syslocker.hpp>
```

### Important notes

- Source-embed mode still depends on libcurl.
- `ws2_32.lib` comes from the Windows SDK and should not be redistributed.
- Build your app, libcurl, and SystemLocker for the same architecture,
  typically `x64`.

## Which option should you choose?

Choose `static/` if:

- you want the quickest Visual Studio setup
- you want the library already built
- you are distributing the same known-good binary to multiple projects

Choose source-embed if:

- you want the implementation compiled inside your project
- you do not want to link `syslocker.lib`
- you want to step through the SystemLocker source directly in your app build

## Basic usage

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

    // // // // // // // // // // // // // // // // // // // // // //
    // Optional: download files from Invisible Folder
    // Invisible Folder storage is included with all subscriptions
    // Link your account at https://systemlocker.net/devs/account

    // Save to a file
    auto saved = client.invisibleFolder().downloadToFile(*reference, destination);

    if (!saved)
    {
        std::cerr << "[if] download error  : " << saved.error() << '\n';
        return 1;
    }

    // Or, keep it in memory:
    auto bytes = client.invisibleFolder().download(*reference);
    if (!bytes)
    {
        std::cerr << "[if] download error  : " << bytes.error() << '\n';
        return 1;
    }
    std::cout << "[if] downloaded bytes: " << bytes->size() << '\n';

    return 0;
}
```
