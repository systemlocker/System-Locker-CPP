# SystemLocker C++ Implementation

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
third_party/curl/        bundled curl headers and runtime/import library
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
  bin/*.dll
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
third_party/curl/bin/*.dll
```

### Visual Studio setup

1. Set your project to C++20.
2. Add all `.cpp` files from `src/` to your project.
3. Keep the private headers from `src/` beside those `.cpp` files.
4. Add `include/` to C/C++ -> General -> Additional Include Directories.
5. Add `third_party/curl/include/` to C/C++ -> General -> Additional Include Directories.
6. Add `third_party/curl/lib/` to Linker -> General -> Additional Library Directories.
7. Add `libcurl.lib;ws2_32.lib` to Linker -> Input -> Additional Dependencies.
8. Copy every DLL from `third_party/curl/bin/` beside your final `.exe`.

### Files that must be compiled

Add every `.cpp` under `src/`:

```text
client.cpp
curl_http.cpp
errors.cpp
integrity.cpp
management.cpp
quicksilver.cpp
security.cpp
sha1.cpp
util.cpp
variables.cpp
```

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
- Keep the complete curl runtime set in `third_party/curl/bin/`; if your
  libcurl build depends on `z.dll`, OpenSSL DLLs, or Brotli DLLs, ship those
  beside your app too.

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

    return 0;
}
```

## Release notes for maintainers

When updating this publish repo for a new release:

1. Run `../package-publish.ps1` from this folder, or run `./package-publish.ps1` from the main repository root.
2. If this machine needs a custom CMake location, pass `-CMakeBinDir "C:\path\to\cmake\bin"`.
3. Commit the refreshed `publish/` contents to the public repository.
4. Include the correct libcurl license/notice files before publishing a release.

Example:

```powershell
./package-publish.ps1 -CMakeBinDir "C:\Program Files\CMake\bin"
```

If you already have a valid `build/Release/syslocker.lib` and only want to
restage the publish tree, use:

```powershell
./package-publish.ps1 -SkipBuild
```
