# System Locker C++ 2.0.0 legacy static package

This Windows x64 Release package is a migration bridge to
[System Locker Bedrock C++](https://github.com/systemlocker/System-Locker-Bedrock-CPP).
The generic client is being sunset; Quicksilver support will phase out in early
2027. This build uses Bedrock and Management v2 through the legacy interfaces.
See the [library guide](https://github.com/systemlocker/System-Locker-CPP#updating-an-existing-integration) for compatibility limits and migration.

Use matching headers and libraries together and rebuild your application.

1. Set Visual Studio to C++20, x64, and Release with the `/MD` runtime.
2. Add this package's `include/` directory to C/C++ include paths.
3. Add its `lib/` directory to linker paths.
4. Link `syslocker.lib;libcurl.lib;libcrypto.lib;bcrypt.lib;advapi32.lib;crypt32.lib;secur32.lib;ws2_32.lib;iphlpapi.lib;user32.lib`.
5. Set the new required `Config::signingPublicKey` to your system's base64url
   Ed25519 public key from the dashboard. Management helpers need an `slm_`
   v2 bearer credential in `Config::apiKey`.

```cpp
#include <syslocker/syslocker.hpp>

syslocker::Config cfg;
cfg.systemId = "YOUR_20_CHARACTER_ID";
cfg.signingPublicKey = "YOUR_BASE64URL_ED25519_PUBLIC_KEY";
cfg.hwid = "YOUR_STABLE_DEVICE_ID";
syslocker::Client client(cfg);
auto result = client.authenticateWithKey("YOUR_LICENSE_KEY");
```

Keep `client` alive during protected work and handle heartbeat failure.
`hwid = "1"` retains the legacy opt-out from device checks. The API surface
is source-compatible where possible; this is not a binary ABI-compatible update.

The package includes public headers, `syslocker.lib`, static libcurl and
OpenSSL Crypto libraries, dependency licenses, and third-party notices. No curl
or OpenSSL DLLs are required. Redistribute the included licenses with the SDK.
