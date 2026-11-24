# System Locker C++ (legacy)

![System Locker Logo](logo.png)

> [!WARNING]
> This library is being sunset. Use [System Locker Bedrock C++](https://github.com/systemlocker/System-Locker-Bedrock-CPP)
> for new integrations and migrate existing applications to it. Quicksilver
> support will phase out in early 2027.

Version **2.0.0**.

This update is a compatibility bridge for developers migrating from the generic
C++ client. It uses **Bedrock** authentication and **Management API v2** behind
its existing interfaces. It intentionally exposes only the legacy feature set;
the dedicated Bedrock library is the supported path for Bedrock's full features.
There is no Quicksilver or Management v1 fallback.

## Updating an existing integration

1. Replace the library's source or static package and rebuild your application.
2. Download your system's Ed25519 public signing key from the System Locker
   dashboard and set `Config::signingPublicKey`. Use the base64url-encoded raw
   32-byte key. This is a public verification key, separate from the optional
   TLS certificate pin; never distribute a private signing key.
3. If you use management helpers, replace `Config::apiKey` with a Management v2
   `slm_` bearer credential for the same system, with the scopes needed for your
   operations. Keep management credentials in trusted server-side applications.
4. Review the compatibility limits below, then plan your migration to the
   [Bedrock C++ client](https://github.com/systemlocker/System-Locker-Bedrock-CPP).

Existing `Client`, `Config`, `Result<T>`, authentication methods, identity
queries, heartbeat hooks, variables, and download methods retain their names
and C++ result types. The signing key is the only new authentication setting.
Recompile all consumers: this update does not preserve binary ABI compatibility.

```cpp
#include <syslocker/syslocker.hpp>
#include <iostream>

int main()
{
    syslocker::Config cfg;
    cfg.systemId = "YOUR_20_CHARACTER_ID";
    cfg.signingPublicKey = "YOUR_BASE64URL_ED25519_PUBLIC_KEY";
    cfg.version = "1.0";
    cfg.hwid = "YOUR_STABLE_DEVICE_ID";
    // cfg.programDigest = "YOUR_PROGRAM_HASH"; // When required by your system.

    syslocker::Client client(cfg);
    client.onHeartbeatFailure([](const syslocker::HeartbeatFailure& failure) {
        std::cerr << "Session ended: " << failure.message << '\n';
        // Signal your main thread to stop protected work.
    });
    auto auth = client.authenticateWithKey("YOUR_LICENSE_KEY");
    // Account authentication: client.authenticateWithPassword(username, password).
    if (!auth) {
        std::cerr << auth.error() << '\n';
        return 1;
    }

    // Keep client alive while protected work runs. Stop that work if the
    // failure hook fires or client.isAuthenticated() becomes false.
    return 0;
}
```

The legacy default `hwid = "1"` still disables device checks. Supply your own
stable HWID when device locking is needed. This bridge does not adopt the
Bedrock client's automatic hardware identification. `version = "bypass"`
still skips the server's version gate.

## Compatibility limits

- Both authentication methods now call `/auth/bedrock/init`; the background
  worker uses `/auth/bedrock/beat`. Responses are verified using Ed25519 before
  parsing, then checked for challenge, system, signing-key ID, freshness,
  response flags, token prefixes, and the submitted identity's SHA-256 hash.
- `InitSuccess::token` now starts with `BRK_`; heartbeat tokens start with
  `BRF_`. `username`/`identity()` retain the submitted identity after its hash
  is verified. `serverEpoch29` remains `floor(server_time / 29)` for callers
  that still read this field. The `QuicksilverSession` type name is retained
  for source compatibility; it runs Bedrock.
- Errors remain strings. Signed denials include the Bedrock response code and
  human message; Google SSO denials also include the portal URL. The legacy
  error enums and text parsers remain available but do not describe every
  Bedrock denial. A terminal heartbeat still ends the local session and fires
  the existing failure hook. Developer termination reasons remain available
  through `BeatError::Terminated` and `terminationReason`.
- `redeemedUserCount()` returns v2's periodically refreshed `total_users`.
  `keyStatus()` returns `user`, `mikros`, or `unclaimed`. `keyExpiration().raw`
  contains the UTC timestamp, or an empty string when unset. An unredeemed
  duration key is not reported as permanent just because its date is unset.
- `generateKeys()` keeps newline-delimited keys and the existing expiry
  presets. Other management mutations return JSON data serialized into the
  existing string result. Server errors include their v2 machine code.
- `resetHwid(key, false)` keeps self-service cooldown behavior via the current
  `/auth` reset intent. Administrative resets use Management v2.
- `adjustExpiry()` retains its signature but returns an error without sending
  a request: Management v2 cannot set an existing key's absolute expiry.
  Migrate that operation to the current Management API's add-time operation.
- Direct three-argument `Management` construction discovers the credential's
  system through `/api/v2/systems`, requiring `systems.read`. Pass the system
  ID as the optional fourth argument, or use `Client::management()`, to avoid
  discovery.

## Invisible Folder downloads

`Client::invisibleFolder()` retains `download()`, `downloadToFile()`,
`ensureToken()`, and `hasValidToken()`. Enable startup token prefetch with:

```cpp
syslocker::AuthenticationOptions options;
options.prefetchInvisibleFolderToken = true;
auto auth = client.authenticateWithKey("YOUR_LICENSE_KEY", options);
if (auth) {
    auto bytes = client.invisibleFolder().download("your_reference_id");
}
```

Tokens now come from signed Bedrock init/heartbeat responses. Prefetch remains
best-effort: an omitted token does not fail authentication. Without a cached
token, a download waits for the next scheduled heartbeat, which requests one.
This can take up to `beatRate` plus request time. Concurrent downloads share
that refresh. No extra heartbeat is sent, because Bedrock rejects early beats.
A token denial (including a concealed `404 not_found` response for a protected
file) is refreshed and the download retried once.
Shutdown or heartbeat failure clears cached access and wakes pending refreshes.

Downloads use `GET /a/{reference_id}` on `Config::invisibleFolderBaseUrl` with
`X-Invisiblefolder-Download: 1` and `X-Invisiblefolder-Token`. Reference IDs must
contain 4-128 letters, digits, underscores, or hyphens. Download-to-file writes
unencrypted bytes and overwrites the destination.

## Integration

[Download the Windows x64 SDK 2.0.0](static/systemlocker-sdk-2.0.0-win64-static.zip).

Use the prebuilt Windows x64 package in [`static/`](static/README.md), or copy
`include/`, `src/`, and `third_party/` into your project. Source integration
requires C++20, libcurl, OpenSSL 1.1.1 or later with Ed25519 support, and threads.
The bundled JSON header is private to `src/`; add every `src/*.cpp` and keep
all adjacent private headers when embedding the source.

For Visual Studio source integration, add `include/`,
`third_party/curl/include/`, and `third_party/openssl/include/` to include
paths, and the two dependency `lib/` directories to linker paths. Define
`CURL_STATICLIB`. Use `/MD` in Release to match the bundled Windows libraries.
Link `libcurl.lib;libcrypto.lib;bcrypt.lib;advapi32.lib;crypt32.lib;secur32.lib;ws2_32.lib;iphlpapi.lib;user32.lib`.
For the prebuilt package, also link `syslocker.lib`.

The bundled libraries target Windows x64 Release. Linux/macOS consumers need
native libcurl and OpenSSL packages; Linux also needs `-ldl` for the existing
local integrity checks.

Custom `IHttpClient` implementations keep the original `post()` entry point,
but must now populate `HttpResponse::headers` for Bedrock verification. Header
lookup is case-insensitive. Implement the new defaulted `request()` method for
Management JSON requests and Invisible Folder GET requests. Its default returns
an unsupported-operation error, leaving older form-only transports compilable.
Enforce HTTPS, validate TLS certificates, reject redirects, and limit auth and
management response bodies to 1 MiB.

## Security notes

> [!WARNING]
> Watch this repository (Watch ? Custom ? Releases) and update your
> dependency when a release ships: releases regularly add security
> enhancements.

The pinned Bedrock public key verifies the server's signed responses. TLS
certificate checks remain enabled; `pinnedPublicKeySha256Base64` remains an
optional TLS SPKI pin and does not replace the Bedrock signing key. A lost
heartbeat response is retried once with the same token and challenge. Init
and Management mutations are not retried.

The existing debugger, clock-jump, and code-integrity checks remain. Local
checks cannot prevent an attacker with control of the process from patching
an application. Keep protected work tied to the live session. Failure hooks
run on the heartbeat thread: signal another thread rather than destroying the
client or calling `shutdown()` from the hook.

See [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) for dependency licenses.

## Public documentation and examples

- [Developer resources](https://systemlocker.net/developers) - public index of SDKs, release history, and examples.
- [C++ library guide](https://systemlocker.net/blog/use-system-locker-cpp-library) - source-embedding, static-package, authentication, and heartbeat walkthrough.
- [Windows C++ example](https://systemlocker.net/blog/protect-windows-cpp-app) - historical key-only integration; see the migration requirements below.
- [API documentation repository](https://github.com/systemlocker/documentation) - public documentation copy.
- [SDK releases](https://github.com/systemlocker/System-Locker-CPP/releases) - published packages and release notes.
- [System Locker GitHub organization](https://github.com/systemlocker) - related public repositories.
