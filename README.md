# VirusTotalCpp.V3

A C++17 client library for the **VirusTotal API v3**, ported from the feature
surface of [VirusTotalNet](https://github.com/Genbox/VirusTotalNet) (C#, API v2).

The **v1.0.0** release implements the file check-then-scan flow: look a file hash
up, and if VirusTotal has never seen it, submit the file for scanning.

## Status - v1.0.0

Implemented in this release:

- `get_file_report(hash)` - ask VirusTotal whether a file hash (md5/sha1/sha256)
  has already been scanned (`GET /files/{id}`)
- `scan_file(...)` - submit a file for scanning, returns the analysis id and the
  file identifiers (`POST /files`, multipart, <= 32 MB)
- `get_public_file_scan_link(hash)` - public virustotal.com report URL for a hash
- CLI `vtapi_eicar` - drive both steps of the flow from a shell

Planned for later releases:

- URLs, IP addresses and domains: report, rescan
- Comments: list and add per object type
- Analysis polling (`GET /analyses/{id}`)
- Large-file upload (> 32 MB), downloads, behaviour reports

Endpoints are implemented one at a time.

## Requirements

- CMake >= 3.20 and a C++17 compiler
- OpenSSL and zlib development headers

libcurl is fetched and built from source automatically, so a system libcurl
package is **not** required.

## Installation

### vcpkg

```sh
vcpkg install vtapi
```

```cmake
find_package(vtapi CONFIG REQUIRED)
target_link_libraries(your_app PRIVATE vtapi::vtapi)
```

### CMake FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(vtapi
  GIT_REPOSITORY https://github.com/zymuk/VirusTotalCpp.V3.git
  GIT_TAG v1.0.0)
FetchContent_MakeAvailable(vtapi)

target_link_libraries(your_app PRIVATE vtapi::vtapi)
```

### Building this repository directly

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

## Usage

### Library

```cpp
#include <vtapi/client.hpp>

vtapi::ClientOptions options;
options.api_key = "your-api-key";           // or read it from the environment

vtapi::VirusTotal client(std::move(options));

try {
    vtapi::FileReport report = client.get_file_report(sha256);
    // Already scanned: inspect report.last_analysis_stats / last_analysis_results.
} catch (const vtapi::NotFound&) {
    // Never seen: submit it for scanning.
    vtapi::ScanResult scan = client.scan_file("/path/to/file");
    // scan.id             -> analysis id (for later GET /analyses/{id})
    // scan.file_info.sha256 -> the file's sha256, for a later get_file_report()
}
```

### CLI

The `vtapi_eicar` demo drives the check-then-scan flow from a shell. The API key
comes from `--key` or the `VIRUSTOTAL_API_KEY` environment variable.

```sh
# Step 1 - has this file been scanned before?
vtapi_eicar report --hash <md5|sha1|sha256>

# Step 2 - if not, submit it for scanning (files up to 32 MB)
vtapi_eicar scan-file --path <file> [--password <pw>]
```

A full check-then-scan round trip:

```sh
vtapi_eicar report --hash "$SHA256"      # Seen before: No
vtapi_eicar scan-file --path eicar.com   # Uploaded. analysis id: ...
vtapi_eicar report --hash "$SHA256"      # Seen before: Yes (once scanning completes)
```

Options (before the command): `--key <key>`, `--base-url <url>`,
`--timeout <seconds>`, `--no-verify-ssl`, `--rpm <n>`. Running the CLI with no
arguments prints the usage. Exit codes: `0` success, `1` runtime error,
`2` usage error.

## API reference

| Method | VirusTotal endpoint |
|---|---|
| `FileReport get_file_report(hash)` | `GET /files/{id}` (`id` = md5/sha1/sha256) |
| `ScanResult scan_file(data, filename, password = {})` | `POST /files` (multipart, <= 32 MB) |
| `ScanResult scan_file(path, password = {})` | `POST /files` (reads the file, sends its basename) |
| `std::string get_public_file_scan_link(hash)` | no request - builds `https://www.virustotal.com/gui/file/{id}/detection` |

The response models match the v3 JSON payloads (`FileReport` from
`data.attributes.*`, `ScanResult` from `data.*` plus `meta.file_info.*`). Field
names and types follow the real API rather than another client library.

## Errors

Every failure is derived from `vtapi::VtError`:

| Exception | Raised when |
|---|---|
| `AuthError` | HTTP 403 - invalid or missing API key |
| `NotFound` | HTTP 404 - the object was never scanned |
| `RateLimit` | HTTP 429 - the rate limit was exceeded |
| `ApiError` | any other non-2xx status (`http_status()`, `api_code()`) |
| `NetworkError` | transport failure (DNS, connect, timeout) |

## Rate limits

Public API keys are limited to **4 requests per minute** and 500 per day. The
client applies a token-bucket limiter (4/min by default, configurable via
`ClientOptions::requests_per_minute`) before every request and surfaces HTTP 429
as `RateLimit`. Premium keys can raise the limit to match their quota.

## License

MIT - see [LICENSE.txt](LICENSE.txt).
