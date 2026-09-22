# VirusTotalCpp.V3

A C++17 client library for the **VirusTotal API v3**, ported from the feature
surface of [VirusTotalNet](https://github.com/Genbox/VirusTotalNet) (C#, API v2).

The **v1.2.x** releases build on the v1.0.0 file check-then-scan flow and add the
rest of the file API: large scans, downloads, rescanning, behaviour reports,
Sigma/YARA rules, MITRE summaries and file relationships.

## Status - v1.2.0

Implemented:

- `get_file_report(hash)` - ask VirusTotal whether a file hash (md5/sha1/sha256)
  has already been scanned (`GET /files/{id}`)
- `scan_file(...)` - submit a file for scanning, returns the analysis id and the
  file identifiers (`POST /files`, multipart, <= 32 MB)
- `scan_large_file(...)` - two-step upload for files up to 650 MB
- `get_file_download_url(hash)` / `download_file(hash, path)` - fetch the raw file (premium)
- `rescan_file(hash)` / `rescan_files(hashes)` - request a fresh analysis
- `get_file_reports(hashes)` - loop over `get_file_report`
- behaviour reports: list, summary, single report, HTML/EVTX/PCAP/memory-dump
- Sigma rules, YARA rulesets, MITRE ATT&CK summaries, file relationships
- `get_public_file_scan_link(hash)` - the public virustotal.com report URL
- CLI `vtapi_eicar` - drive the file flow from a shell

Planned for later releases:

- URLs, IP addresses and domains: report, rescan
- Comments: list and add per object type
- Analysis polling (`GET /analyses/{id}`)

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

Files too large for the direct upload (up to 32 MB) go through the two-step
flow instead — VirusTotal first returns a signed `upload_url`, then you POST
the file to it:

```sh
vtapi_eicar scan-large-file --path big.bin  # Uploaded (two-step). analysis id: ...
vtapi_eicar report --hash "$SHA256"          # Seen before: Yes
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
| `ScanResult scan_large_file(data\|path, password = {})` | `GET /files/upload_url` then `POST {url}` (up to 650 MB) |
| `std::string get_file_download_url(hash)` | `GET /files/{id}/download_url` (premium) |
| `void download_file(hash, dest_path)` | `GET /files/{id}/download` (premium) |
| `ScanResult rescan_file(hash)` | `POST /files/{id}/analyse` |
| `std::vector<ScanResult> rescan_files(hashes)` | loop `POST /files/{id}/analyse` |
| `std::vector<FileReport> get_file_reports(hashes)` | loop `GET /files/{id}` |
| `BehaviourList get_file_behaviours(hash)` | `GET /files/{id}/behaviours` |
| `BehaviourSummary get_file_behaviour_summary(hash)` | `GET /files/{id}/behaviour_summary` |
| `FileBehaviour get_file_behaviour(sandbox_id)` | `GET /file_behaviours/{id}` |
| `RelationshipList get_file_behaviour_relationships(sandbox_id, rel)` | `GET /file_behaviours/{id}/{rel}` |
| `std::string get_file_behaviour_file(sandbox_id, format)` | `GET /file_behaviours/{id}/{html\|evtx\|pcap\|memdump}` |
| `SigmaRule get_sigma_rule(id)` | `GET /sigma_rules/{id}` |
| `YaraRuleset get_yara_ruleset(id)` | `GET /yara_rulesets/{id}` |
| `MitreSummary get_mitre_summary(hash)` | `GET /files/{id}/behaviour_mitre_trees` |
| `RelationshipList get_file_relationships(hash, rel)` | `GET /files/{id}/relationships/{rel}` |

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
