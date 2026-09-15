# VirusTotalCpp.V3

A C++17 client library for the **VirusTotal API v3**, ported from the feature
surface of [VirusTotalNet](https://github.com/Genbox/VirusTotalNet) (C#, API v2).

## Features (initial — files)

Working today:

- `get_file_report(hash)` — ask VirusTotal whether a file hash (md5/sha1/sha256)
  has already been scanned (`GET /files/{id}`)
- `scan_file(data, filename, password)` — submit a file for scanning, returns
  the analysis id (`POST /files`, multipart, ≤32MB)

Planned for later milestones:

- URLs, IP addresses and domains: report, rescan
- Comments: list and add per object type
- Analysis polling (`GET /analyses/{id}`)
- CLI (`vtapi_eicar`), GUI links, vcpkg port, CI
- Large-file upload (>32MB), downloads, behaviour reports

Endpoints are being implemented one at a time.

## Status

File lookup + scan upload are implemented and covered by tests (local mock
HTTP server, no network required). The CLI smoke flow is next.

## Build

Requirements: CMake ≥ 3.20, a C++17 compiler, OpenSSL + zlib dev packages.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

libcurl is fetched and built from source automatically (no system libcurl
headers required).

## License

MIT — see [LICENSE.txt](LICENSE.txt).