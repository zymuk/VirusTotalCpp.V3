# VirusTotalCpp.V3

A C++17 client library for the **VirusTotal API v3**, ported from the feature
surface of [VirusTotalNet](https://github.com/Genbox/VirusTotalNet) (C#, API v2).

## Features (initial — files)

Working today:

- `get_file_report(hash)` — ask VirusTotal whether a file hash (md5/sha1/sha256)
  has already been scanned (`GET /files/{id}`)
- `scan_file(data, filename, password)` — submit a file for scanning, returns
  the analysis id (`POST /files`, multipart, ≤32MB)
- CLI `vtapi_eicar report --hash <hash>` — print whether a hash was already
  scanned and, if so, a short verdict summary
- CLI `vtapi_eicar scan-file --path <file>` — submit a file from the shell and
  print the analysis id plus the locally computed sha256

Planned for later milestones:

- URLs, IP addresses and domains: report, rescan
- Comments: list and add per object type
- Analysis polling (`GET /analyses/{id}`)
- GUI links, vcpkg port, CI
- Large-file upload (>32MB), downloads, behaviour reports

Endpoints are being implemented one at a time.

## Status

File lookup, scan upload and the `report`/`scan-file` CLI commands are
implemented and covered by tests (local mock HTTP server, no network required).
The check-then-scan flow runs end to end; CLI usage is documented below.

## Build

Requirements: CMake ≥ 3.20, a C++17 compiler, OpenSSL + zlib dev packages.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Release
cmake --build build
ctest --test-dir build --output-on-failure
```

libcurl is fetched and built from source automatically (no system libcurl
headers required).

## CLI usage

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

## License

MIT — see [LICENSE.txt](LICENSE.txt).