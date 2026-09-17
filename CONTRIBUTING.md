# Contributing

Thanks for wanting to improve VirusTotalCpp.V3. Please keep changes small and
focused, and always run the test suite before submitting.

## Project layout

- `include/vtapi/` - public headers (the API surface).
- `src/` - implementation.
- `examples/eicar_cli/` - the demo CLI (`report --hash`, `scan-file --path`).
- `tests/` - a tiny dependency-free test harness plus a local mock HTTP server;
  the suite talks to mocks, never to the real VirusTotal API.
- `cmake/` - packaging helpers (the CMake package config template).
- `portfiles/vcpkg/` - the vcpkg port definition.
- `third_party/` - vendored `nlohmann/json` (single header).

## Building and testing

Requirements: a C++17 compiler, CMake >= 3.20, and the development headers for
OpenSSL and zlib. libcurl is built automatically from source (it is pinned and
fetched by CMake when no system copy is found), so you do not need to install
curl separately.

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build
ctest --test-dir build --output-on-failure
```

Optional switches:
- `-DVTAPI_BUILD_TESTS=OFF` turns off the test suite.
- `-DVTAPI_BUILD_EXAMPLE=OFF` turns off the demo CLI (the tests exercise the CLI,
  so enabling tests requires the example).

## Code conventions

- C++17 only; prefer RAII, exceptions, and the standard library.
- Comments in English, explaining the *why*, not the *what*.
- Public API lives in namespace `vtapi`; method names follow VirusTotalNet
  naming (`get_file_report`, `scan_file`, ...).
- Response models mirror the v3 JSON payload exactly: field names and types come
  from the real API, extra fields are ignored.
- There are no batch endpoints in API v3; loop and use the built-in rate
  limiter instead of parallel calls.
- Errors are thrown as the vtapi exception hierarchy (`AuthError`,
  `NotFound`, `RateLimit`, `ApiError`, `NetworkError`); never translate a
  non-2xx response into a success return.

## Adding an endpoint

Work top-down, one endpoint at a time:

1. Add the response model and a JSON fixture in `tests/fixtures/` copied from a
   real v3 response.
2. Add the client method and a unit test against the mock HTTP server (no
   network required, no API key).
3. Build and run `ctest`; keep it green.
4. Expose it through the CLI only if it belongs to a supported flow.

## Commits

- One focused change per commit; each endpoint lands with its own test.
- Conventional prefixes: `feat:`, `fix:`, `test:`, `docs:`, `ci:`, `build:`,
  `chore:`.
- Short, imperative subject line.

## Reporting bugs

Open an issue with the reproduction steps, version, and platform. For security
problems, follow SECURITY.md instead.