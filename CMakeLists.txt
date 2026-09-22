cmake_minimum_required(VERSION 3.20)

# The version is read from include/vtapi/version.hpp (single source of truth),
# so bump the header only. The description is fixed metadata, kept inline.
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/include/vtapi/version.hpp" _vtapi_version_header)
if (_vtapi_version_header MATCHES "kVersion[ \t]*=[ \t]*\"([0-9]+\\.[0-9]+\\.[0-9]+)")
  set(VTAPI_VERSION "${CMAKE_MATCH_1}")
else()
  message(FATAL_ERROR "Could not extract the version from include/vtapi/version.hpp")
endif()
project(vtapi VERSION ${VTAPI_VERSION}
        DESCRIPTION "C++17 VirusTotal API v3 client" LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# Consumers can disable the demo/test targets (e.g. the vcpkg port installs the
# library only). Both default to ON so a plain checkout builds everything.
option(VTAPI_BUILD_TESTS "Build the test suite" ON)
option(VTAPI_BUILD_EXAMPLE "Build the vtapi_eicar CLI example" ON)

# Source and string literals are UTF-8 (the CLI prints "->" as an arrow); MSVC
# must be told explicitly or narrow strings get mis-decoded.
if(MSVC)
  add_compile_options(/utf-8)
endif()

# Prefer static linking (single-binary distribution); override with -DBUILD_SHARED_LIBS=ON.
set(BUILD_SHARED_LIBS OFF CACHE BOOL "build shared libs")

# ---------------------------------------------------------------------------
# Vendored nlohmann/json (single header, MIT).
# ---------------------------------------------------------------------------
add_library(vtapi_json INTERFACE)
target_include_directories(vtapi_json INTERFACE
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/third_party>
  $<INSTALL_INTERFACE:include>
)

# ---------------------------------------------------------------------------
# libcurl + OpenSSL. Prefer an already-installed curl (vcpkg or system) so the
# package manager provides it; otherwise build a pinned curl from source via
# FetchContent (https-only build keeps the dependency surface small).
# ---------------------------------------------------------------------------
find_package(CURL QUIET)
if(NOT CURL_FOUND)
  include(FetchContent)
  set(CURL_PIN "curl-8_22_0")
  FetchContent_Declare(curl
    URL https://github.com/curl/curl/releases/download/${CURL_PIN}/curl-8.22.0.tar.gz
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE)
  set(HTTP_ONLY ON)            # http+https only
  set(CURL_BUILD_TESTS OFF)
  set(CURL_BUILD_EXAMPLES OFF)
  set(CURL_BUILD_TOOLS OFF)
  set(CURL_USE_OPENSSL ON)     # system OpenSSL
  set(CURL_USE_LIBPSL OFF)
  set(CURL_USE_LIBIDN2 OFF)
  set(CURL_USE_LIBSSH2 OFF)
  set(CURL_USE_BROTLI OFF)
  set(CURL_USE_ZSTD OFF)
  set(CURL_DISABLE_LDAP ON)
  set(CURL_DISABLE_LDAPS ON)
  set(CURL_DISABLE_DICT ON)
  set(CURL_DISABLE_TELNET ON)
  set(CURL_DISABLE_TFTP ON)
  set(CURL_DISABLE_POP3 ON)
  set(CURL_DISABLE_IMAP ON)
  set(CURL_DISABLE_SMTP ON)
  set(CURL_DISABLE_RTSP ON)
  set(CURL_DISABLE_GOPHER ON)
  FetchContent_MakeAvailable(curl)
endif()
find_package(OpenSSL REQUIRED)

# ---------------------------------------------------------------------------
# vtapi core library (endpoint implementations land incrementally)
# ---------------------------------------------------------------------------
add_library(vtapi
  src/version.cpp
  src/hashing.cpp
  src/http.cpp
  src/response.cpp
  src/file_report.cpp
  src/scan_result.cpp
  src/behaviour.cpp
  src/mitre.cpp
  src/relationship.cpp
  src/sigma_rule.cpp
  src/yara_ruleset.cpp
  src/client.cpp
)
add_library(vtapi::vtapi ALIAS vtapi)

target_include_directories(vtapi PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(vtapi PUBLIC
  vtapi_json
  CURL::libcurl
  OpenSSL::SSL OpenSSL::Crypto
)
target_compile_features(vtapi PUBLIC cxx_std_17)

# ---------------------------------------------------------------------------
# Example CLI (EICAR demo)
# ---------------------------------------------------------------------------
if(VTAPI_BUILD_EXAMPLE)
  add_executable(vtapi_eicar examples/eicar_cli/main.cpp)
  target_link_libraries(vtapi_eicar PRIVATE vtapi)
endif()

# ---------------------------------------------------------------------------
# Tests (micro-harness, no external test framework)
# ---------------------------------------------------------------------------
if(VTAPI_BUILD_TESTS)
  if(NOT VTAPI_BUILD_EXAMPLE)
    message(FATAL_ERROR "VTAPI_BUILD_TESTS requires VTAPI_BUILD_EXAMPLE (tests spawn the CLI)")
  endif()
  enable_testing()
  add_executable(vtapi_tests tests/run_tests.cpp)
  target_link_libraries(vtapi_tests PRIVATE vtapi)
  # The tests that spawn the CLI use fork/exec and are POSIX only, so the path
  # is only needed (and only defined) off Windows.
  if(NOT WIN32)
    target_compile_definitions(vtapi_tests PRIVATE
      VTAPI_EICAR_BIN="$<TARGET_FILE:vtapi_eicar>")
  endif()
  add_test(NAME vtapi_tests COMMAND vtapi_tests)
endif()

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
set(VTAPI_INSTALL_TARGETS vtapi vtapi_json)
if(VTAPI_BUILD_EXAMPLE)
  list(APPEND VTAPI_INSTALL_TARGETS vtapi_eicar)
endif()
install(TARGETS ${VTAPI_INSTALL_TARGETS}
  EXPORT vtapiTargets
  RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
  LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
  ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)
install(DIRECTORY include/vtapi DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(DIRECTORY third_party/nlohmann DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})
install(EXPORT vtapiTargets
  NAMESPACE vtapi::
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vtapi
)

# Package config so consumers can find_package(vtapi CONFIG REQUIRED).
include(CMakePackageConfigHelpers)
configure_package_config_file(
  "${CMAKE_CURRENT_SOURCE_DIR}/cmake/vtapiConfig.cmake.in"
  "${CMAKE_CURRENT_BINARY_DIR}/vtapiConfig.cmake"
  INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vtapi
)
write_basic_package_version_file(
  "${CMAKE_CURRENT_BINARY_DIR}/vtapiConfigVersion.cmake"
  VERSION ${VTAPI_VERSION}
  COMPATIBILITY AnyNewerVersion
)
install(FILES
  "${CMAKE_CURRENT_BINARY_DIR}/vtapiConfig.cmake"
  "${CMAKE_CURRENT_BINARY_DIR}/vtapiConfigVersion.cmake"
  DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/vtapi
)