cmake_minimum_required(VERSION 3.20)

project(vtapi VERSION 0.1.0 DESCRIPTION "C++17 VirusTotal API v3 client" LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

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
# vtapi core library (endpoint implementations land incrementally)
# ---------------------------------------------------------------------------
add_library(vtapi
  src/version.cpp
)
add_library(vtapi::vtapi ALIAS vtapi)

target_include_directories(vtapi PUBLIC
  $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
  $<INSTALL_INTERFACE:include>
)
target_link_libraries(vtapi PUBLIC vtapi_json)
target_compile_features(vtapi PUBLIC cxx_std_17)

# ---------------------------------------------------------------------------
# Example CLI (EICAR demo)
# ---------------------------------------------------------------------------
add_executable(vtapi_eicar examples/eicar_cli/main.cpp)
target_link_libraries(vtapi_eicar PRIVATE vtapi)

# ---------------------------------------------------------------------------
# Install
# ---------------------------------------------------------------------------
include(GNUInstallDirs)
install(TARGETS vtapi vtapi_json vtapi_eicar
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