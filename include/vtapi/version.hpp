#pragma once

namespace vtapi {

// Library version (kept in sync with the CMake project VERSION).
constexpr const char* kVersion = "0.2.0";

// Returns kVersion ("X.Y.Z"). Defined in src/version.cpp.
const char* version_string();

} // namespace vtapi