#pragma once

namespace vtapi {

// Library version. Sole source of truth: CMake parses it at configure time
// (see CMakeLists.txt), so bump only this constant.
constexpr const char* kVersion = "0.3.1";

// Returns kVersion ("X.Y.Z"). Defined in src/version.cpp.
const char* version_string();

} // namespace vtapi