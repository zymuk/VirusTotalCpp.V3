#include "vtapi/version.hpp"

namespace vtapi {

// Placeholder definition so the core library contains a real translation unit.
// Endpoint implementations land incrementally.
const char* version_string() { return kVersion; }

} // namespace vtapi