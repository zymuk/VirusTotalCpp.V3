#include "vtapi/version.hpp"

namespace vtapi {

// Placeholder definition so the core library contains a real translation unit.
// Endpoint implementations land milestone by milestone (see docs/roadmap.md).
const char* version_string() { return kVersion; }

} // namespace vtapi