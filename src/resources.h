#pragma once

#include <cstdint>

namespace wibo {

struct Executable;
struct ImageResourceDataEntry;
struct ResourceIdentifier;

bool resourceEntryBelongsToExecutable(const Executable &exe, const ImageResourceDataEntry *entry);
ResourceIdentifier resourceIdentifierFromAnsi(const char *id);
ResourceIdentifier resourceIdentifierFromWide(const uint16_t *id);

} // namespace wibo
