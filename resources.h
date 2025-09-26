#pragma once


namespace wibo {

struct Executable;
struct ImageResourceDataEntry;

bool resourceEntryBelongsToExecutable(const Executable &exe, const ImageResourceDataEntry *entry);
ResourceIdentifier resourceIdentifierFromAnsi(const char *id);
ResourceIdentifier resourceIdentifierFromWide(const uint16_t *id);

}
