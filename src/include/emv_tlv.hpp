#pragma once

#include "duckdb.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace duckdb {
namespace cardtrace {

enum class EmvSensitivity : uint8_t {
	NONE = 0,
	PAN = 1,
	TRACK = 2,
	PIN = 3,
};

struct EmvTlvEntry {
	string tag_hex;
	string name;
	idx_t length = 0;
	string value_hex;
	string decoded; // empty means SQL NULL
	EmvSensitivity sensitivity = EmvSensitivity::NONE;
	bool constructed = false;
	idx_t depth = 0;
};

struct EmvParseResult {
	vector<EmvTlvEntry> entries;
	string error; // empty on success
};

//! Convert hex string (optional spaces/colons/0x) to bytes. Throws on invalid input.
vector<uint8_t> ParseHex(const string &hex);

//! Encode bytes as uppercase hex without separators.
string ToHex(const uint8_t *data, idx_t len);

//! Lookup EMVCo tag name; returns empty string if unknown.
string LookupTagName(const string &tag_hex);

//! Sensitivity classification for a tag.
EmvSensitivity LookupTagSensitivity(const string &tag_hex);

//! Decode a BER-TLV payload (bytes). Nested constructed tags are flattened with depth.
EmvParseResult DecodeBerTlv(const uint8_t *data, idx_t size, bool recurse_constructed = true);

//! Decode from hex string.
EmvParseResult DecodeBerTlvHex(const string &hex, bool recurse_constructed = true);

//! Find first primitive value for tag (hex, case-insensitive). Returns empty if missing.
string FindTagValueHex(const EmvParseResult &parsed, const string &tag_hex);

//! Apply privacy defaults: mask PAN, redact track/PIN unless unsafe.
void ApplyPrivacy(vector<EmvTlvEntry> &entries, bool unsafe);

} // namespace cardtrace
} // namespace duckdb
