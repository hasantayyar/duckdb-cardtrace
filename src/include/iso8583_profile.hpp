#pragma once

#include "duckdb.hpp"

#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

namespace duckdb {
namespace cardtrace {

enum class IsoLengthType : uint8_t { FIXED = 0, LLVAR = 1, LLLVAR = 2 };

enum class IsoFieldContent : uint8_t {
	ASCII = 0,     //! Field payload is ASCII characters of the given length
	HEX_BYTES = 1, //! Field payload is 2*N hex chars representing N bytes
};

enum class IsoSensitive : uint8_t { NONE = 0, PAN = 1, TRACK = 2, PIN = 3 };

enum class IsoWireEncoding : uint8_t {
	ASCII = 0, //! Entire message is ASCII (MTI digits, hex bitmap, ASCII/hex fields)
};

struct IsoFieldDef {
	int de = 0;
	string name;
	IsoLengthType length_type = IsoLengthType::FIXED;
	idx_t length = 0;     //! FIXED length (characters or hex-chars depending on content)
	idx_t max_length = 0; //! LLVAR / LLLVAR max
	IsoFieldContent content = IsoFieldContent::ASCII;
	IsoSensitive sensitive = IsoSensitive::NONE;
	bool emv_tlv = false;
};

struct Iso8583Profile {
	string name;
	int version = 1;
	IsoWireEncoding encoding = IsoWireEncoding::ASCII;
	idx_t mti_length = 4;
	idx_t primary_bitmap_hex_len = 16; //! 16 hex chars = 8 bytes = 64 bits
	bool secondary_bitmap = true;
	unordered_map<int, IsoFieldDef> fields;

	const IsoFieldDef *FindField(int de) const;
};

//! Parse a profile JSON document (object). Throws InvalidInputException on schema errors.
Iso8583Profile ParseIso8583ProfileJson(const string &json);

//! Load profile from a filesystem path using DuckDB's FileSystem.
Iso8583Profile LoadIso8583Profile(ClientContext &context, const string &path_or_json);

} // namespace cardtrace
} // namespace duckdb
