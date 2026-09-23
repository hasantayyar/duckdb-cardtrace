#pragma once

#include "iso8583_profile.hpp"

#include <string>
#include <vector>

namespace duckdb {
namespace cardtrace {

struct Iso8583FieldValue {
	int de = 0;
	string name;
	string value;     //! Display value (may be redacted)
	string value_hex; //! Hex encoding of raw field bytes/chars
	string decoded;   //! Optional semantic decode (e.g. DE55 EMV summary)
	idx_t offset = 0; //! Character offset into the (normalized) message
	string error;     //! Non-empty if this field failed
};

struct Iso8583Message {
	string mti;
	string bitmap_hex;
	vector<Iso8583FieldValue> fields;
	string error; //! Message-level error (empty on success / partial success)
};

//! Parse one ISO 8583 message according to profile.
//! `redact` applies PAN/track/PIN privacy (default on).
Iso8583Message ParseIso8583Message(const string &payload, const Iso8583Profile &profile, bool redact = true);

} // namespace cardtrace
} // namespace duckdb
