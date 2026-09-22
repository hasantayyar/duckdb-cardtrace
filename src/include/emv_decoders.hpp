#pragma once

#include "duckdb.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace duckdb {
namespace cardtrace {

//! Decode Cryptogram Information Data (tag 9F27, 1 byte) to a short label (e.g. ARQC).
string DecodeCid(const uint8_t *data, idx_t len);

//! Decode Terminal Verification Results (tag 95, 5 bytes) as semicolon-separated flags.
string DecodeTvr(const uint8_t *data, idx_t len);

//! Decode Transaction Status Information (tag 9B, 2 bytes).
string DecodeTsi(const uint8_t *data, idx_t len);

//! Decode CVM Results (tag 9F34, 3 bytes).
string DecodeCvmResults(const uint8_t *data, idx_t len);

//! Convenience: decode from hex value string. Returns empty on invalid/empty input.
string DecodeCidHex(const string &hex);
string DecodeTvrHex(const string &hex);
string DecodeTsiHex(const string &hex);
string DecodeCvmHex(const string &hex);

//! Best-effort decoded string for a known tag value; empty if none.
string DecodeTagValue(const string &tag_hex, const uint8_t *data, idx_t len);

} // namespace cardtrace
} // namespace duckdb
