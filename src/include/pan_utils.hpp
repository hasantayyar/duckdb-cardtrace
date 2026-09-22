#pragma once

#include "duckdb.hpp"

#include <string>

namespace duckdb {
namespace cardtrace {

//! Return true if digits pass the Luhn check. Non-digit characters are ignored.
//! Returns false for empty input or fewer than 12 digits.
bool PanLuhnValid(const string &pan);

//! Mask a PAN for display: keep first 6 and last 4 digits, replace middle with '*'.
//! Non-digit characters are stripped first. Short values are fully masked.
string PanMask(const string &pan);

//! Mask Track2-equivalent data: keep only service-code presence metadata-ish redaction.
//! Returns a redacted token that never contains the full track payload.
string RedactTrackData(const string &track_hex_or_digits);

} // namespace cardtrace
} // namespace duckdb
