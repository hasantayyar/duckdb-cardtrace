#include "pan_utils.hpp"

#include "duckdb/common/string_util.hpp"

#include <cctype>

namespace duckdb {
namespace cardtrace {

namespace {

string DigitsOnly(const string &value) {
	string digits;
	digits.reserve(value.size());
	for (char c : value) {
		if (std::isdigit(static_cast<unsigned char>(c))) {
			digits.push_back(c);
		}
	}
	return digits;
}

} // namespace

bool PanLuhnValid(const string &pan) {
	auto digits = DigitsOnly(pan);
	if (digits.size() < 12 || digits.size() > 19) {
		return false;
	}
	int sum = 0;
	bool double_digit = false;
	for (idx_t i = digits.size(); i-- > 0;) {
		int d = digits[i] - '0';
		if (double_digit) {
			d *= 2;
			if (d > 9) {
				d -= 9;
			}
		}
		sum += d;
		double_digit = !double_digit;
	}
	return (sum % 10) == 0;
}

string PanMask(const string &pan) {
	auto digits = DigitsOnly(pan);
	if (digits.empty()) {
		return "****";
	}
	if (digits.size() <= 10) {
		return string(digits.size(), '*');
	}
	// PCI DSS: retain BIN (first 6) and last 4 by default.
	string out = digits.substr(0, 6);
	out.append(digits.size() - 10, '*');
	out.append(digits.substr(digits.size() - 4));
	return out;
}

string RedactTrackData(const string &track_hex_or_digits) {
	auto digits = DigitsOnly(track_hex_or_digits);
	if (digits.empty()) {
		return "[REDACTED]";
	}
	return StringUtil::Format("[REDACTED track digits=%llu]", static_cast<uint64_t>(digits.size()));
}

} // namespace cardtrace
} // namespace duckdb
