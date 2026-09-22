#include "emv_tlv.hpp"
#include "emv_decoders.hpp"
#include "pan_utils.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"

#include <cctype>
#include <unordered_map>

namespace duckdb {
namespace cardtrace {

namespace {

struct TagInfo {
	const char *name;
	EmvSensitivity sensitivity;
};

// Common EMV / ISO 7816 tags used in terminal DE55 / chip data.
// Names follow EMVCo Book 3 terminology where applicable.
const std::unordered_map<string, TagInfo> TAG_DICT = {
    {"42", {"Issuer Identification Number (IIN)", EmvSensitivity::NONE}},
    {"4F", {"Application Dedicated File (ADF) Name", EmvSensitivity::NONE}},
    {"50", {"Application Label", EmvSensitivity::NONE}},
    {"57", {"Track 2 Equivalent Data", EmvSensitivity::TRACK}},
    {"5A", {"Application PAN", EmvSensitivity::PAN}},
    {"5F20", {"Cardholder Name", EmvSensitivity::NONE}},
    {"5F24", {"Application Expiration Date", EmvSensitivity::NONE}},
    {"5F25", {"Application Effective Date", EmvSensitivity::NONE}},
    {"5F28", {"Issuer Country Code", EmvSensitivity::NONE}},
    {"5F2A", {"Transaction Currency Code", EmvSensitivity::NONE}},
    {"5F2D", {"Language Preference", EmvSensitivity::NONE}},
    {"5F30", {"Service Code", EmvSensitivity::NONE}},
    {"5F34", {"Application PAN Sequence Number", EmvSensitivity::NONE}},
    {"5F36", {"Transaction Currency Exponent", EmvSensitivity::NONE}},
    {"5F50", {"Issuer URL", EmvSensitivity::NONE}},
    {"5F57", {"Account Type", EmvSensitivity::NONE}},
    {"61", {"Application Template", EmvSensitivity::NONE}},
    {"6F", {"File Control Information (FCI) Template", EmvSensitivity::NONE}},
    {"70", {"EMV Proprietary Template", EmvSensitivity::NONE}},
    {"71", {"Issuer Script Template 1", EmvSensitivity::NONE}},
    {"72", {"Issuer Script Template 2", EmvSensitivity::NONE}},
    {"73", {"Directory Discretionary Template", EmvSensitivity::NONE}},
    {"77", {"Response Message Template Format 2", EmvSensitivity::NONE}},
    {"80", {"Response Message Template Format 1", EmvSensitivity::NONE}},
    {"81", {"Amount, Authorised (Binary)", EmvSensitivity::NONE}},
    {"82", {"Application Interchange Profile", EmvSensitivity::NONE}},
    {"83", {"Command Template", EmvSensitivity::NONE}},
    {"84", {"Dedicated File (DF) Name", EmvSensitivity::NONE}},
    {"86", {"Issuer Script Command", EmvSensitivity::NONE}},
    {"87", {"Application Priority Indicator", EmvSensitivity::NONE}},
    {"88", {"Short File Identifier (SFI)", EmvSensitivity::NONE}},
    {"89", {"Authorisation Code", EmvSensitivity::NONE}},
    {"8A", {"Authorisation Response Code", EmvSensitivity::NONE}},
    {"8C", {"Card Risk Management Data Object List 1 (CDOL1)", EmvSensitivity::NONE}},
    {"8D", {"Card Risk Management Data Object List 2 (CDOL2)", EmvSensitivity::NONE}},
    {"8E", {"Cardholder Verification Method (CVM) List", EmvSensitivity::NONE}},
    {"8F", {"Certification Authority Public Key Index", EmvSensitivity::NONE}},
    {"90", {"Issuer Public Key Certificate", EmvSensitivity::NONE}},
    {"91", {"Issuer Authentication Data", EmvSensitivity::NONE}},
    {"92", {"Issuer Public Key Remainder", EmvSensitivity::NONE}},
    {"93", {"Signed Static Application Data", EmvSensitivity::NONE}},
    {"94", {"Application File Locator (AFL)", EmvSensitivity::NONE}},
    {"95", {"Terminal Verification Results", EmvSensitivity::NONE}},
    {"97", {"Transaction Certificate Data Object List (TDOL)", EmvSensitivity::NONE}},
    {"98", {"Transaction Certificate (TC) Hash Value", EmvSensitivity::NONE}},
    {"99", {"Transaction Personal Identification Number (PIN) Data", EmvSensitivity::PIN}},
    {"9A", {"Transaction Date", EmvSensitivity::NONE}},
    {"9B", {"Transaction Status Information", EmvSensitivity::NONE}},
    {"9C", {"Transaction Type", EmvSensitivity::NONE}},
    {"9D", {"Directory Definition File (DDF) Name", EmvSensitivity::NONE}},
    {"9F01", {"Acquirer Identifier", EmvSensitivity::NONE}},
    {"9F02", {"Amount, Authorised (Numeric)", EmvSensitivity::NONE}},
    {"9F03", {"Amount, Other (Numeric)", EmvSensitivity::NONE}},
    {"9F06", {"Application Identifier (AID) – Terminal", EmvSensitivity::NONE}},
    {"9F07", {"Application Usage Control", EmvSensitivity::NONE}},
    {"9F08", {"Application Version Number (Card)", EmvSensitivity::NONE}},
    {"9F09", {"Application Version Number (Terminal)", EmvSensitivity::NONE}},
    {"9F0D", {"Issuer Action Code – Default", EmvSensitivity::NONE}},
    {"9F0E", {"Issuer Action Code – Denial", EmvSensitivity::NONE}},
    {"9F0F", {"Issuer Action Code – Online", EmvSensitivity::NONE}},
    {"9F10", {"Issuer Application Data", EmvSensitivity::NONE}},
    {"9F11", {"Issuer Code Table Index", EmvSensitivity::NONE}},
    {"9F12", {"Application Preferred Name", EmvSensitivity::NONE}},
    {"9F15", {"Merchant Category Code", EmvSensitivity::NONE}},
    {"9F16", {"Merchant Identifier", EmvSensitivity::NONE}},
    {"9F1A", {"Terminal Country Code", EmvSensitivity::NONE}},
    {"9F1B", {"Terminal Floor Limit", EmvSensitivity::NONE}},
    {"9F1C", {"Terminal Identification", EmvSensitivity::NONE}},
    {"9F1E", {"Interface Device (IFD) Serial Number", EmvSensitivity::NONE}},
    {"9F21", {"Transaction Time", EmvSensitivity::NONE}},
    {"9F26", {"Application Cryptogram", EmvSensitivity::NONE}},
    {"9F27", {"Cryptogram Information Data", EmvSensitivity::NONE}},
    {"9F33", {"Terminal Capabilities", EmvSensitivity::NONE}},
    {"9F34", {"Cardholder Verification Method (CVM) Results", EmvSensitivity::NONE}},
    {"9F35", {"Terminal Type", EmvSensitivity::NONE}},
    {"9F36", {"Application Transaction Counter (ATC)", EmvSensitivity::NONE}},
    {"9F37", {"Unpredictable Number", EmvSensitivity::NONE}},
    {"9F39", {"Point-of-Service (POS) Entry Mode", EmvSensitivity::NONE}},
    {"9F40", {"Additional Terminal Capabilities", EmvSensitivity::NONE}},
    {"9F41", {"Transaction Sequence Counter", EmvSensitivity::NONE}},
    {"9F42", {"Application Currency Code", EmvSensitivity::NONE}},
    {"9F46", {"ICC Public Key Certificate", EmvSensitivity::NONE}},
    {"9F47", {"ICC Public Key Exponent", EmvSensitivity::NONE}},
    {"9F48", {"ICC Public Key Remainder", EmvSensitivity::NONE}},
    {"9F4A", {"Static Data Authentication Tag List", EmvSensitivity::NONE}},
    {"9F4E", {"Merchant Name and Location", EmvSensitivity::NONE}},
    {"9F53", {"Transaction Category Code", EmvSensitivity::NONE}},
    {"9F5B", {"Issuer Script Results", EmvSensitivity::NONE}},
    {"9F66", {"Terminal Transaction Qualifiers (TTQ)", EmvSensitivity::NONE}},
    {"9F6C", {"Card Transaction Qualifiers (CTQ)", EmvSensitivity::NONE}},
    {"9F6E", {"Form Factor Indicator", EmvSensitivity::NONE}},
    {"9F7C", {"Customer Exclusive Data", EmvSensitivity::NONE}},
    {"A5", {"File Control Information (FCI) Proprietary Template", EmvSensitivity::NONE}},
    {"BF0C", {"File Control Information (FCI) Issuer Discretionary Data", EmvSensitivity::NONE}},
};

char HexNibble(char c) {
	if (c >= '0' && c <= '9') {
		return static_cast<char>(c - '0');
	}
	if (c >= 'a' && c <= 'f') {
		return static_cast<char>(c - 'a' + 10);
	}
	if (c >= 'A' && c <= 'F') {
		return static_cast<char>(c - 'A' + 10);
	}
	throw InvalidInputException("Invalid hex character '%c' in EMV TLV payload", c);
}

void DecodeRecursive(const uint8_t *data, idx_t size, idx_t depth, vector<EmvTlvEntry> &out, string &error) {
	idx_t offset = 0;
	while (offset < size) {
		if (error.size()) {
			return;
		}
		idx_t tag_start = offset;
		uint8_t first = data[offset++];
		bool constructed = (first & 0x20) != 0;

		// Multi-byte tag when lower 5 bits are all set.
		if ((first & 0x1F) == 0x1F) {
			if (offset >= size) {
				error = "Truncated multi-byte tag";
				return;
			}
			while (offset < size) {
				uint8_t b = data[offset++];
				if ((b & 0x80) == 0) {
					break;
				}
				if (offset >= size) {
					error = "Truncated multi-byte tag";
					return;
				}
				// Guard absurd tag lengths
				if (offset - tag_start > 4) {
					error = "Tag exceeds maximum supported length (4 bytes)";
					return;
				}
			}
		}

		idx_t tag_len = offset - tag_start;
		if (tag_len == 0 || tag_len > 4) {
			error = "Invalid tag length";
			return;
		}

		if (offset >= size) {
			error = "Missing TLV length byte";
			return;
		}

		uint8_t len_first = data[offset++];
		idx_t value_len = 0;
		if ((len_first & 0x80) == 0) {
			value_len = len_first;
		} else {
			idx_t num_len_bytes = len_first & 0x7F;
			if (num_len_bytes == 0 || num_len_bytes > 3) {
				error = "Unsupported BER length form";
				return;
			}
			if (offset + num_len_bytes > size) {
				error = "Truncated BER length";
				return;
			}
			for (idx_t i = 0; i < num_len_bytes; i++) {
				value_len = (value_len << 8) | data[offset++];
			}
		}

		if (offset + value_len > size) {
			error = StringUtil::Format("Truncated TLV value for tag at offset %llu (need %llu bytes, have %llu)",
			                           static_cast<uint64_t>(tag_start), static_cast<uint64_t>(value_len),
			                           static_cast<uint64_t>(size - offset));
			return;
		}

		EmvTlvEntry entry;
		entry.tag_hex = ToHex(data + tag_start, tag_len);
		entry.name = LookupTagName(entry.tag_hex);
		entry.length = value_len;
		entry.value_hex = ToHex(data + offset, value_len);
		entry.sensitivity = LookupTagSensitivity(entry.tag_hex);
		entry.constructed = constructed;
		entry.depth = depth;

		if (!constructed) {
			entry.decoded = DecodeTagValue(entry.tag_hex, data + offset, value_len);
		}

		out.push_back(entry);

		if (constructed && value_len > 0) {
			DecodeRecursive(data + offset, value_len, depth + 1, out, error);
		}

		offset += value_len;
	}
}

} // namespace

vector<uint8_t> ParseHex(const string &hex) {
	string cleaned;
	cleaned.reserve(hex.size());
	for (char c : hex) {
		if (std::isspace(static_cast<unsigned char>(c)) || c == ':' || c == '-') {
			continue;
		}
		cleaned.push_back(c);
	}
	if (cleaned.size() >= 2 && cleaned[0] == '0' && (cleaned[1] == 'x' || cleaned[1] == 'X')) {
		cleaned = cleaned.substr(2);
	}
	if (cleaned.empty()) {
		return {};
	}
	if (cleaned.size() % 2 != 0) {
		throw InvalidInputException("EMV TLV hex payload must have an even number of hex digits");
	}
	vector<uint8_t> out;
	out.reserve(cleaned.size() / 2);
	for (idx_t i = 0; i < cleaned.size(); i += 2) {
		auto hi = HexNibble(cleaned[i]);
		auto lo = HexNibble(cleaned[i + 1]);
		out.push_back(static_cast<uint8_t>((hi << 4) | lo));
	}
	return out;
}

string ToHex(const uint8_t *data, idx_t len) {
	static const char *HEX = "0123456789ABCDEF";
	string out;
	out.resize(len * 2);
	for (idx_t i = 0; i < len; i++) {
		out[i * 2] = HEX[(data[i] >> 4) & 0x0F];
		out[i * 2 + 1] = HEX[data[i] & 0x0F];
	}
	return out;
}

string LookupTagName(const string &tag_hex) {
	auto key = StringUtil::Upper(tag_hex);
	auto it = TAG_DICT.find(key);
	if (it == TAG_DICT.end()) {
		return "";
	}
	return it->second.name;
}

EmvSensitivity LookupTagSensitivity(const string &tag_hex) {
	auto key = StringUtil::Upper(tag_hex);
	auto it = TAG_DICT.find(key);
	if (it == TAG_DICT.end()) {
		return EmvSensitivity::NONE;
	}
	return it->second.sensitivity;
}

EmvParseResult DecodeBerTlv(const uint8_t *data, idx_t size, bool recurse_constructed) {
	EmvParseResult result;
	if (!data || size == 0) {
		return result;
	}
	if (recurse_constructed) {
		DecodeRecursive(data, size, 0, result.entries, result.error);
	} else {
		// Non-recursive: still parse top-level only by temporarily treating constructed as primitive.
		// Implemented by DecodeRecursive which always recurses; for false, strip nested after.
		DecodeRecursive(data, size, 0, result.entries, result.error);
		if (!recurse_constructed) {
			vector<EmvTlvEntry> top;
			for (auto &e : result.entries) {
				if (e.depth == 0) {
					top.push_back(std::move(e));
				}
			}
			result.entries = std::move(top);
		}
	}
	return result;
}

EmvParseResult DecodeBerTlvHex(const string &hex, bool recurse_constructed) {
	auto bytes = ParseHex(hex);
	return DecodeBerTlv(bytes.data(), bytes.size(), recurse_constructed);
}

string FindTagValueHex(const EmvParseResult &parsed, const string &tag_hex) {
	auto want = StringUtil::Upper(tag_hex);
	// Strip optional leading zeros style; tags are already uppercase hex.
	for (auto &e : parsed.entries) {
		if (e.tag_hex == want && !e.constructed) {
			return e.value_hex;
		}
	}
	// Fall back to constructed match if no primitive
	for (auto &e : parsed.entries) {
		if (e.tag_hex == want) {
			return e.value_hex;
		}
	}
	return "";
}

void ApplyPrivacy(vector<EmvTlvEntry> &entries, bool unsafe) {
	for (auto &e : entries) {
		switch (e.sensitivity) {
		case EmvSensitivity::PAN: {
			// Prefer decoded digits from hex BCD-ish / nibble hex
			string digits;
			for (char c : e.value_hex) {
				if (std::isdigit(static_cast<unsigned char>(c))) {
					digits.push_back(c);
				} else if (c == 'A' || c == 'a') {
					// padding nibble sometimes used
					break;
				} else if (c == 'F' || c == 'f') {
					break;
				}
			}
			auto masked = PanMask(digits.empty() ? e.value_hex : digits);
			if (!unsafe) {
				e.value_hex = masked;
			}
			e.decoded = masked;
			break;
		}
		case EmvSensitivity::TRACK:
			if (!unsafe) {
				e.value_hex = "[REDACTED]";
				e.decoded = "track_data_redacted";
			} else {
				e.decoded = "track_data_present";
			}
			break;
		case EmvSensitivity::PIN:
			if (!unsafe) {
				e.value_hex = StringUtil::Format("[PIN_BLOCK len=%llu]", static_cast<uint64_t>(e.length));
				e.decoded = "pin_block_present";
			} else {
				e.decoded = "pin_block_present";
			}
			break;
		case EmvSensitivity::NONE:
		default:
			break;
		}
	}
}

} // namespace cardtrace
} // namespace duckdb
