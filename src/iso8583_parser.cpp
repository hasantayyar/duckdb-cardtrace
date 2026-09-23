#include "iso8583_parser.hpp"

#include "emv_tlv.hpp"
#include "pan_utils.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"

#include <cctype>

namespace duckdb {
namespace cardtrace {

namespace {

string NormalizePayload(const string &payload) {
	string out;
	out.reserve(payload.size());
	for (char c : payload) {
		unsigned char uc = static_cast<unsigned char>(c);
		if (std::isspace(uc) || c == ':' || c == '-' || c == '_') {
			continue;
		}
		out.push_back(c);
	}
	return out;
}

bool IsHexChar(char c) {
	return std::isxdigit(static_cast<unsigned char>(c)) != 0;
}

string HexEncodeAscii(const string &value) {
	return ToHex(reinterpret_cast<const uint8_t *>(value.data()), value.size());
}

idx_t ParseDecimalLength(const string &msg, idx_t &pos, idx_t digits, string &error) {
	if (pos + digits > msg.size()) {
		error = StringUtil::Format("truncated length prefix (%llu digits needed)", static_cast<uint64_t>(digits));
		return 0;
	}
	idx_t value = 0;
	for (idx_t i = 0; i < digits; i++) {
		char c = msg[pos + i];
		if (!std::isdigit(static_cast<unsigned char>(c))) {
			error = StringUtil::Format("non-digit in length prefix at offset %llu", static_cast<uint64_t>(pos + i));
			return 0;
		}
		value = value * 10 + static_cast<idx_t>(c - '0');
	}
	pos += digits;
	return value;
}

bool ParseBitmapHex(const string &hex, vector<bool> &bits_out, string &error) {
	if (hex.size() != 16 && hex.size() != 32) {
		error = StringUtil::Format("bitmap must be 16 or 32 hex chars, got %llu", static_cast<uint64_t>(hex.size()));
		return false;
	}
	for (char c : hex) {
		if (!IsHexChar(c)) {
			error = "bitmap contains non-hex characters";
			return false;
		}
	}
	idx_t bit_count = (hex.size() / 2) * 8;
	bits_out.assign(bit_count + 1, false); // 1-indexed
	for (idx_t byte_idx = 0; byte_idx < hex.size() / 2; byte_idx++) {
		auto hi = hex[byte_idx * 2];
		auto lo = hex[byte_idx * 2 + 1];
		auto nibble = [](char c) -> uint8_t {
			if (c >= '0' && c <= '9') {
				return static_cast<uint8_t>(c - '0');
			}
			return static_cast<uint8_t>(10 + std::tolower(static_cast<unsigned char>(c)) - 'a');
		};
		uint8_t byte = static_cast<uint8_t>((nibble(hi) << 4) | nibble(lo));
		for (idx_t bit = 0; bit < 8; bit++) {
			if (byte & (0x80 >> bit)) {
				bits_out[byte_idx * 8 + bit + 1] = true;
			}
		}
	}
	return true;
}

string SummarizeEmv(const string &field_hex, bool redact) {
	auto parsed = DecodeBerTlvHex(field_hex, true);
	if (!parsed.error.empty()) {
		return StringUtil::Format("emv_tlv_error:%s", parsed.error);
	}
	// ApplyPrivacy(..., unsafe) — unsafe=true keeps sensitive values
	ApplyPrivacy(parsed.entries, !redact);

	string summary;
	for (auto &entry : parsed.entries) {
		if (entry.constructed) {
			continue;
		}
		if (!summary.empty()) {
			summary.push_back(';');
		}
		summary.append(entry.tag_hex);
		summary.push_back('=');
		summary.append(entry.value_hex);
		if (!entry.decoded.empty()) {
			summary.push_back('(');
			summary.append(entry.decoded);
			summary.push_back(')');
		}
	}
	return summary;
}

string ApplyFieldPrivacy(const IsoFieldDef &def, const string &raw, bool redact) {
	if (!redact || def.sensitive == IsoSensitive::NONE) {
		return raw;
	}
	switch (def.sensitive) {
	case IsoSensitive::PAN:
		return PanMask(raw);
	case IsoSensitive::TRACK:
		return RedactTrackData(raw);
	case IsoSensitive::PIN:
		return StringUtil::Format("[REDACTED pin bytes=%llu]", static_cast<uint64_t>(raw.size() / 2));
	default:
		return raw;
	}
}

} // namespace

Iso8583Message ParseIso8583Message(const string &payload, const Iso8583Profile &profile, bool redact) {
	Iso8583Message result;
	if (profile.encoding != IsoWireEncoding::ASCII) {
		result.error = "only ASCII wire encoding is supported";
		return result;
	}

	auto msg = NormalizePayload(payload);
	if (msg.empty()) {
		result.error = "empty message";
		return result;
	}

	idx_t pos = 0;
	if (pos + profile.mti_length > msg.size()) {
		result.error = "message shorter than MTI";
		return result;
	}
	result.mti = msg.substr(pos, profile.mti_length);
	for (char c : result.mti) {
		if (!std::isdigit(static_cast<unsigned char>(c))) {
			result.error = "MTI must be numeric";
			return result;
		}
	}
	pos += profile.mti_length;

	if (pos + profile.primary_bitmap_hex_len > msg.size()) {
		result.error = "message truncated in primary bitmap";
		return result;
	}
	string bitmap = StringUtil::Upper(msg.substr(pos, profile.primary_bitmap_hex_len));
	pos += profile.primary_bitmap_hex_len;

	vector<bool> bits;
	string bmp_error;
	if (!ParseBitmapHex(bitmap, bits, bmp_error)) {
		result.error = bmp_error;
		return result;
	}

	if (profile.secondary_bitmap && bits.size() > 1 && bits[1]) {
		if (pos + 16 > msg.size()) {
			result.error = "message truncated in secondary bitmap";
			return result;
		}
		string secondary = StringUtil::Upper(msg.substr(pos, 16));
		pos += 16;
		bitmap.append(secondary);
		vector<bool> more;
		if (!ParseBitmapHex(bitmap, more, bmp_error)) {
			result.error = bmp_error;
			return result;
		}
		bits = std::move(more);
	} else if (bits.size() > 1 && bits[1] && !profile.secondary_bitmap) {
		result.error = "bitmap bit 1 set but profile disables secondary bitmap";
		return result;
	}

	result.bitmap_hex = bitmap;

	idx_t max_de = bits.size() > 1 ? bits.size() - 1 : 0;
	for (idx_t de = 2; de <= max_de; de++) {
		if (!bits[de]) {
			continue;
		}
		Iso8583FieldValue field_value;
		field_value.de = NumericCast<int>(de);
		field_value.offset = pos;

		auto *def = profile.FindField(NumericCast<int>(de));
		if (!def) {
			field_value.error =
			    StringUtil::Format("DE%llu present in bitmap but missing from profile", static_cast<uint64_t>(de));
			result.fields.push_back(std::move(field_value));
			result.error = field_value.error;
			break;
		}
		field_value.name = def->name;

		idx_t data_len = 0;
		string len_error;
		switch (def->length_type) {
		case IsoLengthType::FIXED:
			data_len = def->length;
			break;
		case IsoLengthType::LLVAR:
			data_len = ParseDecimalLength(msg, pos, 2, len_error);
			break;
		case IsoLengthType::LLLVAR:
			data_len = ParseDecimalLength(msg, pos, 3, len_error);
			break;
		}
		if (!len_error.empty()) {
			field_value.error = len_error;
			result.fields.push_back(std::move(field_value));
			result.error = len_error;
			break;
		}
		if (def->length_type != IsoLengthType::FIXED && data_len > def->max_length) {
			field_value.error =
			    StringUtil::Format("DE%d length %llu exceeds max_length %llu", def->de, static_cast<uint64_t>(data_len),
			                       static_cast<uint64_t>(def->max_length));
			result.fields.push_back(std::move(field_value));
			result.error = field_value.error;
			break;
		}

		// HEX_BYTES content: length is in bytes, on-wire uses 2 hex chars per byte
		idx_t on_wire_len = data_len;
		if (def->content == IsoFieldContent::HEX_BYTES) {
			on_wire_len = data_len * 2;
		}

		if (pos + on_wire_len > msg.size()) {
			field_value.error =
			    StringUtil::Format("DE%d truncated (need %llu chars)", def->de, static_cast<uint64_t>(on_wire_len));
			result.fields.push_back(std::move(field_value));
			result.error = field_value.error;
			break;
		}

		string raw = msg.substr(pos, on_wire_len);
		pos += on_wire_len;

		if (def->content == IsoFieldContent::HEX_BYTES) {
			for (char c : raw) {
				if (!IsHexChar(c)) {
					field_value.error = StringUtil::Format("DE%d expected hex content", def->de);
					break;
				}
			}
			if (!field_value.error.empty()) {
				result.fields.push_back(std::move(field_value));
				result.error = field_value.error;
				break;
			}
			raw = StringUtil::Upper(raw);
			field_value.value_hex = raw;
			field_value.value = ApplyFieldPrivacy(*def, raw, redact);
		} else {
			field_value.value_hex = HexEncodeAscii(raw);
			field_value.value = ApplyFieldPrivacy(*def, raw, redact);
			if (redact && def->sensitive == IsoSensitive::PAN) {
				field_value.value_hex = HexEncodeAscii(field_value.value);
			} else if (redact && def->sensitive == IsoSensitive::TRACK) {
				field_value.value_hex = "[REDACTED]";
			} else if (redact && def->sensitive == IsoSensitive::PIN) {
				field_value.value_hex = "[REDACTED]";
			}
		}

		if (def->emv_tlv) {
			string emv_hex = def->content == IsoFieldContent::HEX_BYTES ? raw : field_value.value_hex;
			if (def->content == IsoFieldContent::ASCII) {
				// ASCII DE55 is unusual; treat ASCII as hex characters if they look like hex
				bool all_hex = true;
				for (char c : raw) {
					if (!IsHexChar(c)) {
						all_hex = false;
						break;
					}
				}
				emv_hex = all_hex ? raw : field_value.value_hex;
			}
			field_value.decoded = SummarizeEmv(emv_hex, redact);
		}

		result.fields.push_back(std::move(field_value));
	}

	if (result.error.empty() && pos < msg.size()) {
		// Trailing data is reported but not fatal — useful for concatenated dumps
		Iso8583FieldValue trailing;
		trailing.de = 0;
		trailing.name = "trailing_data";
		trailing.offset = pos;
		trailing.value = msg.substr(pos);
		trailing.value_hex = HexEncodeAscii(trailing.value);
		trailing.error = StringUtil::Format("%llu trailing characters", static_cast<uint64_t>(msg.size() - pos));
		result.fields.push_back(std::move(trailing));
	}

	return result;
}

} // namespace cardtrace
} // namespace duckdb
