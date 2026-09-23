#include "iso8583_profile.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/main/client_context.hpp"

#include <cctype>

namespace duckdb {
namespace cardtrace {

namespace {

struct JsonParser {
	const char *data;
	idx_t size;
	idx_t pos = 0;

	explicit JsonParser(const string &input) : data(input.c_str()), size(input.size()) {
	}

	void SkipWs() {
		while (pos < size && std::isspace(static_cast<unsigned char>(data[pos]))) {
			pos++;
		}
	}

	char Peek() {
		SkipWs();
		return pos < size ? data[pos] : '\0';
	}

	char Get() {
		SkipWs();
		if (pos >= size) {
			throw InvalidInputException("iso8583 profile: unexpected end of JSON");
		}
		return data[pos++];
	}

	void Expect(char c) {
		char got = Get();
		if (got != c) {
			throw InvalidInputException("iso8583 profile: expected '%c' at position %llu, got '%c'", c,
			                            static_cast<uint64_t>(pos - 1), got);
		}
	}

	string ParseString() {
		Expect('"');
		string out;
		while (pos < size) {
			char c = data[pos++];
			if (c == '"') {
				return out;
			}
			if (c == '\\') {
				if (pos >= size) {
					throw InvalidInputException("iso8583 profile: truncated escape in string");
				}
				char e = data[pos++];
				switch (e) {
				case '"':
				case '\\':
				case '/':
					out.push_back(e);
					break;
				case 'b':
					out.push_back('\b');
					break;
				case 'f':
					out.push_back('\f');
					break;
				case 'n':
					out.push_back('\n');
					break;
				case 'r':
					out.push_back('\r');
					break;
				case 't':
					out.push_back('\t');
					break;
				default:
					throw InvalidInputException("iso8583 profile: unsupported escape '\\%c'", e);
				}
			} else {
				out.push_back(c);
			}
		}
		throw InvalidInputException("iso8583 profile: unterminated string");
	}

	int64_t ParseInt() {
		SkipWs();
		idx_t start = pos;
		if (pos < size && (data[pos] == '-' || data[pos] == '+')) {
			pos++;
		}
		if (pos >= size || !std::isdigit(static_cast<unsigned char>(data[pos]))) {
			throw InvalidInputException("iso8583 profile: expected integer at position %llu",
			                            static_cast<uint64_t>(pos));
		}
		while (pos < size && std::isdigit(static_cast<unsigned char>(data[pos]))) {
			pos++;
		}
		return std::stoll(string(data + start, data + pos));
	}

	bool ParseBool() {
		SkipWs();
		if (pos + 4 <= size && StringUtil::Lower(string(data + pos, 4)) == "true") {
			pos += 4;
			return true;
		}
		if (pos + 5 <= size && StringUtil::Lower(string(data + pos, 5)) == "false") {
			pos += 5;
			return false;
		}
		throw InvalidInputException("iso8583 profile: expected boolean at position %llu", static_cast<uint64_t>(pos));
	}

	void SkipValue() {
		SkipWs();
		char c = Peek();
		if (c == '"') {
			ParseString();
		} else if (c == '{') {
			Expect('{');
			SkipWs();
			if (Peek() == '}') {
				Get();
				return;
			}
			while (true) {
				ParseString();
				Expect(':');
				SkipValue();
				SkipWs();
				if (Peek() == ',') {
					Get();
					continue;
				}
				Expect('}');
				break;
			}
		} else if (c == '[') {
			Expect('[');
			SkipWs();
			if (Peek() == ']') {
				Get();
				return;
			}
			while (true) {
				SkipValue();
				SkipWs();
				if (Peek() == ',') {
					Get();
					continue;
				}
				Expect(']');
				break;
			}
		} else if (c == 't' || c == 'T' || c == 'f' || c == 'F') {
			ParseBool();
		} else if (c == 'n' || c == 'N') {
			if (pos + 4 <= size && StringUtil::Lower(string(data + pos, 4)) == "null") {
				pos += 4;
			} else {
				throw InvalidInputException("iso8583 profile: expected null");
			}
		} else {
			ParseInt();
		}
	}
};

IsoLengthType ParseLengthType(const string &value) {
	auto v = StringUtil::Lower(value);
	if (v == "fixed") {
		return IsoLengthType::FIXED;
	}
	if (v == "llvar") {
		return IsoLengthType::LLVAR;
	}
	if (v == "lllvar") {
		return IsoLengthType::LLLVAR;
	}
	throw InvalidInputException("iso8583 profile: unknown length_type '%s'", value);
}

IsoFieldContent ParseContent(const string &value) {
	auto v = StringUtil::Lower(value);
	if (v == "ascii") {
		return IsoFieldContent::ASCII;
	}
	if (v == "hex" || v == "hex_bytes") {
		return IsoFieldContent::HEX_BYTES;
	}
	throw InvalidInputException("iso8583 profile: unknown content '%s'", value);
}

IsoSensitive ParseSensitive(const string &value) {
	auto v = StringUtil::Lower(value);
	if (v.empty() || v == "none") {
		return IsoSensitive::NONE;
	}
	if (v == "pan") {
		return IsoSensitive::PAN;
	}
	if (v == "track") {
		return IsoSensitive::TRACK;
	}
	if (v == "pin") {
		return IsoSensitive::PIN;
	}
	throw InvalidInputException("iso8583 profile: unknown sensitive '%s'", value);
}

IsoFieldDef ParseFieldObject(JsonParser &p, int de) {
	IsoFieldDef field;
	field.de = de;
	p.Expect('{');
	p.SkipWs();
	if (p.Peek() == '}') {
		p.Get();
		throw InvalidInputException("iso8583 profile: field %d is empty", de);
	}
	while (true) {
		auto key = StringUtil::Lower(p.ParseString());
		p.Expect(':');
		if (key == "name") {
			field.name = p.ParseString();
		} else if (key == "length_type" || key == "format") {
			field.length_type = ParseLengthType(p.ParseString());
		} else if (key == "length") {
			auto v = p.ParseInt();
			if (v < 0) {
				throw InvalidInputException("iso8583 profile: field %d length must be >= 0", de);
			}
			field.length = NumericCast<idx_t>(v);
		} else if (key == "max_length") {
			auto v = p.ParseInt();
			if (v < 0) {
				throw InvalidInputException("iso8583 profile: field %d max_length must be >= 0", de);
			}
			field.max_length = NumericCast<idx_t>(v);
		} else if (key == "content" || key == "data_type") {
			// data_type aliases: n/an/ans -> ascii, b/hex -> hex_bytes
			auto raw = p.ParseString();
			auto v = StringUtil::Lower(raw);
			if (v == "n" || v == "an" || v == "ans" || v == "z" || v == "ascii") {
				field.content = IsoFieldContent::ASCII;
			} else if (v == "b" || v == "hex" || v == "hex_bytes") {
				field.content = IsoFieldContent::HEX_BYTES;
			} else {
				field.content = ParseContent(raw);
			}
		} else if (key == "sensitive") {
			field.sensitive = ParseSensitive(p.ParseString());
		} else if (key == "emv_tlv") {
			field.emv_tlv = p.ParseBool();
		} else {
			p.SkipValue();
		}
		p.SkipWs();
		if (p.Peek() == ',') {
			p.Get();
			continue;
		}
		p.Expect('}');
		break;
	}
	if (field.length_type == IsoLengthType::FIXED && field.length == 0) {
		throw InvalidInputException("iso8583 profile: field %d FIXED requires length", de);
	}
	if (field.length_type != IsoLengthType::FIXED && field.max_length == 0) {
		// default max from length if provided
		if (field.length > 0) {
			field.max_length = field.length;
		} else {
			field.max_length = field.length_type == IsoLengthType::LLVAR ? 99 : 999;
		}
	}
	return field;
}

} // namespace

const IsoFieldDef *Iso8583Profile::FindField(int de) const {
	auto it = fields.find(de);
	if (it == fields.end()) {
		return nullptr;
	}
	return &it->second;
}

Iso8583Profile ParseIso8583ProfileJson(const string &json) {
	JsonParser p(json);
	Iso8583Profile profile;
	p.Expect('{');
	p.SkipWs();
	if (p.Peek() == '}') {
		throw InvalidInputException("iso8583 profile: empty object");
	}
	while (true) {
		auto key = StringUtil::Lower(p.ParseString());
		p.Expect(':');
		if (key == "name") {
			profile.name = p.ParseString();
		} else if (key == "version") {
			profile.version = NumericCast<int>(p.ParseInt());
		} else if (key == "encoding" || key == "wire_encoding") {
			auto v = StringUtil::Lower(p.ParseString());
			if (v != "ascii") {
				throw InvalidInputException("iso8583 profile: only encoding 'ascii' is supported (got '%s')", v);
			}
			profile.encoding = IsoWireEncoding::ASCII;
		} else if (key == "header") {
			p.Expect('{');
			p.SkipWs();
			if (p.Peek() != '}') {
				while (true) {
					auto hk = StringUtil::Lower(p.ParseString());
					p.Expect(':');
					if (hk == "mti_length") {
						auto v = p.ParseInt();
						if (v <= 0) {
							throw InvalidInputException("iso8583 profile: mti_length must be > 0");
						}
						profile.mti_length = NumericCast<idx_t>(v);
					} else if (hk == "bitmap_length" || hk == "primary_bitmap_hex_len") {
						auto v = p.ParseInt();
						if (v != 16 && v != 32) {
							throw InvalidInputException(
							    "iso8583 profile: bitmap_length must be 16 (primary) hex chars");
						}
						profile.primary_bitmap_hex_len = 16;
					} else if (hk == "bitmap_encoding") {
						auto v = StringUtil::Lower(p.ParseString());
						if (v != "hex") {
							throw InvalidInputException("iso8583 profile: bitmap_encoding must be 'hex'");
						}
					} else if (hk == "secondary_bitmap") {
						profile.secondary_bitmap = p.ParseBool();
					} else {
						p.SkipValue();
					}
					p.SkipWs();
					if (p.Peek() == ',') {
						p.Get();
						continue;
					}
					p.Expect('}');
					break;
				}
			} else {
				p.Get();
			}
		} else if (key == "fields") {
			p.Expect('{');
			p.SkipWs();
			if (p.Peek() != '}') {
				while (true) {
					auto de_key = p.ParseString();
					int de = 0;
					try {
						de = std::stoi(de_key);
					} catch (...) {
						throw InvalidInputException("iso8583 profile: field key '%s' is not a DE number", de_key);
					}
					if (de < 2 || de > 128) {
						throw InvalidInputException("iso8583 profile: DE %d out of range (2-128)", de);
					}
					p.Expect(':');
					auto field = ParseFieldObject(p, de);
					profile.fields[de] = std::move(field);
					p.SkipWs();
					if (p.Peek() == ',') {
						p.Get();
						continue;
					}
					p.Expect('}');
					break;
				}
			} else {
				p.Get();
			}
		} else {
			p.SkipValue();
		}
		p.SkipWs();
		if (p.Peek() == ',') {
			p.Get();
			continue;
		}
		p.Expect('}');
		break;
	}
	p.SkipWs();
	if (p.pos < p.size) {
		throw InvalidInputException("iso8583 profile: trailing content after JSON object");
	}
	if (profile.fields.empty()) {
		throw InvalidInputException("iso8583 profile: fields map is required");
	}
	return profile;
}

Iso8583Profile LoadIso8583Profile(ClientContext &context, const string &path_or_json) {
	string trimmed = path_or_json;
	StringUtil::Trim(trimmed);
	if (trimmed.empty()) {
		throw InvalidInputException("iso8583 profile path/JSON cannot be empty");
	}
	if (trimmed[0] == '{') {
		return ParseIso8583ProfileJson(trimmed);
	}
	auto &fs = FileSystem::GetFileSystem(context);
	auto handle = fs.OpenFile(trimmed, FileOpenFlags::FILE_FLAGS_READ);
	auto file_size = handle->GetFileSize();
	if (file_size == 0) {
		throw InvalidInputException("iso8583 profile file '%s' is empty", trimmed);
	}
	if (file_size > 16 * 1024 * 1024) {
		throw InvalidInputException("iso8583 profile file '%s' is too large", trimmed);
	}
	string content;
	content.resize(NumericCast<size_t>(file_size));
	handle->Read(content.data(), file_size);
	return ParseIso8583ProfileJson(content);
}

} // namespace cardtrace
} // namespace duckdb
