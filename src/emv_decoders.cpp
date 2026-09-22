#include "emv_decoders.hpp"
#include "emv_tlv.hpp"

#include "duckdb/common/exception.hpp"
#include "duckdb/common/string_util.hpp"

namespace duckdb {
namespace cardtrace {

namespace {

void AppendFlag(vector<string> &flags, bool set, const char *name) {
	if (set) {
		flags.emplace_back(name);
	}
}

string JoinFlags(const vector<string> &flags) {
	if (flags.empty()) {
		return "none";
	}
	return StringUtil::Join(flags, "; ");
}

const char *CvmMethodName(uint8_t code) {
	// EMV Book 3, Annex C.3 - lower 6 bits are the method when applied.
	uint8_t method = code & 0x3F;
	switch (method) {
	case 0x00:
		return "Fail CVM processing";
	case 0x01:
		return "Plaintext PIN verification performed by ICC";
	case 0x02:
		return "Enciphered PIN verified online";
	case 0x03:
		return "Plaintext PIN verification by ICC and signature";
	case 0x04:
		return "Enciphered PIN verification by ICC";
	case 0x05:
		return "Enciphered PIN verification by ICC and signature";
	case 0x1E:
		return "Signature (paper)";
	case 0x1F:
		return "No CVM required";
	case 0x3F:
		return "Not available for use";
	default:
		return "Unknown CVM";
	}
}

const char *CvmConditionName(uint8_t cond) {
	switch (cond) {
	case 0x00:
		return "Always";
	case 0x01:
		return "If unattended cash";
	case 0x02:
		return "If not unattended cash and not manual cash and not purchase with cashback";
	case 0x03:
		return "If terminal supports the CVM";
	case 0x04:
		return "If manual cash";
	case 0x05:
		return "If purchase with cashback";
	case 0x06:
		return "If transaction is in the application currency and is under X value";
	case 0x07:
		return "If transaction is in the application currency and is over X value";
	case 0x08:
		return "If transaction is in the application currency and is under Y value";
	case 0x09:
		return "If transaction is in the application currency and is over Y value";
	default:
		return "Unknown condition";
	}
}

const char *CvmResultName(uint8_t result) {
	switch (result) {
	case 0x00:
		return "Unknown";
	case 0x01:
		return "Failed";
	case 0x02:
		return "Successful";
	default:
		return "RFU";
	}
}

} // namespace

string DecodeCid(const uint8_t *data, idx_t len) {
	if (!data || len < 1) {
		return "";
	}
	uint8_t cid = data[0];
	uint8_t type = (cid >> 6) & 0x03;
	const char *label = "RFU";
	switch (type) {
	case 0x00:
		label = "AAC";
		break;
	case 0x01:
		label = "TC";
		break;
	case 0x02:
		label = "ARQC";
		break;
	default:
		label = "RFU";
		break;
	}
	vector<string> parts;
	parts.emplace_back(label);
	if (cid & 0x08) {
		parts.emplace_back("advice_required");
	}
	uint8_t reason = cid & 0x07;
	if (reason != 0) {
		parts.push_back(StringUtil::Format("reason=%u", static_cast<unsigned>(reason)));
	}
	return StringUtil::Join(parts, "; ");
}

string DecodeTvr(const uint8_t *data, idx_t len) {
	if (!data || len < 5) {
		return "";
	}
	vector<string> flags;
	// Byte 1
	AppendFlag(flags, data[0] & 0x80, "Offline data authentication was not performed");
	AppendFlag(flags, data[0] & 0x40, "SDA failed");
	AppendFlag(flags, data[0] & 0x20, "ICC data missing");
	AppendFlag(flags, data[0] & 0x10, "Card appears on terminal exception file");
	AppendFlag(flags, data[0] & 0x08, "DDA failed");
	AppendFlag(flags, data[0] & 0x04, "CDA failed");
	AppendFlag(flags, data[0] & 0x02, "SDA selected");
	// Byte 2
	AppendFlag(flags, data[1] & 0x80, "ICC and terminal have different application versions");
	AppendFlag(flags, data[1] & 0x40, "Expired application");
	AppendFlag(flags, data[1] & 0x20, "Application not yet effective");
	AppendFlag(flags, data[1] & 0x10, "Requested service not allowed for card product");
	AppendFlag(flags, data[1] & 0x08, "New card");
	// Byte 3
	AppendFlag(flags, data[2] & 0x80, "Cardholder verification was not successful");
	AppendFlag(flags, data[2] & 0x40, "Unrecognised CVM");
	AppendFlag(flags, data[2] & 0x20, "PIN Try Limit exceeded");
	AppendFlag(flags, data[2] & 0x10, "PIN entry required and PIN pad not present or not working");
	AppendFlag(flags, data[2] & 0x08, "PIN entry required, PIN pad present, but PIN was not entered");
	AppendFlag(flags, data[2] & 0x04, "Online PIN entered");
	// Byte 4
	AppendFlag(flags, data[3] & 0x80, "Transaction exceeds floor limit");
	AppendFlag(flags, data[3] & 0x40, "Lower consecutive offline limit exceeded");
	AppendFlag(flags, data[3] & 0x20, "Upper consecutive offline limit exceeded");
	AppendFlag(flags, data[3] & 0x10, "Transaction selected randomly for online processing");
	AppendFlag(flags, data[3] & 0x08, "Merchant forced transaction online");
	// Byte 5
	AppendFlag(flags, data[4] & 0x80, "Default TDOL used");
	AppendFlag(flags, data[4] & 0x40, "Issuer authentication failed");
	AppendFlag(flags, data[4] & 0x20, "Script processing failed before final Generate AC");
	AppendFlag(flags, data[4] & 0x10, "Script processing failed after final Generate AC");
	return JoinFlags(flags);
}

string DecodeTsi(const uint8_t *data, idx_t len) {
	if (!data || len < 2) {
		return "";
	}
	vector<string> flags;
	AppendFlag(flags, data[0] & 0x80, "Offline data authentication was performed");
	AppendFlag(flags, data[0] & 0x40, "Cardholder verification was performed");
	AppendFlag(flags, data[0] & 0x20, "Card risk management was performed");
	AppendFlag(flags, data[0] & 0x10, "Issuer authentication was performed");
	AppendFlag(flags, data[0] & 0x08, "Terminal risk management was performed");
	AppendFlag(flags, data[0] & 0x04, "Script processing was performed");
	return JoinFlags(flags);
}

string DecodeCvmResults(const uint8_t *data, idx_t len) {
	if (!data || len < 3) {
		return "";
	}
	bool apply_succeeding = (data[0] & 0x40) != 0;
	string method = CvmMethodName(data[0]);
	string condition = CvmConditionName(data[1]);
	string result = CvmResultName(data[2]);
	return StringUtil::Format("%s; condition=%s; result=%s%s", method, condition, result,
	                          apply_succeeding ? "; apply_succeeding" : "");
}

string DecodeCidHex(const string &hex) {
	auto bytes = ParseHex(hex);
	return DecodeCid(bytes.data(), bytes.size());
}

string DecodeTvrHex(const string &hex) {
	auto bytes = ParseHex(hex);
	return DecodeTvr(bytes.data(), bytes.size());
}

string DecodeTsiHex(const string &hex) {
	auto bytes = ParseHex(hex);
	return DecodeTsi(bytes.data(), bytes.size());
}

string DecodeCvmHex(const string &hex) {
	auto bytes = ParseHex(hex);
	return DecodeCvmResults(bytes.data(), bytes.size());
}

string DecodeTagValue(const string &tag_hex, const uint8_t *data, idx_t len) {
	auto tag = StringUtil::Upper(tag_hex);
	if (tag == "9F27") {
		return DecodeCid(data, len);
	}
	if (tag == "95") {
		return DecodeTvr(data, len);
	}
	if (tag == "9B") {
		return DecodeTsi(data, len);
	}
	if (tag == "9F34") {
		return DecodeCvmResults(data, len);
	}
	return "";
}

} // namespace cardtrace
} // namespace duckdb
