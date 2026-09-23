#define DUCKDB_EXTENSION_MAIN

#include "cardtrace_extension.hpp"
#include "emv_decoders.hpp"
#include "emv_tlv.hpp"
#include "iso8583_parser.hpp"
#include "iso8583_profile.hpp"
#include "pan_utils.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
#include "duckdb/common/file_system.hpp"
#include "duckdb/common/optional.hpp"
#include "duckdb/common/string_util.hpp"
#include "duckdb/function/scalar_function.hpp"
#include "duckdb/function/table_function.hpp"
#include "duckdb/main/extension/extension_loader.hpp"

namespace duckdb {

namespace {

using cardtrace::EmvParseResult;
using cardtrace::EmvTlvEntry;

struct EmvTlvBindData : public TableFunctionData {
	vector<EmvTlvEntry> entries;
};

struct EmvTlvGlobalState : public GlobalTableFunctionState {
	idx_t offset = 0;

	idx_t MaxThreads() const override {
		return 1;
	}
};

unique_ptr<FunctionData> EmvTlvBind(ClientContext &context, TableFunctionBindInput &input,
                                    vector<LogicalType> &return_types, vector<Identifier> &names) {
	names = {Identifier("tag"), Identifier("name"),     Identifier("length"),
	         Identifier("value_hex"), Identifier("decoded"), Identifier("depth")};
	return_types = {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::UINTEGER,
	                LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::UINTEGER};

	if (input.inputs.empty() || input.inputs[0].IsNull()) {
		throw BinderException("emv_tlv_decode payload cannot be NULL");
	}

	bool unsafe = false;
	for (auto &param : input.named_parameters) {
		if (param.first == "unsafe") {
			unsafe = BooleanValue::Get(param.second);
		} else {
			throw BinderException("emv_tlv_decode: unknown named parameter '%s'", param.first);
		}
	}

	auto payload = StringValue::Get(input.inputs[0]);
	EmvParseResult parsed;
	try {
		parsed = cardtrace::DecodeBerTlvHex(payload, true);
	} catch (std::exception &ex) {
		throw BinderException("emv_tlv_decode: %s", ex.what());
	}
	if (!parsed.error.empty()) {
		throw BinderException("emv_tlv_decode: malformed BER-TLV (%s)", parsed.error);
	}

	cardtrace::ApplyPrivacy(parsed.entries, unsafe);

	auto result = make_uniq<EmvTlvBindData>();
	result->entries = std::move(parsed.entries);
	return std::move(result);
}

unique_ptr<GlobalTableFunctionState> EmvTlvInit(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<EmvTlvGlobalState>();
}

void EmvTlvFunction(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &bind_data = data_p.bind_data->Cast<EmvTlvBindData>();
	auto &state = data_p.global_state->Cast<EmvTlvGlobalState>();

	if (state.offset >= bind_data.entries.size()) {
		return;
	}

	idx_t count = 0;
	while (state.offset < bind_data.entries.size() && count < STANDARD_VECTOR_SIZE) {
		auto &entry = bind_data.entries[state.offset++];
		output.SetValue(0, count, Value(entry.tag_hex));
		output.SetValue(1, count, entry.name.empty() ? Value() : Value(entry.name));
		output.SetValue(2, count, Value::UINTEGER(NumericCast<uint32_t>(entry.length)));
		output.SetValue(3, count, Value(entry.value_hex));
		output.SetValue(4, count, entry.decoded.empty() ? Value() : Value(entry.decoded));
		output.SetValue(5, count, Value::UINTEGER(NumericCast<uint32_t>(entry.depth)));
		count++;
	}
	output.SetCardinality(count);
}

void EmvTagScalar(DataChunk &args, ExpressionState &state, Vector &result) {
	BinaryExecutor::Execute<string_t, string_t, string_t>(
	    args.data[0], args.data[1], result, args.size(),
	    [&](string_t payload, string_t tag) -> optional<string_t> {
		    auto parsed = cardtrace::DecodeBerTlvHex(payload.GetString(), true);
		    if (!parsed.error.empty()) {
			    throw InvalidInputException("emv_tag: malformed BER-TLV (%s)", parsed.error);
		    }
		    cardtrace::ApplyPrivacy(parsed.entries, false);
		    auto value = cardtrace::FindTagValueHex(parsed, tag.GetString());
		    if (value.empty()) {
			    return nullopt;
		    }
		    return StringVector::AddString(result, value);
	    });
}

void EmvTvrDecodeScalar(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(),
	                                           [&](string_t value) -> optional<string_t> {
		                                           auto decoded = cardtrace::DecodeTvrHex(value.GetString());
		                                           if (decoded.empty()) {
			                                           return nullopt;
		                                           }
		                                           return StringVector::AddString(result, decoded);
	                                           });
}

void EmvTsiDecodeScalar(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(),
	                                           [&](string_t value) -> optional<string_t> {
		                                           auto decoded = cardtrace::DecodeTsiHex(value.GetString());
		                                           if (decoded.empty()) {
			                                           return nullopt;
		                                           }
		                                           return StringVector::AddString(result, decoded);
	                                           });
}

void EmvCvmDecodeScalar(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(),
	                                           [&](string_t value) -> optional<string_t> {
		                                           auto decoded = cardtrace::DecodeCvmHex(value.GetString());
		                                           if (decoded.empty()) {
			                                           return nullopt;
		                                           }
		                                           return StringVector::AddString(result, decoded);
	                                           });
}

void EmvCidDecodeScalar(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(),
	                                           [&](string_t value) -> optional<string_t> {
		                                           auto decoded = cardtrace::DecodeCidHex(value.GetString());
		                                           if (decoded.empty()) {
			                                           return nullopt;
		                                           }
		                                           return StringVector::AddString(result, decoded);
	                                           });
}

void PanLuhnValidScalar(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, bool>(args.data[0], result, args.size(),
	                                       [&](string_t value) { return cardtrace::PanLuhnValid(value.GetString()); });
}

void PanMaskScalar(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::Execute<string_t, string_t>(args.data[0], result, args.size(), [&](string_t value) {
		return StringVector::AddString(result, cardtrace::PanMask(value.GetString()));
	});
}

// ---------------------------------------------------------------------------
// ISO 8583 — iso8583_decode / read_iso8583
// ---------------------------------------------------------------------------

struct IsoFieldRow {
	uint64_t message_idx = 0;
	string source;
	string mti;
	string bitmap_hex;
	int32_t de = 0;
	string name;
	string value;
	string value_hex;
	string decoded;
	uint32_t offset = 0;
	string error;
};

struct Iso8583BindData : public TableFunctionData {
	vector<IsoFieldRow> rows;
};

struct Iso8583GlobalState : public GlobalTableFunctionState {
	idx_t offset = 0;

	idx_t MaxThreads() const override {
		return 1;
	}
};

static void AppendMessageRows(vector<IsoFieldRow> &rows, uint64_t message_idx, const string &source,
                              const cardtrace::Iso8583Message &msg) {
	if (msg.fields.empty()) {
		IsoFieldRow row;
		row.message_idx = message_idx;
		row.source = source;
		row.mti = msg.mti;
		row.bitmap_hex = msg.bitmap_hex;
		row.error = msg.error.empty() ? string("no fields") : msg.error;
		rows.push_back(std::move(row));
		return;
	}
	for (auto &field : msg.fields) {
		IsoFieldRow row;
		row.message_idx = message_idx;
		row.source = source;
		row.mti = msg.mti;
		row.bitmap_hex = msg.bitmap_hex;
		row.de = field.de;
		row.name = field.name;
		row.value = field.value;
		row.value_hex = field.value_hex;
		row.decoded = field.decoded;
		row.offset = NumericCast<uint32_t>(field.offset);
		row.error = field.error;
		rows.push_back(std::move(row));
	}
}

static void SetIsoReturnTypes(vector<LogicalType> &return_types, vector<Identifier> &names, bool include_source) {
	names.clear();
	return_types.clear();
	if (include_source) {
		names.emplace_back("message_idx");
		return_types.push_back(LogicalType::UBIGINT);
		names.emplace_back("source");
		return_types.push_back(LogicalType::VARCHAR);
	}
	names.emplace_back("mti");
	names.emplace_back("bitmap_hex");
	names.emplace_back("de");
	names.emplace_back("name");
	names.emplace_back("value");
	names.emplace_back("value_hex");
	names.emplace_back("decoded");
	names.emplace_back("offset");
	names.emplace_back("error");
	return_types.insert(return_types.end(),
	                    {LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::INTEGER, LogicalType::VARCHAR,
	                     LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::VARCHAR, LogicalType::UINTEGER,
	                     LogicalType::VARCHAR});
}

static string NamedString(TableFunctionBindInput &input, const string &key) {
	for (auto &param : input.named_parameters) {
		if (param.first == key) {
			return StringValue::Get(param.second);
		}
	}
	return string();
}

static string ReadEntireFile(ClientContext &context, const string &path, idx_t max_bytes) {
	auto &fs = FileSystem::GetFileSystem(context);
	auto handle = fs.OpenFile(path, FileOpenFlags::FILE_FLAGS_READ);
	auto file_size = handle->GetFileSize();
	if (file_size > max_bytes) {
		throw InvalidInputException("file '%s' exceeds size limit", path);
	}
	string content;
	content.resize(NumericCast<size_t>(file_size));
	if (file_size > 0) {
		handle->Read(content.data(), file_size);
	}
	return content;
}

unique_ptr<FunctionData> Iso8583DecodeBind(ClientContext &context, TableFunctionBindInput &input,
                                           vector<LogicalType> &return_types, vector<Identifier> &names) {
	SetIsoReturnTypes(return_types, names, false);

	if (input.inputs.size() < 2 || input.inputs[0].IsNull() || input.inputs[1].IsNull()) {
		throw BinderException("iso8583_decode requires payload and profile arguments");
	}

	bool redact = true;
	for (auto &param : input.named_parameters) {
		if (param.first == "redact_pan" || param.first == "redact") {
			redact = BooleanValue::Get(param.second);
		} else {
			throw BinderException("iso8583_decode: unknown named parameter '%s'", param.first);
		}
	}

	auto payload = StringValue::Get(input.inputs[0]);
	auto profile_arg = StringValue::Get(input.inputs[1]);
	cardtrace::Iso8583Profile profile;
	try {
		profile = cardtrace::LoadIso8583Profile(context, profile_arg);
	} catch (std::exception &ex) {
		throw BinderException("iso8583_decode profile: %s", ex.what());
	}

	auto parsed = cardtrace::ParseIso8583Message(payload, profile, redact);
	auto result = make_uniq<Iso8583BindData>();
	AppendMessageRows(result->rows, 0, "", parsed);
	return std::move(result);
}

unique_ptr<FunctionData> ReadIso8583Bind(ClientContext &context, TableFunctionBindInput &input,
                                         vector<LogicalType> &return_types, vector<Identifier> &names) {
	SetIsoReturnTypes(return_types, names, true);

	if (input.inputs.empty() || input.inputs[0].IsNull()) {
		throw BinderException("read_iso8583 requires a file path");
	}

	auto profile_arg = NamedString(input, "profile");
	if (profile_arg.empty()) {
		throw BinderException("read_iso8583 requires profile := 'path-or-json'");
	}

	bool redact = true;
	for (auto &param : input.named_parameters) {
		if (param.first == "profile") {
			continue;
		}
		if (param.first == "redact_pan" || param.first == "redact") {
			redact = BooleanValue::Get(param.second);
		} else {
			throw BinderException("read_iso8583: unknown named parameter '%s'", param.first);
		}
	}

	cardtrace::Iso8583Profile profile;
	try {
		profile = cardtrace::LoadIso8583Profile(context, profile_arg);
	} catch (std::exception &ex) {
		throw BinderException("read_iso8583 profile: %s", ex.what());
	}

	auto path = StringValue::Get(input.inputs[0]);
	string content;
	try {
		content = ReadEntireFile(context, path, 64ULL * 1024 * 1024);
	} catch (std::exception &ex) {
		throw BinderException("read_iso8583: %s", ex.what());
	}

	auto result = make_uniq<Iso8583BindData>();
	uint64_t message_idx = 0;
	idx_t line_start = 0;
	for (idx_t i = 0; i <= content.size(); i++) {
		if (i < content.size() && content[i] != '\n') {
			continue;
		}
		idx_t line_end = i;
		if (line_end > line_start && content[line_end - 1] == '\r') {
			line_end--;
		}
		string line = content.substr(line_start, line_end - line_start);
		line_start = i + 1;
		string trimmed = line;
		StringUtil::Trim(trimmed);
		if (trimmed.empty()) {
			continue;
		}
		if (!trimmed.empty() && trimmed[0] == '#') {
			continue;
		}
		auto parsed = cardtrace::ParseIso8583Message(line, profile, redact);
		AppendMessageRows(result->rows, message_idx++, path, parsed);
	}
	return std::move(result);
}

unique_ptr<GlobalTableFunctionState> Iso8583Init(ClientContext &context, TableFunctionInitInput &input) {
	return make_uniq<Iso8583GlobalState>();
}

void Iso8583Function(ClientContext &context, TableFunctionInput &data_p, DataChunk &output) {
	auto &bind_data = data_p.bind_data->Cast<Iso8583BindData>();
	auto &state = data_p.global_state->Cast<Iso8583GlobalState>();

	if (state.offset >= bind_data.rows.size()) {
		return;
	}

	const bool include_source = output.ColumnCount() > 9;
	idx_t count = 0;
	while (state.offset < bind_data.rows.size() && count < STANDARD_VECTOR_SIZE) {
		auto &row = bind_data.rows[state.offset++];
		idx_t col = 0;
		if (include_source) {
			output.SetValue(col++, count, Value::UBIGINT(row.message_idx));
			output.SetValue(col++, count, Value(row.source));
		}
		output.SetValue(col++, count, row.mti.empty() ? Value() : Value(row.mti));
		output.SetValue(col++, count, row.bitmap_hex.empty() ? Value() : Value(row.bitmap_hex));
		output.SetValue(col++, count, row.de == 0 && row.name != "trailing_data" ? Value() : Value::INTEGER(row.de));
		output.SetValue(col++, count, row.name.empty() ? Value() : Value(row.name));
		output.SetValue(col++, count, row.value.empty() ? Value() : Value(row.value));
		output.SetValue(col++, count, row.value_hex.empty() ? Value() : Value(row.value_hex));
		output.SetValue(col++, count, row.decoded.empty() ? Value() : Value(row.decoded));
		output.SetValue(col++, count, Value::UINTEGER(row.offset));
		output.SetValue(col++, count, row.error.empty() ? Value() : Value(row.error));
		count++;
	}
	output.SetCardinality(count);
}

} // namespace

static void LoadInternal(ExtensionLoader &loader) {
	TableFunction emv_tlv_decode("emv_tlv_decode", {LogicalType::VARCHAR}, EmvTlvFunction, EmvTlvBind, EmvTlvInit);
	emv_tlv_decode.named_parameters["unsafe"] = LogicalType::BOOLEAN;
	loader.RegisterFunction(emv_tlv_decode);

	loader.RegisterFunction(
	    ScalarFunction("emv_tag", {LogicalType::VARCHAR, LogicalType::VARCHAR}, LogicalType::VARCHAR, EmvTagScalar));

	loader.RegisterFunction(
	    ScalarFunction("emv_tvr_decode", {LogicalType::VARCHAR}, LogicalType::VARCHAR, EmvTvrDecodeScalar));
	loader.RegisterFunction(
	    ScalarFunction("emv_tsi_decode", {LogicalType::VARCHAR}, LogicalType::VARCHAR, EmvTsiDecodeScalar));
	loader.RegisterFunction(
	    ScalarFunction("emv_cvm_decode", {LogicalType::VARCHAR}, LogicalType::VARCHAR, EmvCvmDecodeScalar));
	loader.RegisterFunction(
	    ScalarFunction("emv_cid_decode", {LogicalType::VARCHAR}, LogicalType::VARCHAR, EmvCidDecodeScalar));

	loader.RegisterFunction(
	    ScalarFunction("pan_luhn_valid", {LogicalType::VARCHAR}, LogicalType::BOOLEAN, PanLuhnValidScalar));
	loader.RegisterFunction(ScalarFunction("pan_mask", {LogicalType::VARCHAR}, LogicalType::VARCHAR, PanMaskScalar));

	TableFunction iso8583_decode("iso8583_decode", {LogicalType::VARCHAR, LogicalType::VARCHAR}, Iso8583Function,
	                             Iso8583DecodeBind, Iso8583Init);
	iso8583_decode.named_parameters["redact_pan"] = LogicalType::BOOLEAN;
	iso8583_decode.named_parameters["redact"] = LogicalType::BOOLEAN;
	loader.RegisterFunction(iso8583_decode);

	TableFunction read_iso8583("read_iso8583", {LogicalType::VARCHAR}, Iso8583Function, ReadIso8583Bind, Iso8583Init);
	read_iso8583.named_parameters["profile"] = LogicalType::VARCHAR;
	read_iso8583.named_parameters["redact_pan"] = LogicalType::BOOLEAN;
	read_iso8583.named_parameters["redact"] = LogicalType::BOOLEAN;
	loader.RegisterFunction(read_iso8583);
}

void CardtraceExtension::Load(ExtensionLoader &loader) {
	LoadInternal(loader);
}

std::string CardtraceExtension::Name() {
	return "cardtrace";
}

std::string CardtraceExtension::Version() const {
#ifdef EXT_VERSION_CARDTRACE
	return EXT_VERSION_CARDTRACE;
#else
	return "";
#endif
}

} // namespace duckdb

extern "C" {

DUCKDB_CPP_EXTENSION_ENTRY(cardtrace, loader) {
	duckdb::LoadInternal(loader);
}
}
