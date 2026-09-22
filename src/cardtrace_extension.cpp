#define DUCKDB_EXTENSION_MAIN

#include "cardtrace_extension.hpp"
#include "emv_decoders.hpp"
#include "emv_tlv.hpp"
#include "pan_utils.hpp"

#include "duckdb.hpp"
#include "duckdb/common/exception.hpp"
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
                                    vector<LogicalType> &return_types, vector<string> &names) {
	names = {"tag", "name", "length", "value_hex", "decoded", "depth"};
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
	auto &payload_vec = args.data[0];
	auto &tag_vec = args.data[1];

	BinaryExecutor::ExecuteWithNulls<string_t, string_t, string_t>(
	    payload_vec, tag_vec, result, args.size(),
	    [&](string_t payload, string_t tag, ValidityMask &mask, idx_t idx) {
		    auto parsed = cardtrace::DecodeBerTlvHex(payload.GetString(), true);
		    if (!parsed.error.empty()) {
			    throw InvalidInputException("emv_tag: malformed BER-TLV (%s)", parsed.error);
		    }
		    cardtrace::ApplyPrivacy(parsed.entries, false);
		    auto value = cardtrace::FindTagValueHex(parsed, tag.GetString());
		    if (value.empty()) {
			    mask.SetInvalid(idx);
			    return string_t();
		    }
		    return StringVector::AddString(result, value);
	    });
}

void EmvTvrDecodeScalar(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::ExecuteWithNulls<string_t, string_t>(
	    args.data[0], result, args.size(), [&](string_t value, ValidityMask &mask, idx_t idx) {
		    auto decoded = cardtrace::DecodeTvrHex(value.GetString());
		    if (decoded.empty()) {
			    mask.SetInvalid(idx);
			    return string_t();
		    }
		    return StringVector::AddString(result, decoded);
	    });
}

void EmvTsiDecodeScalar(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::ExecuteWithNulls<string_t, string_t>(
	    args.data[0], result, args.size(), [&](string_t value, ValidityMask &mask, idx_t idx) {
		    auto decoded = cardtrace::DecodeTsiHex(value.GetString());
		    if (decoded.empty()) {
			    mask.SetInvalid(idx);
			    return string_t();
		    }
		    return StringVector::AddString(result, decoded);
	    });
}

void EmvCvmDecodeScalar(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::ExecuteWithNulls<string_t, string_t>(
	    args.data[0], result, args.size(), [&](string_t value, ValidityMask &mask, idx_t idx) {
		    auto decoded = cardtrace::DecodeCvmHex(value.GetString());
		    if (decoded.empty()) {
			    mask.SetInvalid(idx);
			    return string_t();
		    }
		    return StringVector::AddString(result, decoded);
	    });
}

void EmvCidDecodeScalar(DataChunk &args, ExpressionState &state, Vector &result) {
	UnaryExecutor::ExecuteWithNulls<string_t, string_t>(
	    args.data[0], result, args.size(), [&](string_t value, ValidityMask &mask, idx_t idx) {
		    auto decoded = cardtrace::DecodeCidHex(value.GetString());
		    if (decoded.empty()) {
			    mask.SetInvalid(idx);
			    return string_t();
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
