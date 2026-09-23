# CardTrace

CardTrace is a DuckDB extension that decodes EMV payment data and configurable ISO 8583 messages in SQL. Sensitive fields are redacted by default.

This repository is based on the [DuckDB extension template](https://github.com/duckdb/extension-template).

## Status

> [!WARNING]
> This is a personal duckdb extension written with AI assisted tools. Use it with your own risk. Currently in MVP phase.

| Phase | Scope | Status |
|-------|-------|--------|
| MVP | BER-TLV decode, EMV tag extract, TVR/TSI/CVM/CID bitfields, PAN Luhn + mask | Implemented |
| Phase 2 | Configurable ISO 8583 via external JSON profiles | Implemented |

## Quick start

```sql
-- After community publication:
-- INSTALL cardtrace FROM community;
LOAD cardtrace;

SELECT *
FROM emv_tlv_decode('9F2608A1B2C3D4E5F607089F270180');
```

| tag  | name                        | length | value_hex          | decoded | depth |
|------|-----------------------------|-------:|--------------------|---------|------:|
| 9F26 | Application Cryptogram      |      8 | A1B2C3D4E5F60708   | NULL    |     0 |
| 9F27 | Cryptogram Information Data |      1 | 80                 | ARQC    |     0 |

```sql
SELECT de, name, value, decoded
FROM read_iso8583(
  'authorization.log',
  profile := 'profiles/generic_ascii.json',
  redact_pan := true
);
```

## Functions

| Function | Type | Description |
|----------|------|-------------|
| `emv_tlv_decode(payload [, unsafe := false])` | table | One row per BER-TLV tag |
| `emv_tag(payload, tag)` | scalar | Extract a tag value (hex); PAN/track privacy applied |
| `emv_tvr_decode(value)` | scalar | Decode Terminal Verification Results (tag 95) |
| `emv_tsi_decode(value)` | scalar | Decode Transaction Status Information (tag 9B) |
| `emv_cvm_decode(value)` | scalar | Decode CVM Results (tag 9F34) |
| `emv_cid_decode(value)` | scalar | Decode Cryptogram Information Data (tag 9F27) |
| `pan_luhn_valid(value)` | scalar | Luhn check (synthetic / already-tokenized inputs) |
| `pan_mask(value)` | scalar | Mask PAN to first 6 + last 4 |
| `iso8583_decode(payload, profile [, redact_pan := true])` | table | Decode one ASCII ISO 8583 message using a JSON profile |
| `read_iso8583(path, profile := '...', redact_pan := true)` | table | Decode one message per line from a file |

### Investigation pattern

```sql
SELECT
    terminal_model,
    emv_tag(de55, '9F27') AS cryptogram_type,
    emv_cid_decode(emv_tag(de55, '9F27')) AS cid,
    emv_tvr_decode(emv_tag(de55, '95')) AS tvr,
    count(*) AS attempts
FROM read_parquet('transactions/*.parquet')
GROUP BY ALL;
```

## Privacy defaults

By default, CardTrace redacts PAN, track 2, and PIN data during parse:

* **PAN** (tag `5A`) is masked automatically (`411111******1111`).
* **Track 2 equivalent data** (tag `57`) is never returned unless `unsafe := true`.
* **PIN blocks** (tag `99`) are shown only as presence/length metadata unless `unsafe := true`.
* Redaction happens during parsing, not as a post-process SQL step.
* This repository ships synthetic fixtures only. Do not add real card data.

```sql
-- Explicit opt-in required for raw sensitive values
SELECT * FROM emv_tlv_decode(payload, unsafe := true);
```

## Building

DuckDB extensions may use VCPKG. CardTrace has no third-party dependencies, so VCPKG is optional.

```sh
git submodule update --init --recursive
GEN=ninja make
make test
```

Binaries:

```
./build/release/duckdb
./build/release/test/unittest
./build/release/extension/cardtrace/cardtrace.duckdb_extension
```

Run only CardTrace SQL tests:

```sh
./build/release/test/unittest "test/sql/cardtrace.test"
```

## Roadmap

1. Generic BER-TLV parser with strict malformed-input handling
2. EMV tag extraction and common bit-field decoders
3. PAN-safe defaults
4. Synthetic golden test corpus + DE55 benchmarks
5. Configurable ISO 8583 via external JSON profiles (`iso8583_decode` / `read_iso8583`)
6. Additional wire encodings (binary/EBCDIC) and more network dialect profiles

Dialect profiles live under `profiles/`. See `profiles/README.md`.

## Community publication

To publish to [DuckDB Community Extensions](https://duckdb.org/community_extensions/documentation), open a PR against `duckdb/community-extensions` with `extensions/cardtrace/description.yml` (see `community/description.yml` in this repo).

## License

MIT
