# CardTrace ISO 8583 profiles

Dialect-specific ISO 8583 layouts live here as JSON. The C++ parser stays generic:
MTI, bitmaps, length prefixes, and field content rules come from these files.

## Schema

```json
{
  "name": "generic-ascii",
  "version": 1,
  "encoding": "ascii",
  "header": {
    "mti_length": 4,
    "bitmap_encoding": "hex",
    "bitmap_length": 16,
    "secondary_bitmap": true
  },
  "fields": {
    "2": {
      "name": "Primary Account Number",
      "length_type": "llvar",
      "max_length": 19,
      "content": "ascii",
      "sensitive": "pan"
    },
    "55": {
      "name": "ICC System Related Data",
      "length_type": "lllvar",
      "max_length": 999,
      "content": "hex",
      "emv_tlv": true
    }
  }
}
```

| Key | Meaning |
|-----|---------|
| `encoding` | Wire encoding. Currently `ascii` only (MTI digits, hex bitmap, ASCII/hex fields). |
| `length_type` | `fixed`, `llvar` (2-digit length), or `lllvar` (3-digit length). |
| `content` | `ascii` (length in characters) or `hex` (length in bytes, on-wire is 2 hex chars/byte). Aliases: `n`/`an`/`ans` → ascii, `b` → hex. |
| `sensitive` | `pan`, `track`, or `pin` — redacted unless `redact_pan := false`. |
| `emv_tlv` | When true, CardTrace runs BER-TLV decode and fills `decoded`. |

Visa, Mastercard, and acquirer dialects should be additional JSON files in this directory, not hardcoded C++.
