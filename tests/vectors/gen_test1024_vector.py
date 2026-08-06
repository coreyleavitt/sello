#!/usr/bin/env python3
"""Extract RFC 8032 Section 7.1's TEST 1024 vector (sello's only official
multi-block-SHA-512 signature vector) from a verbatim pasted copy of the
RFC text, never hand-retyped.

RFC-001 slice 7 mandates *scripted* sourcing for this vector specifically:
it is the one Ed25519 test vector long enough (1023 bytes) to exercise
SHA-512's multi-block compression path, so a single transposed hex digit
picked up while hand-copying it would be exactly the kind of bug this
vector exists to catch -- silently defeating its own purpose.

Input: tests/vectors/rfc8032_test1024_raw.txt, a byte-for-byte paste of
the "-----TEST 1024" section of RFC 8032 (fetched from
https://www.rfc-editor.org/rfc/rfc8032.txt, 2026-08-05), including the
page-break header/footer lines pagination injected into the original
text. This script's whole job is to mechanically strip exactly those
known non-hex lines and concatenate what remains -- no hex is ever typed
here, only recognized and sliced by the field lengths RFC 8032 itself
declares (32/32/1023/64 bytes).

Self-checks (a transcription error must fail loudly, not silently):
  - total extracted hex must equal 64+64+2046+128 = 2302 hex digits
    (32+32+1023+64 bytes), i.e. every line in the raw file classified as
    either a known label/page-break line or a hex data line, no leftovers;
  - message length must be exactly 1023 bytes;
  - message first/last 4 bytes must match the constants below, transcribed
    independently by eye from the same RFC page as an endpoint cross-check;
  - secret key and public key must match sello's own slice-5 TEST-1024
    keygen vectors (tests/unit/test_signing.nim), already verified against
    RFC 8032 -- an independent second source for the same 64 bytes.

Output: tests/vectors/test1024_vector.json, checked in alongside this
script and the raw paste (same pattern as gen_scmuladd_vectors.py).

Usage:
    python3 tests/vectors/gen_test1024_vector.py > tests/vectors/test1024_vector.json

Run from the repository root (or adjust the paths accordingly).
"""
import json
import pathlib
import re

RAW_PATH = pathlib.Path(__file__).parent / "rfc8032_test1024_raw.txt"

# Independently-transcribed endpoint self-check (see module docstring).
MSG_LEN = 1023
MSG_FIRST4 = "08b8b2b7"
MSG_LAST4 = "00a0b9d0"

# Cross-check against sello's already-RFC-verified slice-5 keygen vectors
# (tests/unit/test_signing.nim tv1024_sk / tv1024_pk).
EXPECTED_SK = (
    "f5e5767cf153319517630f226876b86c8160cc583bc013744c6bf255f5cc0ee5"
)
EXPECTED_PK = (
    "278117fc144c72340f67d0f2316e8386ceffbf2b2428c9c51fef7c597f1d426e"
)

HEX_LINE_RE = re.compile(r"^[0-9a-fA-F]+$")

# Lines that are structure/pagination, not hex data. Matched verbatim
# (after stripping) or by prefix for the two lines that vary (page number,
# "MESSAGE (length ... bytes):").
KNOWN_LABEL_LINES = {
    "-----TEST 1024",
    "ALGORITHM:",
    "Ed25519",
    "SECRET KEY:",
    "PUBLIC KEY:",
    "SIGNATURE:",
}


def is_noise_line(line: str) -> bool:
    if line == "":
        return True
    if line in KNOWN_LABEL_LINES:
        return True
    if line.startswith("MESSAGE (length"):
        return True
    if line.startswith("Josefsson & Liusvaara"):
        return True
    if line.startswith("RFC 8032"):
        return True
    return False


def extract_hex(raw_text: str) -> str:
    hex_chunks = []
    for lineno, raw_line in enumerate(raw_text.splitlines(), start=1):
        line = raw_line.strip()
        if is_noise_line(line):
            continue
        if not HEX_LINE_RE.match(line):
            raise ValueError(
                f"line {lineno}: not a recognized label line and not "
                f"pure hex -- unclassified content, refusing to guess: "
                f"{raw_line!r}"
            )
        hex_chunks.append(line)
    return "".join(hex_chunks)


def main() -> None:
    raw_text = RAW_PATH.read_text()
    all_hex = extract_hex(raw_text)

    expected_total_hex = (32 + 32 + 1023 + 64) * 2
    if len(all_hex) != expected_total_hex:
        raise AssertionError(
            f"extracted {len(all_hex)} hex digits, expected "
            f"{expected_total_hex} (32+32+1023+64 bytes) -- a label line "
            f"was misclassified as data, or vice versa"
        )

    sk_hex = all_hex[0:64]
    pk_hex = all_hex[64:128]
    msg_hex = all_hex[128:128 + 1023 * 2]
    sig_hex = all_hex[128 + 1023 * 2:]
    assert len(sig_hex) == 128, "signature must be exactly 64 bytes"

    # Transcription self-checks -- fail loudly on any mismatch.
    msg_bytes = bytes.fromhex(msg_hex)
    if len(msg_bytes) != MSG_LEN:
        raise AssertionError(
            f"message length {len(msg_bytes)} != {MSG_LEN}"
        )
    if msg_hex[:8] != MSG_FIRST4:
        raise AssertionError(
            f"message first 4 bytes {msg_hex[:8]} != expected {MSG_FIRST4}"
        )
    if msg_hex[-8:] != MSG_LAST4:
        raise AssertionError(
            f"message last 4 bytes {msg_hex[-8:]} != expected {MSG_LAST4}"
        )
    if sk_hex != EXPECTED_SK:
        raise AssertionError(
            f"secret key {sk_hex} != sello's verified slice-5 vector "
            f"{EXPECTED_SK}"
        )
    if pk_hex != EXPECTED_PK:
        raise AssertionError(
            f"public key {pk_hex} != sello's verified slice-5 vector "
            f"{EXPECTED_PK}"
        )

    doc = {
        "description": (
            "RFC 8032 Section 7.1 TEST 1024: the 1023-byte-message Ed25519 "
            "vector, the only official vector long enough to exercise "
            "SHA-512's multi-block compression path. Extracted "
            "programmatically by gen_test1024_vector.py from a verbatim "
            "paste of the RFC text (rfc8032_test1024_raw.txt), never "
            "hand-retyped; see that script for the self-checks applied."
        ),
        "secretKey": sk_hex,
        "publicKey": pk_hex,
        "message": msg_hex,
        "signature": sig_hex,
    }
    print(json.dumps(doc, indent=2))


if __name__ == "__main__":
    main()
