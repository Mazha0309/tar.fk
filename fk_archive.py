#!/usr/bin/env python3
"""
FK Archive Format v2

FK = FK's Kompressor

A deliberately silly, lossless anti-compression archive format.

Default pipeline:
    input files/directories -> tar stream -> base64 -> duplicate every char -> .tar.fk

File layout:
    [64-byte FK header][payload]

Payload algorithm v1:
    base64(tar_data), then duplicate each Base64 byte:
        b"ABC=" -> b"AABBCC=="

Payload algorithm v2:
    base64(tar_data), then triplicate each Base64 byte:
        b"ABC=" -> b"AAABBBCCC==="

Payload algorithm v3 (encrypted):
    Encrypt tar_data with AES-256-GCM using password-derived key, then base64, then dup2.

Usage:
    Pack one file or directory:
        python fk_archive.py pack input_path output.tar.fk
        python fk_archive.py pack --algorithm dup3 input_path output.tar.fk
        python fk_archive.py pack --algorithm encrypted --password secret input_path output.tar.fk

    Pack multiple paths:
        python fk_archive.py pack file1 dir2 file3 output.tar.fk

    Unpack:
        python fk_archive.py unpack output.tar.fk extracted_dir
        python fk_archive.py unpack --password secret output.tar.fk extracted_dir

    Show info:
        python fk_archive.py info output.tar.fk
"""

from __future__ import annotations

import argparse
import base64
import getpass
import hashlib
import io
import os
import struct
import sys
import tarfile
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Callable

# Optional encryption support
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    HAS_CRYPTOGRAPHY = True
except ImportError:
    HAS_CRYPTOGRAPHY = False


MAGIC = b"FKAR\r\n\x1A\n"
HEADER_SIZE = 64
VERSION = 2

# Algorithms
ALGORITHM_BASE64_DUP2 = 1
ALGORITHM_BASE64_DUP3 = 2
ALGORITHM_ENCRYPTED_DUP2 = 3
ALGORITHM_BITEXPAND = 4
ALGORITHM_NESTED = 5
ALGORITHM_RS_REDUNDANT = 6

# magic[8], header_size[u16], version[u16], flags[u32], algorithm[u32], reserved[u32],
# original_size[u64], payload_size[u64], crc32_original[u32], crc32_payload[u32], reserved2[16]
HEADER_STRUCT = struct.Struct("<8sHHIIIQQII16s")

ALGORITHM_NAMES = {
    ALGORITHM_BASE64_DUP2: "base64 + dup2",
    ALGORITHM_BASE64_DUP3: "base64 + dup3",
    ALGORITHM_ENCRYPTED_DUP2: "encrypted + base64 + dup2",
    ALGORITHM_BITEXPAND: "bit-expand + base64",
    ALGORITHM_NESTED: "base64 + hex + dup3 + base64",
    ALGORITHM_RS_REDUNDANT: "reed-solomon redundancy",
}


class FKError(Exception):
    """FK archive error."""


@dataclass(frozen=True)
class FKHeader:
    magic: bytes
    header_size: int
    version: int
    flags: int
    algorithm: int
    reserved: int
    original_size: int
    payload_size: int
    crc32_original: int
    crc32_payload: int
    reserved2: bytes

    def pack(self) -> bytes:
        return HEADER_STRUCT.pack(
            self.magic,
            self.header_size,
            self.version,
            self.flags,
            self.algorithm,
            self.reserved,
            self.original_size,
            self.payload_size,
            self.crc32_original,
            self.crc32_payload,
            self.reserved2,
        )

    @classmethod
    def unpack(cls, data: bytes) -> "FKHeader":
        if len(data) != HEADER_SIZE:
            raise FKError(f"invalid header length: expected {HEADER_SIZE}, got {len(data)}")
        header = cls(*HEADER_STRUCT.unpack(data))
        header.validate_basic()
        return header

    def validate_basic(self) -> None:
        if self.magic != MAGIC:
            raise FKError(f"bad magic: expected {MAGIC!r}, got {self.magic!r}")
        if self.header_size != HEADER_SIZE:
            raise FKError(f"unsupported header size: {self.header_size}")
        if self.version > VERSION:
            raise FKError(f"unsupported FK version: {self.version} (max supported: {VERSION})")
        if self.algorithm not in ALGORITHM_NAMES:
            raise FKError(f"unsupported algorithm id: {self.algorithm}")
        if self.reserved != 0:
            raise FKError("reserved field must be 0")
        if self.reserved2 != b"\x00" * 16:
            raise FKError("reserved2 field must be zero-filled")


def crc32_u32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def dup_encode(data: bytes, times: int) -> bytes:
    """Duplicate every byte N times: b'ABC' -> b'AAABBBCCC' for times=3."""
    out = bytearray(len(data) * times)
    j = 0
    for b in data:
        for _ in range(times):
            out[j] = b
            j += 1
    return bytes(out)


def dup_decode(data: bytes, times: int) -> bytes:
    """Decode duplicated bytes. Validates every group."""
    if len(data) % times != 0:
        raise FKError(f"payload length is not divisible by {times}")

    out = bytearray(len(data) // times)
    for i in range(0, len(data), times):
        group = data[i : i + times]
        first = group[0]
        if any(b != first for b in group):
            raise FKError(f"bad duplicated byte group at payload offset {i}")
        out[i // times] = first
    return bytes(out)


def bitexpand_encode(data: bytes) -> bytes:
    """Expand each byte to 8 ASCII '0'/'1' chars, then base64.
    b'\xAB' -> b'10101011' -> base64('10101011')
    """
    bits = "".join(f"{b:08b}" for b in data)
    return base64.b64encode(bits.encode("ascii"))


def bitexpand_decode(data: bytes) -> bytes:
    """Decode bit-expanded base64 payload."""
    bits = base64.b64decode(data, validate=True).decode("ascii")
    if len(bits) % 8 != 0:
        raise FKError("bit-expand payload length is not divisible by 8")
    out = bytearray(len(bits) // 8)
    for i in range(0, len(bits), 8):
        byte_str = bits[i : i + 8]
        if not set(byte_str).issubset({"0", "1"}):
            raise FKError(f"invalid bit string at offset {i}: {byte_str!r}")
        out[i // 8] = int(byte_str, 2)
    return bytes(out)


def nested_encode(data: bytes) -> bytes:
    """base64 -> hex -> dup3 -> base64. Maximum bloat."""
    b64_1 = base64.b64encode(data)
    hexed = b64_1.hex().encode("ascii")
    dup3 = dup_encode(hexed, 3)
    return base64.b64encode(dup3)


def nested_decode(data: bytes) -> bytes:
    """Decode nested payload: base64 -> dup3_decode -> hex -> base64_decode."""
    b64_dup3 = base64.b64decode(data, validate=True)
    hexed = dup_decode(b64_dup3, 3)
    b64_1 = bytes.fromhex(hexed.decode("ascii"))
    return base64.b64decode(b64_1, validate=True)


def _gf256_mul(a: int, b: int) -> int:
    """Multiply two numbers in GF(2^8) with primitive polynomial x^8 + x^4 + x^3 + x^2 + 1 (0x11d)."""
    result = 0
    for _ in range(8):
        if b & 1:
            result ^= a
        a <<= 1
        if a & 0x100:
            a ^= 0x11D
        b >>= 1
    return result


def _rs_encode_message(msg: bytes, nsym: int) -> bytes:
    """Simple Reed-Solomon encoder over GF(256). Adds nsym redundancy symbols."""
    gen = [1]
    for i in range(nsym):
        gen = _gf256_poly_mul(gen, [1, _gf256_pow(2, i)])
    remainder = list(msg) + [0] * nsym
    for i in range(len(msg)):
        coef = remainder[i]
        if coef != 0:
            for j in range(len(gen)):
                remainder[i + j] ^= _gf256_mul(gen[j], coef)
    return msg + bytes(remainder[len(msg):])


def _gf256_pow(a: int, n: int) -> int:
    result = 1
    while n:
        if n & 1:
            result = _gf256_mul(result, a)
        a = _gf256_mul(a, a)
        n >>= 1
    return result


def _gf256_poly_mul(p: list[int], q: list[int]) -> list[int]:
    r = [0] * (len(p) + len(q) - 1)
    for i in range(len(p)):
        for j in range(len(q)):
            r[i + j] ^= _gf256_mul(p[i], q[j])
    return r


def rs_redundant_encode(data: bytes, ratio: float = 2.0) -> bytes:
    """Add Reed-Solomon redundancy: for every K bytes add M parity bytes where (K+M)/K = ratio.
    Format: [original_size:u32][k:u32][nsym:u32][chunks...]
    """
    k = 32
    m = int(k * (ratio - 1))
    if m < 2:
        m = 2
    nsym = m
    chunks = []
    for i in range(0, len(data), k):
        chunk = data[i : i + k]
        if len(chunk) < k:
            chunk = chunk + b"\x00" * (k - len(chunk))
        encoded = _rs_encode_message(chunk, nsym)
        chunks.append(encoded)
    header = struct.pack("<III", len(data), k, nsym)
    return header + b"".join(chunks)


def _rs_decode_message(msg: bytes, nsym: int) -> bytes:
    """Simple RS decoder: just extract the message part (no error correction for now)."""
    return msg[:-nsym]


def rs_redundant_decode(data: bytes) -> bytes:
    """Decode RS redundant payload.
    Format: [original_size:u32][k:u32][nsym:u32][chunks...]
    """
    if len(data) < 12:
        raise FKError("RS payload too short")
    original_size, k, nsym = struct.unpack("<III", data[:12])
    chunk_size = k + nsym
    payload = data[12:]
    if len(payload) % chunk_size != 0:
        raise FKError("RS payload length mismatch")
    chunks = []
    for i in range(0, len(payload), chunk_size):
        chunk = payload[i : i + chunk_size]
        decoded = _rs_decode_message(chunk, nsym)
        chunks.append(decoded)
    result = b"".join(chunks)
    return result[:original_size]


def _derive_key(password: str, salt: bytes) -> bytes:
    """Derive a 256-bit key from password using PBKDF2-like simple hashing."""
    return hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), salt, 100000, dklen=32)


def _encrypt_aes_gcm(plaintext: bytes, password: str) -> bytes:
    if not HAS_CRYPTOGRAPHY:
        raise FKError("encryption requires 'cryptography' package: pip install cryptography")
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return salt + nonce + ciphertext


def _decrypt_aes_gcm(ciphertext: bytes, password: str) -> bytes:
    if not HAS_CRYPTOGRAPHY:
        raise FKError("encryption requires 'cryptography' package: pip install cryptography")
    if len(ciphertext) < 28:
        raise FKError("encrypted payload too short")
    salt = ciphertext[:16]
    nonce = ciphertext[16:28]
    encrypted = ciphertext[28:]
    key = _derive_key(password, salt)
    aesgcm = AESGCM(key)
    try:
        return aesgcm.decrypt(nonce, encrypted, None)
    except Exception as exc:
        raise FKError(f"decryption failed (bad password or corrupted data): {exc}") from exc


def make_tar_stream(paths: list[Path]) -> bytes:
    """Create a tar stream from one or more filesystem paths."""
    buf = io.BytesIO()

    with tarfile.open(fileobj=buf, mode="w") as tf:
        for path in paths:
            path = path.resolve()
            if not path.exists():
                raise FKError(f"input path does not exist: {path}")

            # Store each root path by its basename, not as an absolute path.
            arcname = path.name
            tf.add(path, arcname=arcname, recursive=True)

    return buf.getvalue()


def _encode_payload(tar_data: bytes, algorithm: int, password: str | None = None) -> bytes:
    if algorithm == ALGORITHM_ENCRYPTED_DUP2:
        if password is None:
            raise FKError("encrypted algorithm requires a password")
        encrypted = _encrypt_aes_gcm(tar_data, password)
        b64 = base64.b64encode(encrypted)
        return dup_encode(b64, 2)
    elif algorithm == ALGORITHM_BASE64_DUP3:
        b64 = base64.b64encode(tar_data)
        return dup_encode(b64, 3)
    elif algorithm == ALGORITHM_BASE64_DUP2:
        b64 = base64.b64encode(tar_data)
        return dup_encode(b64, 2)
    elif algorithm == ALGORITHM_BITEXPAND:
        return bitexpand_encode(tar_data)
    elif algorithm == ALGORITHM_NESTED:
        return nested_encode(tar_data)
    elif algorithm == ALGORITHM_RS_REDUNDANT:
        return rs_redundant_encode(tar_data, ratio=2.0)
    else:
        raise FKError(f"unsupported algorithm id: {algorithm}")


def _decode_payload(payload: bytes, algorithm: int, password: str | None = None) -> bytes:
    if algorithm == ALGORITHM_ENCRYPTED_DUP2:
        b64 = dup_decode(payload, 2)
        encrypted = base64.b64decode(b64, validate=True)
        if password is None:
            raise FKError("encrypted archive requires --password")
        return _decrypt_aes_gcm(encrypted, password)
    elif algorithm == ALGORITHM_BASE64_DUP3:
        b64 = dup_decode(payload, 3)
        return base64.b64decode(b64, validate=True)
    elif algorithm == ALGORITHM_BASE64_DUP2:
        b64 = dup_decode(payload, 2)
        return base64.b64decode(b64, validate=True)
    elif algorithm == ALGORITHM_BITEXPAND:
        return bitexpand_decode(payload)
    elif algorithm == ALGORITHM_NESTED:
        return nested_decode(payload)
    elif algorithm == ALGORITHM_RS_REDUNDANT:
        return rs_redundant_decode(payload)
    else:
        raise FKError(f"unsupported algorithm id: {algorithm}")


def fk_encode_tar_bytes(tar_data: bytes, algorithm: int = ALGORITHM_BASE64_DUP2, password: str | None = None) -> bytes:
    payload = _encode_payload(tar_data, algorithm, password)

    header = FKHeader(
        magic=MAGIC,
        header_size=HEADER_SIZE,
        version=VERSION,
        flags=0,
        algorithm=algorithm,
        reserved=0,
        original_size=len(tar_data),
        payload_size=len(payload),
        crc32_original=crc32_u32(tar_data),
        crc32_payload=crc32_u32(payload),
        reserved2=b"\x00" * 16,
    )

    return header.pack() + payload


def fk_decode_to_tar_bytes(fk_data: bytes, password: str | None = None) -> tuple[FKHeader, bytes]:
    if len(fk_data) < HEADER_SIZE:
        raise FKError("file is too small to be a FK archive")

    header = FKHeader.unpack(fk_data[:HEADER_SIZE])
    payload = fk_data[HEADER_SIZE:]

    if len(payload) != header.payload_size:
        raise FKError(
            f"payload size mismatch: header says {header.payload_size}, actual {len(payload)}"
        )

    actual_payload_crc = crc32_u32(payload)
    if actual_payload_crc != header.crc32_payload:
        raise FKError(
            f"payload CRC32 mismatch: header {header.crc32_payload:08x}, actual {actual_payload_crc:08x}"
        )

    tar_data = _decode_payload(payload, header.algorithm, password)

    if len(tar_data) != header.original_size:
        raise FKError(
            f"original tar size mismatch: header says {header.original_size}, actual {len(tar_data)}"
        )

    actual_original_crc = crc32_u32(tar_data)
    if actual_original_crc != header.crc32_original:
        raise FKError(
            f"original CRC32 mismatch: header {header.crc32_original:08x}, actual {actual_original_crc:08x}"
        )

    return header, tar_data


def is_safe_tar_member(dest_dir: Path, member_name: str) -> bool:
    """Prevent path traversal during tar extraction."""
    dest_dir = dest_dir.resolve()
    target = (dest_dir / member_name).resolve()
    try:
        target.relative_to(dest_dir)
        return True
    except ValueError:
        return False


def safe_extract_tar(tar_data: bytes, dest_dir: Path) -> None:
    dest_dir.mkdir(parents=True, exist_ok=True)

    with tarfile.open(fileobj=io.BytesIO(tar_data), mode="r:") as tf:
        members = tf.getmembers()

        for member in members:
            if member.name.startswith("/") or member.name.startswith("\\"):
                raise FKError(f"unsafe absolute path in tar: {member.name!r}")
            if not is_safe_tar_member(dest_dir, member.name):
                raise FKError(f"unsafe path traversal in tar: {member.name!r}")

            # Avoid extracting special device files. They are rarely wanted and can be dangerous.
            if member.isdev():
                raise FKError(f"refusing to extract device file: {member.name!r}")

            # Avoid extracting symlinks/hardlinks to prevent path traversal and overwrites.
            if member.issym() or member.islnk():
                raise FKError(f"refusing to extract link: {member.name!r}")

        tf.extractall(dest_dir, members=members)


def _get_password(args: argparse.Namespace, prompt: str) -> str | None:
    if args.password:
        return args.password
    if args.password_file:
        return Path(args.password_file).read_text().strip()
    if getattr(args, "algorithm", None) == "encrypted":
        return getpass.getpass(prompt)
    return None


def pack_command(args: argparse.Namespace) -> int:
    input_paths = [Path(p) for p in args.inputs]
    output_path = Path(args.output)

    algorithm_map = {
        "dup2": ALGORITHM_BASE64_DUP2,
        "dup3": ALGORITHM_BASE64_DUP3,
        "encrypted": ALGORITHM_ENCRYPTED_DUP2,
        "bitexpand": ALGORITHM_BITEXPAND,
        "nested": ALGORITHM_NESTED,
        "rs": ALGORITHM_RS_REDUNDANT,
    }
    algorithm = algorithm_map.get(args.algorithm, ALGORITHM_BASE64_DUP2)
    password = _get_password(args, "Enter encryption password: ")

    tar_data = make_tar_stream(input_paths)
    fk_data = fk_encode_tar_bytes(tar_data, algorithm=algorithm, password=password)

    if output_path.suffixes[-2:] != [".tar", ".fk"]:
        print(
            f"warning: output path does not end with .tar.fk: {output_path}",
            file=sys.stderr,
        )

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(fk_data)

    ratio = len(fk_data) / len(tar_data) if tar_data else float("inf")
    expansion_rate = ratio - 1

    print(f"created: {output_path}")
    print(f"tar size: {len(tar_data)} bytes")
    print(f"fk size:  {len(fk_data)} bytes")
    print(f"bloat ratio: {ratio:.6f}x")
    print(f"expansion rate: {expansion_rate * 100:.2f}%")
    print(f"algorithm: {ALGORITHM_NAMES[algorithm]}")
    return 0


def unpack_command(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)

    password = _get_password(args, "Enter decryption password: ")

    fk_data = input_path.read_bytes()
    header, tar_data = fk_decode_to_tar_bytes(fk_data, password=password)
    safe_extract_tar(tar_data, output_dir)

    print(f"extracted: {input_path} -> {output_dir}")
    print(f"original tar size: {header.original_size} bytes")
    print(f"payload size:      {header.payload_size} bytes")
    print(f"algorithm:         {ALGORITHM_NAMES[header.algorithm]}")
    return 0


def info_command(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    fk_data = input_path.read_bytes()

    if len(fk_data) < HEADER_SIZE:
        raise FKError("file is too small to be a FK archive")

    header = FKHeader.unpack(fk_data[:HEADER_SIZE])
    payload_actual_size = max(0, len(fk_data) - HEADER_SIZE)

    print("FK Archive Info")
    print(f"file:             {input_path}")
    print(f"magic:            {header.magic!r}")
    print(f"header size:      {header.header_size}")
    print(f"version:          {header.version}")
    print(f"flags:            {header.flags}")
    print(f"algorithm:        {header.algorithm} = {ALGORITHM_NAMES.get(header.algorithm, 'unknown')}")
    print(f"original size:    {header.original_size} bytes")
    print(f"payload size:     {header.payload_size} bytes")
    print(f"actual payload:   {payload_actual_size} bytes")
    print(f"crc32 original:   {header.crc32_original:08x}")
    print(f"crc32 payload:    {header.crc32_payload:08x}")

    if header.payload_size != payload_actual_size:
        print("warning: payload size mismatch")
        return 2

    total_ratio = len(fk_data) / header.original_size if header.original_size else float("inf")
    payload_ratio = header.payload_size / header.original_size if header.original_size else float("inf")
    expansion_rate = total_ratio - 1

    print(f"payload bloat:    {payload_ratio:.6f}x")
    print(f"total bloat:      {total_ratio:.6f}x")
    print(f"expansion rate: {expansion_rate * 100:.2f}%")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="fk_archive.py",
        description="FK's Kompressor: a lossless anti-compression .tar.fk archive tool.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_pack = sub.add_parser("pack", help="pack files/directories into a .tar.fk archive")
    p_pack.add_argument(
        "paths",
        nargs="+",
        help="input path(s), followed by output .tar.fk path",
    )
    p_pack.add_argument(
        "--algorithm",
        choices=["dup2", "dup3", "encrypted", "bitexpand", "nested", "rs"],
        default="nested",
        help="encoding algorithm (default: nested)",
    )
    p_pack.add_argument(
        "--password",
        default=None,
        help="encryption password (for encrypted algorithm)",
    )
    p_pack.add_argument(
        "--password-file",
        default=None,
        help="read encryption password from file",
    )
    p_pack.set_defaults(func=pack_command)

    p_unpack = sub.add_parser("unpack", help="unpack a .tar.fk archive")
    p_unpack.add_argument("input", help="input .tar.fk file")
    p_unpack.add_argument("output_dir", help="output directory")
    p_unpack.add_argument(
        "--password",
        default=None,
        help="decryption password (for encrypted archives)",
    )
    p_unpack.add_argument(
        "--password-file",
        default=None,
        help="read decryption password from file",
    )
    p_unpack.set_defaults(func=unpack_command)

    p_info = sub.add_parser("info", help="show FK archive header information")
    p_info.add_argument("input", help="input .tar.fk file")
    p_info.set_defaults(func=info_command)

    return parser


def normalize_pack_args(args: argparse.Namespace) -> None:
    # Allows:
    #   python fk_archive.py pack input output.tar.fk
    #   python fk_archive.py pack file1 dir2 file3 output.tar.fk
    if args.command != "pack":
        return
    if len(args.paths) < 2:
        raise FKError("pack requires at least one input path and one output path")

    args.inputs = args.paths[:-1]
    args.output = args.paths[-1]


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    try:
        normalize_pack_args(args)
        return args.func(args)
    except FKError as exc:
        print(f"fk: error: {exc}", file=sys.stderr)
        return 1
    except KeyboardInterrupt:
        print("fk: interrupted", file=sys.stderr)
        return 130


if __name__ == "__main__":
    raise SystemExit(main())
