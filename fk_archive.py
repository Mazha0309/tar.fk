#!/usr/bin/env python3
"""
FK Archive Format v1

FK = FK's Kompressor

A deliberately silly, lossless anti-compression archive format.

Default pipeline:
    input files/directories -> tar stream -> base64 -> duplicate every char -> .tar.fk

File layout:
    [64-byte FK header][payload]

Payload algorithm v1:
    base64(tar_data), then duplicate each Base64 byte:
        b"ABC=" -> b"AABBCC=="

Usage:
    Pack one file or directory:
        python fk_archive.py pack input_path output.tar.fk

    Pack multiple paths:
        python fk_archive.py pack file1 dir2 file3 output.tar.fk

    Unpack:
        python fk_archive.py unpack output.tar.fk extracted_dir

    Show info:
        python fk_archive.py info output.tar.fk
"""

from __future__ import annotations

import argparse
import base64
import io
import struct
import sys
import tarfile
import zlib
from dataclasses import dataclass
from pathlib import Path


MAGIC = b"FKAR\r\n\x1A\n"
HEADER_SIZE = 64
VERSION = 1
ALGORITHM_BASE64_DUP2 = 1

# magic[8], header_size[u16], version[u16], flags[u32], algorithm[u32], reserved[u32],
# original_size[u64], payload_size[u64], crc32_original[u32], crc32_payload[u32], reserved2[16]
HEADER_STRUCT = struct.Struct("<8sHHIIIQQII16s")


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
        if self.version != VERSION:
            raise FKError(f"unsupported FK version: {self.version}")
        if self.algorithm != ALGORITHM_BASE64_DUP2:
            raise FKError(f"unsupported algorithm id: {self.algorithm}")
        if self.reserved != 0:
            raise FKError("reserved field must be 0")
        if self.reserved2 != b"\x00" * 16:
            raise FKError("reserved2 field must be zero-filled")


def crc32_u32(data: bytes) -> int:
    return zlib.crc32(data) & 0xFFFFFFFF


def dup2_encode(data: bytes) -> bytes:
    """Duplicate every byte: b'ABC' -> b'AABBCC'."""
    out = bytearray(len(data) * 2)
    j = 0
    for b in data:
        out[j] = b
        out[j + 1] = b
        j += 2
    return bytes(out)


def dup2_decode(data: bytes) -> bytes:
    """Decode duplicated bytes. Validates every pair."""
    if len(data) % 2 != 0:
        raise FKError("payload length is odd; dup2 payload must have even length")

    out = bytearray(len(data) // 2)
    for i in range(0, len(data), 2):
        a = data[i]
        b = data[i + 1]
        if a != b:
            raise FKError(f"bad duplicated byte pair at payload offset {i}: {a:#04x} != {b:#04x}")
        out[i // 2] = a
    return bytes(out)


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


def fk_encode_tar_bytes(tar_data: bytes) -> bytes:
    b64 = base64.b64encode(tar_data)
    payload = dup2_encode(b64)

    header = FKHeader(
        magic=MAGIC,
        header_size=HEADER_SIZE,
        version=VERSION,
        flags=0,
        algorithm=ALGORITHM_BASE64_DUP2,
        reserved=0,
        original_size=len(tar_data),
        payload_size=len(payload),
        crc32_original=crc32_u32(tar_data),
        crc32_payload=crc32_u32(payload),
        reserved2=b"\x00" * 16,
    )

    return header.pack() + payload


def fk_decode_to_tar_bytes(fk_data: bytes) -> tuple[FKHeader, bytes]:
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

    b64 = dup2_decode(payload)

    try:
        tar_data = base64.b64decode(b64, validate=True)
    except Exception as exc:
        raise FKError(f"invalid base64 payload: {exc}") from exc

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

        tf.extractall(dest_dir, members=members)


def pack_command(args: argparse.Namespace) -> int:
    input_paths = [Path(p) for p in args.inputs]
    output_path = Path(args.output)

    tar_data = make_tar_stream(input_paths)
    fk_data = fk_encode_tar_bytes(tar_data)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_bytes(fk_data)

    ratio = len(fk_data) / len(tar_data) if tar_data else float("inf")
    compression_rate = 1 - ratio

    print(f"created: {output_path}")
    print(f"tar size: {len(tar_data)} bytes")
    print(f"fk size:  {len(fk_data)} bytes")
    print(f"bloat ratio: {ratio:.6f}x")
    print(f"compression rate: {compression_rate * 100:.2f}%")
    return 0


def unpack_command(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)

    fk_data = input_path.read_bytes()
    header, tar_data = fk_decode_to_tar_bytes(fk_data)
    safe_extract_tar(tar_data, output_dir)

    print(f"extracted: {input_path} -> {output_dir}")
    print(f"original tar size: {header.original_size} bytes")
    print(f"payload size:      {header.payload_size} bytes")
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
    print(f"algorithm:        {header.algorithm} = base64 + dup2")
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
    compression_rate = 1 - total_ratio

    print(f"payload bloat:    {payload_ratio:.6f}x")
    print(f"total bloat:      {total_ratio:.6f}x")
    print(f"compression rate: {compression_rate * 100:.2f}%")
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
    p_pack.set_defaults(func=None)

    p_unpack = sub.add_parser("unpack", help="unpack a .tar.fk archive")
    p_unpack.add_argument("input", help="input .tar.fk file")
    p_unpack.add_argument("output_dir", help="output directory")
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
    args.func = pack_command


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
