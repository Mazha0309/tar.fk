# FK Archive Format

FK = FK's Kompressor

A deliberately silly, lossless **anti-compression** archive format. It takes your data and makes it bigger — on purpose.

## Features

- **Lossless** — every bit is preserved
- **Anti-compression** — files get significantly larger
- **Multiple algorithms** — choose your level of bloat
- **Encryption** — AES-256-GCM password protection
- **Safe extraction** — path traversal and symlink protection
- **Versioned format** — backward compatible with v1 archives

## Algorithms

| Algorithm | ID | Expansion | Description |
|-----------|-----|-----------|-------------|
| `dup2` | 1 | ~167% | base64 + duplicate every byte 2x |
| `dup3` | 2 | ~300% | base64 + duplicate every byte 3x |
| `encrypted` | 3 | ~168% | AES-256-GCM + base64 + dup2 |
| `bitexpand` | 4 | ~967% | expand each byte to 8 ASCII bits + base64 |
| `nested` | 5 | ~967% | base64 → hex → dup3 → base64 (default) |
| `rs` | 6 | ~100% | Reed-Solomon redundancy codes |

## Installation

Requires Python 3.9+.

```bash
# Optional: for encrypted algorithm support
pip install cryptography
```

## Usage

### Pack

```bash
# Default (nested algorithm)
python fk_archive.py pack input.txt output.tar.fk

# Multiple files/directories
python fk_archive.py pack file1 dir2 file3 output.tar.fk

# Choose algorithm
python fk_archive.py pack --algorithm dup3 input.txt output.tar.fk
python fk_archive.py pack --algorithm bitexpand input.txt output.tar.fk

# Encrypted
python fk_archive.py pack --algorithm encrypted --password secret input.txt output.tar.fk
```

### Unpack

```bash
python fk_archive.py unpack output.tar.fk extracted_dir

# Encrypted archive
python fk_archive.py unpack --password secret output.tar.fk extracted_dir
```

### Info

```bash
python fk_archive.py info output.tar.fk
```

## File Format

```
[64-byte FK header][payload]
```

### Header Structure (64 bytes)

| Field | Size | Description |
|-------|------|-------------|
| magic | 8 | `FKAR\r\n\x1A\n` |
| header_size | 2 | 64 |
| version | 2 | format version (1 or 2) |
| flags | 4 | reserved |
| algorithm | 4 | algorithm ID |
| reserved | 4 | must be 0 |
| original_size | 8 | original tar size |
| payload_size | 8 | payload size |
| crc32_original | 4 | CRC32 of original data |
| crc32_payload | 4 | CRC32 of payload |
| reserved2 | 16 | must be zero |

## License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.
