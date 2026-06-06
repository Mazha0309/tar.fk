# FK Archive Format / FK 归档格式

[English](#english) | [中文](#中文)

---

<a name="english"></a>
## English

FK = FK's Kompressor

A deliberately silly, lossless **anti-compression** archive format. It takes your data and makes it bigger — on purpose.

### Table of Contents

- [Features](#features)
- [Algorithms](#algorithms)
- [Installation](#installation)
- [Usage](#usage)
  - [Pack](#pack)
  - [Unpack](#unpack)
  - [Info](#info)
- [File Format](#file-format)
  - [Header Structure](#header-structure)
- [License](#license)

### Features

- **Lossless** — every bit is preserved
- **Anti-compression** — files get significantly larger
- **Multiple algorithms** — choose your level of bloat
- **Encryption** — AES-256-GCM password protection (can be combined with any algorithm)
- **Safe extraction** — path traversal and symlink protection
- **Versioned format** — backward compatible with v1 archives

### Algorithms

| Algorithm | ID | Expansion | Description |
|-----------|-----|-----------|-------------|
| `dup2` | 1 | ~167% | base64 + duplicate every byte 2x |
| `dup3` | 2 | ~300% | base64 + duplicate every byte 3x |
| `bitexpand` | 3 | ~967% | expand each byte to 8 ASCII bits + base64 |
| `nested` | 4 | ~967% | base64 → hex → dup3 → base64 (default) |
| `rs` | 5 | ~100% | Reed-Solomon redundancy codes |

### Installation

Requires Python 3.9+.

```bash
# Optional: for encryption support
pip install cryptography
```

### Usage

#### Pack

```bash
# Default (nested algorithm)
python fk_archive.py pack input.txt output.tar.fk

# Multiple files/directories
python fk_archive.py pack file1 dir2 file3 output.tar.fk

# Choose algorithm
python fk_archive.py pack --algorithm dup3 input.txt output.tar.fk
python fk_archive.py pack --algorithm bitexpand input.txt output.tar.fk

# Encrypt (can be combined with any algorithm)
python fk_archive.py pack --encrypt --password secret input.txt output.tar.fk
python fk_archive.py pack --algorithm dup3 --encrypt --password secret input.txt output.tar.fk
```

#### Unpack

```bash
python fk_archive.py unpack output.tar.fk extracted_dir

# Encrypted archive
python fk_archive.py unpack --password secret output.tar.fk extracted_dir
```

#### Info

```bash
python fk_archive.py info output.tar.fk
```

### File Format

```
[64-byte FK header][payload]
```

#### Header Structure (64 bytes)

| Field | Size | Description |
|-------|------|-------------|
| magic | 8 | `FKAR\r\n\x1A\n` |
| header_size | 2 | 64 |
| version | 2 | format version (1 or 2) |
| flags | 4 | bit 0 = encrypted |
| algorithm | 4 | algorithm ID |
| reserved | 4 | must be 0 |
| original_size | 8 | original tar size |
| payload_size | 8 | payload size |
| crc32_original | 4 | CRC32 of original data |
| crc32_payload | 4 | CRC32 of payload |
| reserved2 | 16 | must be zero |

### License

This program is free software: you can redistribute it and/or modify it under the terms of the GNU Affero General Public License as published by the Free Software Foundation, either version 3 of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful, but WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU Affero General Public License for more details.

You should have received a copy of the GNU Affero General Public License along with this program. If not, see <https://www.gnu.org/licenses/>.

---

<a name="中文"></a>
## 中文

FK = FK's Kompressor

一个故意设计得有点傻的**无损反压缩**归档格式。它会将你的数据变得更大——而且是故意的。

### 目录

- [特性](#特性)
- [算法](#算法-1)
- [安装](#安装)
- [使用方法](#使用方法)
  - [打包](#打包)
  - [解压](#解压)
  - [查看信息](#查看信息)
- [文件格式](#文件格式)
  - [头部结构](#头部结构)
- [许可证](#许可证-1)

### 特性

- **无损** — 每一位数据都完整保留
- **反压缩** — 文件会显著变大
- **多种算法** — 选择你想要的膨胀程度
- **加密** — AES-256-GCM 密码保护（可与任何算法组合使用）
- **安全解压** — 防止路径遍历和符号链接攻击
- **版本化格式** — 向后兼容 v1 归档

### 算法

| 算法 | ID | 膨胀率 | 说明 |
|-----------|-----|-----------|-------------|
| `dup2` | 1 | ~167% | base64 + 每个字节复制 2 次 |
| `dup3` | 2 | ~300% | base64 + 每个字节复制 3 次 |
| `bitexpand` | 3 | ~967% | 每个字节展开为 8 个 ASCII 位 + base64 |
| `nested` | 4 | ~967% | base64 → hex → dup3 → base64（默认） |
| `rs` | 5 | ~100% | Reed-Solomon 冗余纠错码 |

### 安装

需要 Python 3.9+。

```bash
# 可选：如需使用加密功能
pip install cryptography
```

### 使用方法

#### 打包

```bash
# 默认算法（nested）
python fk_archive.py pack input.txt output.tar.fk

# 多个文件/目录
python fk_archive.py pack file1 dir2 file3 output.tar.fk

# 选择算法
python fk_archive.py pack --algorithm dup3 input.txt output.tar.fk
python fk_archive.py pack --algorithm bitexpand input.txt output.tar.fk

# 加密（可与任何算法组合）
python fk_archive.py pack --encrypt --password secret input.txt output.tar.fk
python fk_archive.py pack --algorithm dup3 --encrypt --password secret input.txt output.tar.fk
```

#### 解压

```bash
python fk_archive.py unpack output.tar.fk extracted_dir

# 加密归档
python fk_archive.py unpack --password secret output.tar.fk extracted_dir
```

#### 查看信息

```bash
python fk_archive.py info output.tar.fk
```

### 文件格式

```
[64 字节 FK 头部][载荷]
```

#### 头部结构（64 字节）

| 字段 | 大小 | 说明 |
|-------|------|-------------|
| magic | 8 | `FKAR\r\n\x1A\n` |
| header_size | 2 | 64 |
| version | 2 | 格式版本（1 或 2） |
| flags | 4 | bit 0 = 加密 |
| algorithm | 4 | 算法 ID |
| reserved | 4 | 必须为 0 |
| original_size | 8 | 原始 tar 大小 |
| payload_size | 8 | 载荷大小 |
| crc32_original | 4 | 原始数据 CRC32 |
| crc32_payload | 4 | 载荷 CRC32 |
| reserved2 | 16 | 必须为零 |

### 许可证

本程序是自由软件：你可以在 GNU Affero 通用公共许可证（由自由软件基金会发布，第 3 版或任何后续版本）的条款下重新分发和/或修改它。

本程序分发时希望它有用，但**不提供任何担保**；甚至没有对适销性或特定用途适用性的默示担保。详情请参阅 GNU Affero 通用公共许可证。

你应该已经随本程序收到了一份 GNU Affero 通用公共许可证的副本。如果没有，请参阅 <https://www.gnu.org/licenses/>。
