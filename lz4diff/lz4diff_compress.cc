//
// Copyright (C) 2021 The Android Open Source Project
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

#include "lz4diff_compress.h"

#include "update_engine/common/utils.h"
#include "update_engine/common/hash_calculator.h"
#include "update_engine/payload_generator/delta_diff_generator.h"
#include "update_engine/payload_generator/payload_generation_config.h"

#include <base/logging.h>
#include <lz4.h>
#include <lz4hc.h>

namespace chromeos_update_engine {

Blob TryCompressBlob(std::string_view blob,
                     const std::vector<CompressedBlock>& block_info,
                     const bool zero_padding_enabled,
                     const CompressionAlgorithm compression_algo) {
  size_t uncompressed_size = 0;
  size_t compressed_size = 0;
  for (const auto& block : block_info) {
    CHECK_EQ(uncompressed_size, block.uncompressed_offset)
        << "Compressed block info is expected to be sorted.";
    uncompressed_size += block.uncompressed_length;
    compressed_size += block.compressed_length;
  }
  CHECK_EQ(uncompressed_size, blob.size());
  Blob output(utils::RoundUp(compressed_size, kBlockSize));
  auto hc = LZ4_createStreamHC();
  DEFER {
    if (hc) {
      LZ4_freeStreamHC(hc);
      hc = nullptr;
    }
  };
  size_t compressed_offset = 0;
  for (const auto& block : block_info) {
    // Execute the increment at end of each loop
    DEFER { compressed_offset += block.compressed_length; };
    CHECK_LE(compressed_offset + block.compressed_length, output.size());

    if (!block.IsCompressed()) {
      std::memcpy(output.data() + compressed_offset,
                  blob.data() + block.uncompressed_offset,
                  block.compressed_length);
      continue;
    }
    // LZ4 spec enforces that last op of a compressed block must be an insert op
    // of at least 5 bytes. Compressors will try to conform to that requirement
    // if the input size is just right. We don't want that. So always give a
    // little bit more data.
    int src_size = uncompressed_size - block.uncompressed_offset;
    uint64_t bytes_written = 0;
    switch (compression_algo.type()) {
      case CompressionAlgorithm::LZ4HC:
        bytes_written = LZ4_compress_HC_destSize(
            hc,
            blob.data() + block.uncompressed_offset,
            reinterpret_cast<char*>(output.data()) + compressed_offset,
            &src_size,
            block.compressed_length,
            compression_algo.level());
        break;
      case CompressionAlgorithm::LZ4:
        bytes_written = LZ4_compress_destSize(
            blob.data() + block.uncompressed_offset,
            reinterpret_cast<char*>(output.data()) + compressed_offset,
            &src_size,
            block.compressed_length);
        break;
      default:
        CHECK(false) << "Unrecognized compression algorithm: "
                     << compression_algo.type();
        break;
    }
    // Last block may have trailing zeros
    CHECK_LE(bytes_written, block.compressed_length);
    if (bytes_written < block.compressed_length) {
      if (zero_padding_enabled) {
        const auto padding = block.compressed_length - bytes_written;
        // LOG(INFO) << "Padding: " << padding;
        CHECK_LE(compressed_offset + padding + bytes_written, output.size());
        std::memmove(output.data() + compressed_offset + padding,
                     output.data() + compressed_offset,
                     bytes_written);
        CHECK_LE(compressed_offset + padding, output.size());
        std::fill(output.data() + compressed_offset,
                  output.data() + compressed_offset + padding,
                  0);

      } else {
        std::fill(output.data() + compressed_offset + bytes_written,
                  output.data() + compressed_offset + block.compressed_length,
                  0);
      }
    }
  }
  // Any trailing data will be copied to the output buffer.
  output.insert(output.end(), blob.begin() + uncompressed_size, blob.end());
  return output;
}

Blob TryDecompressBlob(std::string_view blob,
                       const std::vector<CompressedBlock>& block_info,
                       const bool zero_padding_enabled) {
  if (block_info.empty()) {
    return {};
  }
  size_t uncompressed_size = 0;
  size_t compressed_size = 0;
  for (const auto& block : block_info) {
    CHECK_EQ(uncompressed_size, block.uncompressed_offset)
        << " Compressed block info is expected to be sorted, expected offset "
        << uncompressed_size << ", actual block " << block;
    uncompressed_size += block.uncompressed_length;
    compressed_size += block.compressed_length;
  }
  if (blob.size() < compressed_size) {
    LOG(INFO) << "File is chunked. Skip lz4 decompress.Expected size : "
              << compressed_size << ", actual size: " << blob.size();
    return {};
  }
  Blob output;
  output.reserve(uncompressed_size);
  size_t compressed_offset = 0;
  for (const auto& block : block_info) {
    std::string_view cluster =
        blob.substr(compressed_offset, block.compressed_length);
    if (!block.IsCompressed()) {
      CHECK_NE(cluster.size(), 0UL);
      output.insert(output.end(), cluster.begin(), cluster.end());
      compressed_offset += cluster.size();
      continue;
    }
    size_t inputmargin = 0;
    if (zero_padding_enabled) {
      while (inputmargin < std::min(kBlockSize, cluster.size()) &&
             cluster[inputmargin] == 0) {
        inputmargin++;
      }
    }
    output.resize(output.size() + block.uncompressed_length);

    const auto bytes_decompressed = LZ4_decompress_safe_partial(
        cluster.data() + inputmargin,
        reinterpret_cast<char*>(output.data()) + output.size() -
            block.uncompressed_length,
        cluster.size() - inputmargin,
        block.uncompressed_length,
        block.uncompressed_length);
    if (bytes_decompressed < 0) {
      Blob cluster_hash;
      HashCalculator::RawHashOfBytes(
          cluster.data(), cluster.size(), &cluster_hash);
      Blob blob_hash;
      HashCalculator::RawHashOfBytes(blob.data(), blob.size(), &blob_hash);
      LOG(FATAL) << "Failed to decompress, " << bytes_decompressed
                 << ", output_cursor = "
                 << output.size() - block.uncompressed_length
                 << ", input_cursor = " << compressed_offset
                 << ", blob.size() = " << blob.size()
                 << ", cluster_size = " << block.compressed_length
                 << ", dest capacity = " << block.uncompressed_length
                 << ", input margin = " << inputmargin << " "
                 << HexEncode(cluster_hash) << " " << HexEncode(blob_hash);
      return {};
    }
    compressed_offset += block.compressed_length;
    CHECK_EQ(static_cast<uint64_t>(bytes_decompressed),
             block.uncompressed_length);
  }
  CHECK_EQ(output.size(), uncompressed_size);

  // Trailing data not recorded by compressed block info will be treated as
  // uncompressed, most of the time these are xattrs or trailing zeros.
  CHECK_EQ(blob.size(), compressed_offset)
      << " Unexpected data the end of compressed data ";
  if (compressed_offset < blob.size()) {
    output.insert(output.end(), blob.begin() + compressed_offset, blob.end());
  }

  return output;
}

[[nodiscard]] std::string_view ToStringView(const Blob& blob) noexcept {
  return std::string_view{reinterpret_cast<const char*>(blob.data()),
                          blob.size()};
}

Blob TryDecompressBlob(const Blob& blob,
                       const std::vector<CompressedBlock>& block_info,
                       const bool zero_padding_enabled) {
  return TryDecompressBlob(
      ToStringView(blob), block_info, zero_padding_enabled);
}

std::ostream& operator<<(std::ostream& out, const CompressedBlock& block) {
  out << "CompressedBlock{.uncompressed_offset = " << block.uncompressed_offset
      << ", .compressed_length = " << block.compressed_length
      << ", .uncompressed_length = " << block.uncompressed_length << "}";
  return out;
}

[[nodiscard]] std::string_view ToStringView(const void* data,
                                            size_t size) noexcept {
  return std::string_view(reinterpret_cast<const char*>(data), size);
}

std::ostream& operator<<(std::ostream& out, const CompressedBlockInfo& info) {
  out << "BlockInfo { compressed_length: " << info.compressed_length()
      << ", uncompressed_length: " << info.uncompressed_length()
      << ", uncompressed_offset: " << info.uncompressed_offset();
  if (!info.sha256_hash().empty()) {
    out << ", sha256_hash: " << HexEncode(info.sha256_hash());
  }
  if (!info.postfix_bspatch().empty()) {
    out << ", postfix_bspatch: " << info.postfix_bspatch().size();
  }
  out << "}";
  return out;
}

}  // namespace chromeos_update_engine
