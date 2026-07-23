//
// Copyright (C) 2022 The Android Open Source Project
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

#include <algorithm>
#include <array>
#include <atomic>
#include <cstdint>
#include <cstdio>
#include <future>
#include <iterator>
#include <memory>
#include <string>
#include <thread>
#include <vector>

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>

#include <android-base/strings.h>
#include <base/files/file_path.h>
#include <fec/ecc.h>
#include <gflags/gflags.h>
#include <unistd.h>
#include <xz.h>

#include "update_engine/common/utils.h"
#include "update_engine/common/hash_calculator.h"
#include "update_engine/payload_consumer/file_descriptor.h"
#include "update_engine/payload_consumer/file_descriptor_utils.h"
#include "update_engine/payload_consumer/install_operation_executor.h"
#include "update_engine/payload_consumer/payload_metadata.h"
#include "update_engine/payload_consumer/verity_writer_android.h"
#include "update_engine/update_metadata.pb.h"

DEFINE_string(payload, "", "Path to payload.bin");
DEFINE_string(
    input_dir,
    "",
    "Directory to read input images. Only required for incremental OTAs");
DEFINE_string(output_dir, "", "Directory to put output images");
DEFINE_int64(payload_offset,
             0,
             "Offset to start of payload.bin. Useful if payload path actually "
             "points to a .zip file containing payload.bin");
DEFINE_string(partitions,
              "",
              "Comma separated list of partitions to extract, leave empty for "
              "extracting all partitions");
DEFINE_bool(single_thread, false, "Limit extraction to a single thread");
DEFINE_int32(operation_threads,
             0,
             "Number of threads applying the operations of a single "
             "partition, 0 to pick a default");
DEFINE_int32(verity_threads,
             0,
             "Number of threads encoding the verity FEC data of a single "
             "partition, 0 to pick a default");

using chromeos_update_engine::DeltaArchiveManifest;
using chromeos_update_engine::PayloadMetadata;

namespace chromeos_update_engine {

// An operation holds its data blob and, for the lz4diff and zucchini ones, its
// whole source and destination in memory, so the peak footprint of a partition
// grows with the number of threads applying its operations. Several partitions
// are extracted at the same time, keep this well below the core count.
static constexpr int kDefaultOperationThreads = 16;
// A FEC round only needs about a mebibyte of scratch, and encoding one is pure
// computation, so this can afford to go wider than the operations.
static constexpr int kDefaultVerityThreads = 16;

// Number of threads to spread |units| pieces of work of a single partition
// over, |fallback| when the flag leaves the count up to us.
int WorkerThreads(const int requested, const int fallback, const int units) {
  if (FLAGS_single_thread) {
    return 1;
  }
  const int threads =
      requested > 0
          ? requested
          : std::min(fallback,
                     static_cast<int>(std::thread::hardware_concurrency()));
  return std::max(1, std::min(threads, units));
}

// Encodes the verity FEC data of a partition across several threads. The rounds
// are independent and all cost the same, so they are split into one contiguous
// slice per worker. Each worker opens its own descriptor inside
// VerityWriterAndroid::EncodeFEC.
bool EncodeFEC(const std::string& path,
               const InstallPlan::Partition& partition) {
  const uint64_t rs_n = FEC_RSM - partition.fec_roots;
  const uint64_t rounds = utils::DivRoundUp(
      partition.fec_data_size / partition.block_size, rs_n);

  const int threads =
      WorkerThreads(FLAGS_verity_threads, kDefaultVerityThreads, rounds);
  LOG(INFO) << "Encoding " << rounds << " verity FEC rounds of " << path
            << " on " << threads << " threads";

  std::vector<std::future<bool>> futures;
  for (int i = 0; i < threads; i++) {
    const uint64_t round_begin = rounds * i / threads;
    const uint64_t round_end = rounds * (i + 1) / threads;
    futures.push_back(std::async(std::launch::async, [&, round_begin,
                                                      round_end] {
      return VerityWriterAndroid::EncodeFEC(path,
                                            partition.fec_data_offset,
                                            partition.fec_data_size,
                                            partition.fec_offset,
                                            partition.fec_size,
                                            partition.fec_roots,
                                            partition.block_size,
                                            false /* verify_mode */,
                                            round_begin,
                                            round_end);
    }));
  }
  bool ret = true;
  for (auto& future : futures) {
    if (!future.get()) {
      ret = false;
    }
  }
  return ret;
}

void WriteVerity(const PartitionUpdate& partition,
                 FileDescriptorPtr fd,
                 const size_t block_size,
                 const std::string& path) {
  // 512KB buffer, arbitrary value. Larger buffers may improve performance.
  static constexpr size_t BUFFER_SIZE = 1024 * 512;
  if (partition.hash_tree_extent().num_blocks() == 0 &&
      partition.fec_extent().num_blocks() == 0) {
    return;
  }
  InstallPlan::Partition install_part;
  install_part.block_size = block_size;
  CHECK(install_part.ParseVerityConfig(partition));
  // The FEC data is encoded below instead, in parallel. Hide it from the writer
  // so that it only builds the hash tree, which has to be on disk first because
  // the FEC data covers it.
  InstallPlan::Partition hash_tree_part = install_part;
  hash_tree_part.fec_data_size = 0;
  hash_tree_part.fec_size = 0;
  VerityWriterAndroid writer;
  CHECK(writer.Init(hash_tree_part));
  std::array<uint8_t, BUFFER_SIZE> buffer;
  const auto data_size =
      install_part.hash_tree_data_offset + install_part.hash_tree_data_size;
  size_t offset = 0;
  while (offset < data_size) {
    const auto bytes_to_read =
        static_cast<ssize_t>(std::min(BUFFER_SIZE, data_size - offset));
    ssize_t bytes_read;
    CHECK(
        utils::ReadAll(fd, buffer.data(), bytes_to_read, offset, &bytes_read));
    CHECK_EQ(bytes_read, bytes_to_read)
        << " Failed to read at offset " << offset << " "
        << android::base::ErrnoNumberAsString(errno);
    writer.Update(offset, buffer.data(), bytes_read);
    offset += bytes_read;
  }
  CHECK(writer.Finalize(fd.get(), fd.get()));
  CHECK(fd->Flush());
  if (install_part.fec_size != 0) {
    CHECK(EncodeFEC(path, install_part));
  }
  return;
}

// These operations read from the source partition and write to disjoint
// destination extents, so they can be applied in any order. The deprecated
// MOVE and BSDIFF operations read back from the partition being written
// instead, and are deliberately left out, together with any operation added
// after this was written.
bool CanApplyOperationInParallel(const InstallOperation& op) {
  switch (op.type()) {
    case InstallOperation::REPLACE:
    case InstallOperation::REPLACE_BZ:
    case InstallOperation::REPLACE_XZ:
    case InstallOperation::ZERO:
    case InstallOperation::DISCARD:
    case InstallOperation::SOURCE_COPY:
    case InstallOperation::SOURCE_BSDIFF:
    case InstallOperation::BROTLI_BSDIFF:
    case InstallOperation::PUFFDIFF:
    case InstallOperation::ZUCCHINI:
    case InstallOperation::LZ4DIFF_BSDIFF:
    case InstallOperation::LZ4DIFF_PUFFDIFF:
      return true;
    default:
      return false;
  }
}

bool CanApplyOperationsInParallel(const PartitionUpdate& partition) {
  for (const auto& op : partition.operations()) {
    if (!CanApplyOperationInParallel(op)) {
      return false;
    }
  }
  return true;
}

// Applies the operations of |partition| pulled from |next_op| until they run
// out. Every worker opens its own descriptors, reading and writing seeks them,
// and keeps its own scratch buffer. The payload is read positionally, so its
// descriptor is shared.
bool ApplyOperations(const DeltaArchiveManifest& manifest,
                     const PartitionUpdate& partition,
                     const size_t data_begin,
                     int payload_fd,
                     const std::string& input_path,
                     const std::string& output_path,
                     std::atomic<int>* next_op) {
  InstallOperationExecutor executor(manifest.block_size());
  std::vector<unsigned char> blob;

  auto out_fd =
      std::make_shared<chromeos_update_engine::EintrSafeFileDescriptor>();
  TEST_AND_RETURN_FALSE_ERRNO(
      out_fd->Open(output_path.c_str(), O_RDWR | O_CREAT, 0644));
  auto in_fd =
      std::make_shared<chromeos_update_engine::EintrSafeFileDescriptor>();
  if (!input_path.empty()) {
    CHECK(in_fd->Open(input_path.c_str(), O_RDONLY))
        << " failed to open " << input_path;
  }

  int index;
  while ((index = next_op->fetch_add(1)) < partition.operations_size()) {
    const auto& op = partition.operations(index);
    if (op.has_src_sha256_hash()) {
      brillo::Blob actual_hash;
      TEST_AND_RETURN_FALSE(fd_utils::ReadAndHashExtents(
          in_fd, op.src_extents(), manifest.block_size(), &actual_hash));
      CHECK_EQ(HexEncode(ToStringView(actual_hash)),
               HexEncode(op.src_sha256_hash()))
          << ", failed partition: " << partition.partition_name();
    }

    blob.resize(op.data_length());
    const auto op_data_offset = data_begin + op.data_offset();
    ssize_t bytes_read = 0;
    TEST_AND_RETURN_FALSE(utils::PReadAll(
        payload_fd, blob.data(), blob.size(), op_data_offset, &bytes_read));
    if (op.has_data_sha256_hash()) {
      brillo::Blob actual_hash;
      TEST_AND_RETURN_FALSE(HashCalculator::RawHashOfData(blob, &actual_hash));
      CHECK_EQ(HexEncode(ToStringView(actual_hash)),
               HexEncode(op.data_sha256_hash()))
          << ", failed partition: " << partition.partition_name();
    }
    auto direct_writer = std::make_unique<DirectExtentWriter>(out_fd);
    if (op.type() == InstallOperation::ZERO) {
      TEST_AND_RETURN_FALSE(
          executor.ExecuteZeroOrDiscardOperation(op, std::move(direct_writer)));
    } else if (op.type() == InstallOperation::REPLACE ||
               op.type() == InstallOperation::REPLACE_BZ ||
               op.type() == InstallOperation::REPLACE_XZ) {
      TEST_AND_RETURN_FALSE(executor.ExecuteReplaceOperation(
          op, std::move(direct_writer), blob.data()));
    } else if (op.type() == InstallOperation::SOURCE_COPY) {
      CHECK(in_fd->IsOpen())
          << ", failed partition: " << partition.partition_name();
      TEST_AND_RETURN_FALSE(executor.ExecuteSourceCopyOperation(
          op, std::move(direct_writer), in_fd));
    } else {
      CHECK(in_fd->IsOpen())
          << ", failed partition: " << partition.partition_name();
      TEST_AND_RETURN_FALSE(executor.ExecuteDiffOperation(
          op, std::move(direct_writer), in_fd, blob.data(), blob.size()));
    }
  }
  return true;
}

bool ExtractImageFromPartition(const DeltaArchiveManifest& manifest,
                               const PartitionUpdate& partition,
                               const size_t data_begin,
                               int payload_fd,
                               std::string_view input_dir,
                               std::string_view output_dir) {
  const base::FilePath output_dir_path(
      base::StringPiece(output_dir.data(), output_dir.size()));
  const base::FilePath input_dir_path(
      base::StringPiece(input_dir.data(), input_dir.size()));

  LOG(INFO) << "Extracting partition " << partition.partition_name()
            << " size: " << partition.new_partition_info().size();
  const auto output_path =
      output_dir_path.Append(partition.partition_name() + ".img").value();
  std::string input_path;
  if (partition.has_old_partition_info()) {
    input_path = input_dir_path.Append(partition.partition_name() + ".img")
                     .value();
    LOG(INFO) << "Incremental OTA detected for partition "
              << partition.partition_name() << " opening source image "
              << input_path;
  }

  auto out_fd =
      std::make_shared<chromeos_update_engine::EintrSafeFileDescriptor>();
  TEST_AND_RETURN_FALSE_ERRNO(
      out_fd->Open(output_path.c_str(), O_RDWR | O_CREAT, 0644));

  const int threads = CanApplyOperationsInParallel(partition)
                          ? WorkerThreads(FLAGS_operation_threads,
                                          kDefaultOperationThreads,
                                          partition.operations_size())
                          : 1;

  std::atomic<int> next_op(0);
  if (threads == 1) {
    TEST_AND_RETURN_FALSE(ApplyOperations(manifest,
                                          partition,
                                          data_begin,
                                          payload_fd,
                                          input_path,
                                          output_path,
                                          &next_op));
  } else {
    LOG(INFO) << "Applying " << partition.operations_size()
              << " operations of " << partition.partition_name() << " on "
              << threads << " threads";
    std::vector<std::future<bool>> futures;
    for (int i = 0; i < threads; i++) {
      futures.push_back(std::async(std::launch::async,
                                   ApplyOperations,
                                   std::cref(manifest),
                                   std::cref(partition),
                                   data_begin,
                                   payload_fd,
                                   std::cref(input_path),
                                   std::cref(output_path),
                                   &next_op));
    }
    bool ret = true;
    for (auto& future : futures) {
      if (!future.get()) {
        ret = false;
      }
    }
    TEST_AND_RETURN_FALSE(ret);
  }

  WriteVerity(partition, out_fd, manifest.block_size(), output_path);
  int err =
      truncate64(output_path.c_str(), partition.new_partition_info().size());
  if (err) {
    PLOG(ERROR) << "Failed to truncate " << output_path << " to "
                << partition.new_partition_info().size();
  }
  brillo::Blob actual_hash;
  TEST_AND_RETURN_FALSE(
      HashCalculator::RawHashOfFile(output_path, &actual_hash));
  CHECK_EQ(HexEncode(ToStringView(actual_hash)),
           HexEncode(partition.new_partition_info().hash()))
      << " Partition " << partition.partition_name()
      << " hash mismatches. Either the source image or OTA package is "
         "corrupted.";

  LOG(INFO) << "Extracted partition " << partition.partition_name();

  return true;
}

bool ExtractImagesFromOTA(const DeltaArchiveManifest& manifest,
                          const PayloadMetadata& metadata,
                          int payload_fd,
                          size_t payload_offset,
                          std::string_view input_dir,
                          std::string_view output_dir,
                          const std::set<std::string>& partitions) {
  const size_t data_begin = metadata.GetMetadataSize() +
                            metadata.GetMetadataSignatureSize() +
                            payload_offset;
  bool ret = true;

  if (FLAGS_single_thread) {
    for (const auto& partition : manifest.partitions()) {
      if (!partitions.empty() &&
          partitions.count(partition.partition_name()) == 0) {
        continue;
      }
      if (!ExtractImageFromPartition(manifest,
                                     partition,
                                     data_begin,
                                     payload_fd,
                                     input_dir,
                                     output_dir)) {
        ret = false;
        LOG(ERROR) << "Extraction of partition " << partition.partition_name()
                   << " failed";
        break;
      }
    }
  } else {
    std::vector<std::pair<std::future<bool>, std::string>> futures;
    for (const auto& partition : manifest.partitions()) {
      if (!partitions.empty() &&
          partitions.count(partition.partition_name()) == 0) {
        continue;
      }
      futures.push_back(std::make_pair(std::async(std::launch::async,
                                                  ExtractImageFromPartition,
                                                  manifest,
                                                  partition,
                                                  data_begin,
                                                  payload_fd,
                                                  input_dir,
                                                  output_dir),
                                       partition.partition_name()));
    }
    for (auto& future : futures) {
      if (!future.first.get()) {
        ret = false;
        LOG(ERROR) << "Extraction of partition " << future.second << " failed";
      }
    }
  }
  return ret;
}

}  // namespace chromeos_update_engine

namespace {

bool IsIncrementalOTA(const DeltaArchiveManifest& manifest) {
  for (const auto& part : manifest.partitions()) {
    if (part.has_old_partition_info()) {
      return true;
    }
  }
  return false;
}

}  // namespace

int main(int argc, char* argv[]) {
  gflags::SetUsageMessage(
      "A tool to extract device images from Android OTA packages");
  gflags::ParseCommandLineFlags(&argc, &argv, true);
  xz_crc32_init();
  auto tokens = android::base::Tokenize(FLAGS_partitions, ",");
  const std::set<std::string> partitions(
      std::make_move_iterator(tokens.begin()),
      std::make_move_iterator(tokens.end()));
  if (FLAGS_payload.empty()) {
    LOG(ERROR) << "--payload <payload path> is required";
    return 1;
  }
  if (!partitions.empty()) {
    LOG(INFO) << "Extracting " << android::base::Join(partitions, ", ");
  }
  int payload_fd = open(FLAGS_payload.c_str(), O_RDONLY | O_CLOEXEC);
  if (payload_fd < 0) {
    PLOG(ERROR) << "Failed to open payload file";
    return 1;
  }
  chromeos_update_engine::ScopedFdCloser closer{&payload_fd};
  auto payload_size = chromeos_update_engine::utils::FileSize(payload_fd);
  if (payload_size <= 0) {
    PLOG(ERROR)
        << "Couldn't determine size of payload file, or payload file is empty";
    return 1;
  }

  PayloadMetadata payload_metadata;
  auto payload = static_cast<unsigned char*>(
      mmap(nullptr, payload_size, PROT_READ, MAP_PRIVATE, payload_fd, 0));

  if (payload == MAP_FAILED) {
    PLOG(ERROR) << "Failed to mmap() payload file";
    return 1;
  }

  auto munmap_deleter = [payload_size](auto payload) {
    munmap(payload, payload_size);
  };
  std::unique_ptr<unsigned char, decltype(munmap_deleter)> munmapper{
      payload, munmap_deleter};
  if (payload_metadata.ParsePayloadHeader(payload + FLAGS_payload_offset,
                                          payload_size - FLAGS_payload_offset,
                                          nullptr) !=
      chromeos_update_engine::MetadataParseResult::kSuccess) {
    LOG(ERROR) << "Payload header parse failed!";
    return 1;
  }
  DeltaArchiveManifest manifest;
  if (!payload_metadata.GetManifest(payload + FLAGS_payload_offset,
                                    payload_size - FLAGS_payload_offset,
                                    &manifest)) {
    LOG(ERROR) << "Failed to parse manifest!";
    return 1;
  }
  if (IsIncrementalOTA(manifest) && FLAGS_input_dir.empty()) {
    LOG(ERROR) << FLAGS_payload
               << " is an incremental OTA, --input_dir parameter is required.";
    return 1;
  }
  return !ExtractImagesFromOTA(manifest,
                               payload_metadata,
                               payload_fd,
                               FLAGS_payload_offset,
                               FLAGS_input_dir,
                               FLAGS_output_dir,
                               partitions);
}
