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

#include <fcntl.h>

#include <cstdint>
#include <cstdio>
#include <iterator>
#include <memory>

#include <sys/mman.h>
#include <sys/stat.h>

#include <android-base/strings.h>
#include <base/files/file_path.h>
#include <gflags/gflags.h>
#include <unistd.h>

#include "update_engine/common/utils.h"
#include "update_engine/common/hash_calculator.h"
#include "update_engine/payload_consumer/file_descriptor.h"
#include "update_engine/payload_consumer/install_operation_executor.h"
#include "update_engine/payload_consumer/payload_metadata.h"
#include "update_engine/update_metadata.pb.h"
#include "xz.h"

DEFINE_string(payload, "", "Path to payload.bin");
DEFINE_string(output_dir, "", "Directory to put output images");
DEFINE_int64(payload_offset,
             0,
             "Offset to start of payload.bin. Useful if payload path actually "
             "points to a .zip file containing payload.bin");
DEFINE_string(partitions,
              "",
              "Comma separated list of partitions to extract, leave empty for "
              "extracting all partitions");

using chromeos_update_engine::DeltaArchiveManifest;
using chromeos_update_engine::PayloadMetadata;

namespace chromeos_update_engine {

bool ExtractImagesFromOTA(const DeltaArchiveManifest& manifest,
                          const PayloadMetadata& metadata,
                          int payload_fd,
                          size_t payload_offset,
                          std::string_view output_dir,
                          const std::set<std::string>& partitions) {
  InstallOperationExecutor executor(manifest.block_size());
  const size_t data_begin = metadata.GetMetadataSize() +
                            metadata.GetMetadataSignatureSize() +
                            payload_offset;
  const base::FilePath path(
      base::StringPiece(output_dir.data(), output_dir.size()));
  std::vector<unsigned char> blob;
  for (const auto& partition : manifest.partitions()) {
    if (!partitions.empty() &&
        partitions.count(partition.partition_name()) == 0) {
      continue;
    }
    LOG(INFO) << "Extracting partition " << partition.partition_name()
              << " size: " << partition.new_partition_info().size();
    const auto output_path =
        path.Append(partition.partition_name() + ".img").value();
    auto fd =
        std::make_shared<chromeos_update_engine::EintrSafeFileDescriptor>();
    TEST_AND_RETURN_FALSE_ERRNO(
        fd->Open(output_path.c_str(), O_RDWR | O_CREAT, 0644));
    for (const auto& op : partition.operations()) {
      blob.resize(op.data_length());
      const auto op_data_offset = data_begin + op.data_offset();
      ssize_t bytes_read = 0;
      TEST_AND_RETURN_FALSE(utils::PReadAll(
          payload_fd, blob.data(), blob.size(), op_data_offset, &bytes_read));
      auto direct_writer = std::make_unique<DirectExtentWriter>(fd);
      TEST_AND_RETURN_FALSE(executor.ExecuteReplaceOperation(
          op, std::move(direct_writer), blob.data(), blob.size()));
    }
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
             HexEncode(partition.new_partition_info().hash()));
  }
  return true;
}

}  // namespace chromeos_update_engine

int main(int argc, char* argv[]) {
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
  return !ExtractImagesFromOTA(manifest,
                               payload_metadata,
                               payload_fd,
                               FLAGS_payload_offset,
                               FLAGS_output_dir,
                               partitions);
}
