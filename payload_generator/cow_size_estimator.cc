//
// Copyright (C) 2020 The Android Open Source Project
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

#include "update_engine/payload_generator/cow_size_estimator.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include <android-base/unique_fd.h>
#include <libsnapshot/cow_writer.h>
#include <libsnapshot/cow_format.h>

#include "update_engine/payload_consumer/block_extent_writer.h"
#include "update_engine/payload_consumer/snapshot_extent_writer.h"
#include "update_engine/payload_consumer/xor_extent_writer.h"
#include "update_engine/common/utils.h"
#include "update_engine/payload_consumer/vabc_partition_writer.h"
#include "update_engine/payload_generator/extent_ranges.h"
#include "update_engine/payload_generator/extent_utils.h"
#include "update_engine/update_metadata.pb.h"

namespace chromeos_update_engine {
using android::snapshot::CreateCowEstimator;
using android::snapshot::ICowWriter;
// Compute XOR map, a map from dst extent to corresponding merge operation
static ExtentMap<const CowMergeOperation*, ExtentLess> ComputeXorMap(
    const google::protobuf::RepeatedPtrField<CowMergeOperation>& merge_ops) {
  ExtentMap<const CowMergeOperation*, ExtentLess> xor_map;
  for (const auto& merge_op : merge_ops) {
    if (merge_op.type() == CowMergeOperation::COW_XOR) {
      xor_map.AddExtent(merge_op.dst_extent(), &merge_op);
    }
  }
  return xor_map;
}

bool CowDryRun(
    FileDescriptorPtr source_fd,
    FileDescriptorPtr target_fd,
    const google::protobuf::RepeatedPtrField<InstallOperation>& operations,
    const google::protobuf::RepeatedPtrField<CowMergeOperation>&
        merge_operations,
    const size_t block_size,
    android::snapshot::ICowWriter* cow_writer,
    const size_t new_partition_size,
    const size_t old_partition_size,
    const bool xor_enabled) {
  CHECK_NE(target_fd, nullptr);
  CHECK(target_fd->IsOpen());
  VABCPartitionWriter::WriteMergeSequence(merge_operations, cow_writer);
  ExtentRanges visited;
  SnapshotExtentWriter extent_writer(cow_writer);
  ExtentMap<const CowMergeOperation*, ExtentLess> xor_map =
      ComputeXorMap(merge_operations);
  ExtentRanges copy_blocks;
  for (const auto& cow_op : merge_operations) {
    if (cow_op.type() != CowMergeOperation::COW_COPY) {
      continue;
    }
    copy_blocks.AddExtent(cow_op.dst_extent());
  }
  for (const auto& op : operations) {
    switch (op.type()) {
      case InstallOperation::SOURCE_BSDIFF:
      case InstallOperation::BROTLI_BSDIFF:
      case InstallOperation::PUFFDIFF:
      case InstallOperation::ZUCCHINI:
      case InstallOperation::LZ4DIFF_PUFFDIFF:
      case InstallOperation::LZ4DIFF_BSDIFF: {
        if (xor_enabled) {
          std::unique_ptr<XORExtentWriter> writer =
              std::make_unique<XORExtentWriter>(
                  op, source_fd, cow_writer, xor_map, old_partition_size);
          TEST_AND_RETURN_FALSE(writer->Init(op.dst_extents(), block_size));
          for (const auto& ext : op.dst_extents()) {
            visited.AddExtent(ext);
            ssize_t bytes_read = 0;
            std::vector<unsigned char> new_data(ext.num_blocks() * block_size);
            if (!utils::PReadAll(target_fd,
                                 new_data.data(),
                                 new_data.size(),
                                 ext.start_block() * block_size,
                                 &bytes_read)) {
              PLOG(ERROR) << "Failed to read target data at " << ext;
              return false;
            }
            writer->Write(new_data.data(), ext.num_blocks() * block_size);
          }
          cow_writer->AddLabel(0);
          break;
        }
        [[fallthrough]];
      }
      case InstallOperation::REPLACE:
      case InstallOperation::REPLACE_BZ:
      case InstallOperation::REPLACE_XZ: {
        TEST_AND_RETURN_FALSE(extent_writer.Init(op.dst_extents(), block_size));
        for (const auto& ext : op.dst_extents()) {
          visited.AddExtent(ext);
          std::vector<unsigned char> data(ext.num_blocks() * block_size);
          ssize_t bytes_read = 0;
          if (!utils::PReadAll(target_fd,
                               data.data(),
                               data.size(),
                               ext.start_block() * block_size,
                               &bytes_read)) {
            PLOG(ERROR) << "Failed to read new block data at " << ext;
            return false;
          }
          extent_writer.Write(data.data(), data.size());
        }
        cow_writer->AddLabel(0);
        break;
      }
      case InstallOperation::ZERO:
      case InstallOperation::DISCARD: {
        for (const auto& ext : op.dst_extents()) {
          visited.AddExtent(ext);
          cow_writer->AddZeroBlocks(ext.start_block(), ext.num_blocks());
        }
        cow_writer->AddLabel(0);
        break;
      }
      case InstallOperation::SOURCE_COPY: {
        for (const auto& ext : op.dst_extents()) {
          visited.AddExtent(ext);
        }
        if (!VABCPartitionWriter::ProcessSourceCopyOperation(
                op, block_size, copy_blocks, source_fd, cow_writer, true)) {
          LOG(ERROR) << "Failed to process source copy operation: " << op.type()
                     << "\nsource extents: " << op.src_extents()
                     << "\ndestination extents: " << op.dst_extents();
          return false;
        }
        break;
      }
      default:
        LOG(ERROR) << "unknown op: " << op.type();
    }
  }

  const size_t last_block = new_partition_size / block_size;
  const auto unvisited_extents =
      FilterExtentRanges({ExtentForRange(0, last_block)}, visited);
  for (const auto& ext : unvisited_extents) {
    std::vector<unsigned char> data(ext.num_blocks() * block_size);
    ssize_t bytes_read = 0;
    if (!utils::PReadAll(target_fd,
                         data.data(),
                         data.size(),
                         ext.start_block() * block_size,
                         &bytes_read)) {
      PLOG(ERROR) << "Failed to read new block data at " << ext;
      return false;
    }
    auto to_write = data.size();
    // FEC data written on device is chunked to 1mb. We want to mirror that here
    while (to_write) {
      auto curr_write = std::min(block_size, to_write);
      cow_writer->AddRawBlocks(
          ext.start_block() + ((data.size() - to_write) / block_size),
          data.data() + (data.size() - to_write),
          curr_write);
      to_write -= curr_write;
    }
    CHECK_EQ(to_write, 0ULL);
    cow_writer->AddLabel(0);
  }

  TEST_AND_RETURN_FALSE(cow_writer->Finalize());

  return true;
}

android::snapshot::CowSizeInfo EstimateCowSizeInfo(
    FileDescriptorPtr source_fd,
    FileDescriptorPtr target_fd,
    const google::protobuf::RepeatedPtrField<InstallOperation>& operations,
    const google::protobuf::RepeatedPtrField<CowMergeOperation>&
        merge_operations,
    const size_t block_size,
    std::string compression,
    const size_t new_partition_size,
    const size_t old_partition_size,
    const bool xor_enabled,
    uint32_t cow_version,
    uint64_t compression_factor) {
  android::snapshot::CowOptions options{
      .block_size = static_cast<uint32_t>(block_size),
      .compression = std::move(compression),
      .max_blocks = (new_partition_size / block_size),
      .compression_factor = compression_factor};
  auto cow_writer = CreateCowEstimator(cow_version, options);
  CHECK_NE(cow_writer, nullptr) << "Could not create cow estimator";
  CHECK(CowDryRun(source_fd,
                  target_fd,
                  operations,
                  merge_operations,
                  block_size,
                  cow_writer.get(),
                  new_partition_size,
                  old_partition_size,
                  xor_enabled));
  return cow_writer->GetCowSizeInfo();
}

}  // namespace chromeos_update_engine
