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

#include "update_engine/payload_consumer/install_operation_executor.h"

#include <fcntl.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cstring>
#include <limits>
#include <memory>
#include <ostream>
#include <utility>
#include <vector>

#include <brillo/secure_blob.h>
#include <gtest/gtest.h>
#include <update_engine/update_metadata.pb.h>

#include "update_engine/common/utils.h"
#include "update_engine/payload_consumer/extent_writer.h"
#include "update_engine/payload_consumer/file_descriptor.h"
#include "update_engine/payload_consumer/payload_constants.h"
#include "update_engine/payload_generator/extent_ranges.h"
#include "update_engine/payload_generator/extent_utils.h"

namespace chromeos_update_engine {

std::ostream& operator<<(std::ostream& out,
                         const chromeos_update_engine::InstallOperation& op) {
  out << InstallOperationTypeName(op.type())
      << " SRC: " << ExtentsToString(op.src_extents())
      << " DST: " << ExtentsToString(op.dst_extents());
  return out;
}

namespace {
template <typename Container>
size_t GetNthBlock(const Container& extents, const size_t n) {
  size_t cur_block_count = 0;
  for (const auto& extent : extents) {
    if (cur_block_count + extent.num_blocks() >= n) {
      return extent.start_block() + (n - cur_block_count);
    }
    cur_block_count += extent.num_blocks();
  }
  return std::numeric_limits<size_t>::max();
}

}  // namespace

class InstallOperationExecutorTest : public ::testing::Test {
 public:
  static constexpr size_t NUM_BLOCKS = 10;
  static constexpr size_t BLOCK_SIZE = 4096;
  void SetUp() override {
    // Fill source partition with arbitrary data.
    std::array<uint8_t, BLOCK_SIZE> buffer{};
    for (size_t i = 0; i < NUM_BLOCKS; i++) {
      // Fill block with arbitrary data. We don't care about what data is being
      // written to source partition, so as long as each block is slightly
      // different.
      std::fill(buffer.begin(), buffer.end(), i);
      ASSERT_TRUE(utils::WriteAll(source_.fd(), buffer.data(), buffer.size()))
          << "Failed to write to source partition file: " << strerror(errno);
      std::fill(buffer.begin(), buffer.end(), NUM_BLOCKS + i);
      ASSERT_TRUE(utils::WriteAll(target_.fd(), buffer.data(), buffer.size()))
          << "Failed to write to target partition file: " << strerror(errno);
    }
    fsync(source_.fd());
    fsync(target_.fd());

    // set target partition to have same size as source partition.
    // update_engine mostly assumes that target partition have the desired
    // size, so we mock that.
    ASSERT_GE(ftruncate64(target_.fd(), NUM_BLOCKS * BLOCK_SIZE), 0)
        << strerror(errno) << " failed to set target partition size to "
        << NUM_BLOCKS * BLOCK_SIZE;

    source_fd_->Open(source_.path().c_str(), O_RDONLY);
    target_fd_->Open(target_.path().c_str(), O_RDWR);
  }

  void VerityUntouchedExtents(const InstallOperation& op) {
    ExtentRanges extent_set;
    extent_set.AddExtent(ExtentForRange(0, 10));
    extent_set.SubtractRepeatedExtents(op.dst_extents());
    std::vector<Extent> untouched_extents{extent_set.extent_set().begin(),
                                          extent_set.extent_set().end()};
    brillo::Blob actual_data;
    ASSERT_TRUE(utils::ReadExtents(target_.path(),
                                   untouched_extents,
                                   &actual_data,
                                   extent_set.blocks() * BLOCK_SIZE,
                                   BLOCK_SIZE));
    const auto untouched_blocks = ExpandExtents(untouched_extents);
    for (size_t i = 0; i < actual_data.size(); i++) {
      const auto block_offset = i / BLOCK_SIZE;
      const auto offset = i % BLOCK_SIZE;
      ASSERT_EQ(
          actual_data[i],
          static_cast<uint8_t>(NUM_BLOCKS + untouched_blocks[block_offset]))
          << "After performing op " << op << ", offset " << offset
          << " in block " << GetNthBlock(untouched_extents, block_offset)
          << " is modified but it shouldn't.";
    }
  }
  ScopedTempFile source_{"source_partition.XXXXXXXX", true};
  ScopedTempFile target_{"target_partition.XXXXXXXX", true};
  FileDescriptorPtr source_fd_ = std::make_shared<EintrSafeFileDescriptor>();
  FileDescriptorPtr target_fd_ = std::make_shared<EintrSafeFileDescriptor>();
  InstallOperationExecutor executor_{BLOCK_SIZE};
};

TEST_F(InstallOperationExecutorTest, ReplaceOpTest) {
  InstallOperation op;
  op.set_type(InstallOperation::REPLACE);
  *op.mutable_dst_extents()->Add() = ExtentForRange(2, 2);
  *op.mutable_dst_extents()->Add() = ExtentForRange(6, 2);
  op.set_data_length(BLOCK_SIZE * 4);
  brillo::Blob expected_data;
  expected_data.resize(BLOCK_SIZE * 4);
  // Fill buffer with arbitrary data. Doesn't matter what it is. Each block
  // needs to be different so that we can ensure the InstallOperationExecutor
  // is reading data from the correct offset.
  for (int i = 0; i < 4; i++) {
    std::fill(&expected_data[i * BLOCK_SIZE],
              &expected_data[(i + 1) * BLOCK_SIZE],
              i + 99);
  }
  auto writer = std::make_unique<DirectExtentWriter>(target_fd_);
  ASSERT_TRUE(executor_.ExecuteReplaceOperation(
      op, std::move(writer), expected_data.data(), expected_data.size()));

  brillo::Blob actual_data;
  utils::ReadExtents(
      target_.path(),
      std::vector<Extent>{op.dst_extents().begin(), op.dst_extents().end()},
      &actual_data,
      BLOCK_SIZE * 4,
      BLOCK_SIZE);
  ASSERT_EQ(actual_data, expected_data);
  VerityUntouchedExtents(op);
}

TEST_F(InstallOperationExecutorTest, ZeroOrDiscardeOpTest) {
  InstallOperation op;
  op.set_type(InstallOperation::ZERO);
  *op.mutable_dst_extents()->Add() = ExtentForRange(2, 2);
  *op.mutable_dst_extents()->Add() = ExtentForRange(6, 2);
  auto writer = std::make_unique<DirectExtentWriter>(target_fd_);
  ASSERT_TRUE(executor_.ExecuteZeroOrDiscardOperation(op, writer.get()));
  brillo::Blob actual_data;
  utils::ReadExtents(
      target_.path(),
      std::vector<Extent>{op.dst_extents().begin(), op.dst_extents().end()},
      &actual_data,
      BLOCK_SIZE * 4,
      BLOCK_SIZE);
  for (size_t i = 0; i < actual_data.size(); i++) {
    ASSERT_EQ(actual_data[i], 0U) << "position " << i << " isn't zeroed!";
  }
  VerityUntouchedExtents(op);
}

TEST_F(InstallOperationExecutorTest, SourceCopyOpTest) {
  InstallOperation op;
  op.set_type(InstallOperation::SOURCE_COPY);
  *op.mutable_src_extents()->Add() = ExtentForRange(1, 2);
  *op.mutable_src_extents()->Add() = ExtentForRange(5, 1);
  *op.mutable_src_extents()->Add() = ExtentForRange(7, 1);

  *op.mutable_dst_extents()->Add() = ExtentForRange(2, 2);
  *op.mutable_dst_extents()->Add() = ExtentForRange(6, 2);

  auto writer = std::make_unique<DirectExtentWriter>(target_fd_);
  ASSERT_TRUE(
      executor_.ExecuteSourceCopyOperation(op, writer.get(), source_fd_));
  brillo::Blob actual_data;
  utils::ReadExtents(
      target_.path(),
      std::vector<Extent>{op.dst_extents().begin(), op.dst_extents().end()},
      &actual_data,
      BLOCK_SIZE * 4,
      BLOCK_SIZE);
  brillo::Blob expected_data;
  utils::ReadExtents(
      source_.path(),
      std::vector<Extent>{op.src_extents().begin(), op.src_extents().end()},
      &expected_data,
      BLOCK_SIZE * 4,
      BLOCK_SIZE);

  ASSERT_EQ(expected_data.size(), actual_data.size());
  for (size_t i = 0; i < actual_data.size(); i++) {
    const auto block_offset = i / BLOCK_SIZE;
    const auto offset = i % BLOCK_SIZE;
    ASSERT_EQ(actual_data[i], expected_data[i])
        << "After performing op " << op << ", offset " << offset << " in  ["
        << GetNthBlock(op.src_extents(), block_offset) << " -> "
        << GetNthBlock(op.dst_extents(), block_offset) << "]"
        << " is not copied correctly";
  }
  VerityUntouchedExtents(op);
}
}  // namespace chromeos_update_engine
