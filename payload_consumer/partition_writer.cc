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
#include <update_engine/payload_consumer/partition_writer.h>

#include <fcntl.h>
#include <linux/fs.h>
#include <sys/mman.h>

#include <algorithm>
#include <initializer_list>
#include <memory>
#include <utility>
#include <vector>

#include <base/strings/string_number_conversions.h>

#include "update_engine/common/terminator.h"
#include "update_engine/common/utils.h"
#include "update_engine/payload_consumer/bzip_extent_writer.h"
#include "update_engine/payload_consumer/cached_file_descriptor.h"
#include "update_engine/payload_consumer/extent_reader.h"
#include "update_engine/payload_consumer/extent_writer.h"
#include "update_engine/payload_consumer/fec_file_descriptor.h"
#include "update_engine/payload_consumer/file_descriptor_utils.h"
#include "update_engine/payload_consumer/install_plan.h"
#include "update_engine/payload_consumer/mount_history.h"
#include "update_engine/payload_consumer/payload_constants.h"
#include "update_engine/payload_consumer/xz_extent_writer.h"
#include "update_engine/payload_generator/extent_utils.h"

namespace chromeos_update_engine {

namespace {
constexpr uint64_t kCacheSize = 1024 * 1024;  // 1MB

// Discard the tail of the block device referenced by |fd|, from the offset
// |data_size| until the end of the block device. Returns whether the data was
// discarded.

bool DiscardPartitionTail(const FileDescriptorPtr& fd, uint64_t data_size) {
  uint64_t part_size = fd->BlockDevSize();
  if (!part_size || part_size <= data_size)
    return false;

  struct blkioctl_request {
    int number;
    const char* name;
  };
  const std::initializer_list<blkioctl_request> blkioctl_requests = {
      {BLKDISCARD, "BLKDISCARD"},
      {BLKSECDISCARD, "BLKSECDISCARD"},
#ifdef BLKZEROOUT
      {BLKZEROOUT, "BLKZEROOUT"},
#endif
  };
  for (const auto& req : blkioctl_requests) {
    int error = 0;
    if (fd->BlkIoctl(req.number, data_size, part_size - data_size, &error) &&
        error == 0) {
      return true;
    }
    LOG(WARNING) << "Error discarding the last "
                 << (part_size - data_size) / 1024 << " KiB using ioctl("
                 << req.name << ")";
  }
  return false;
}

}  // namespace

using google::protobuf::RepeatedPtrField;

// Opens path for read/write. On success returns an open FileDescriptor
// and sets *err to 0. On failure, sets *err to errno and returns nullptr.
FileDescriptorPtr OpenFile(const char* path,
                           int mode,
                           bool cache_writes,
                           int* err) {
  // Try to mark the block device read-only based on the mode. Ignore any
  // failure since this won't work when passing regular files.
  bool read_only = (mode & O_ACCMODE) == O_RDONLY;
  utils::SetBlockDeviceReadOnly(path, read_only);

  FileDescriptorPtr fd(new EintrSafeFileDescriptor());
  if (cache_writes && !read_only) {
    fd = FileDescriptorPtr(new CachedFileDescriptor(fd, kCacheSize));
    LOG(INFO) << "Caching writes.";
  }
  if (!fd->Open(path, mode, 000)) {
    *err = errno;
    PLOG(ERROR) << "Unable to open file " << path;
    return nullptr;
  }
  *err = 0;
  return fd;
}

PartitionWriter::PartitionWriter(
    const PartitionUpdate& partition_update,
    const InstallPlan::Partition& install_part,
    DynamicPartitionControlInterface* dynamic_control,
    size_t block_size,
    bool is_interactive)
    : partition_update_(partition_update),
      install_part_(install_part),
      dynamic_control_(dynamic_control),
      interactive_(is_interactive),
      block_size_(block_size),
      install_op_executor_(block_size) {}

PartitionWriter::~PartitionWriter() {
  Close();
}

bool PartitionWriter::OpenSourcePartition(uint32_t source_slot,
                                          bool source_may_exist) {
  source_path_.clear();
  if (!source_may_exist) {
    return true;
  }
  if (install_part_.source_size > 0 && !install_part_.source_path.empty()) {
    source_path_ = install_part_.source_path;
    int err;
    source_fd_ = OpenFile(source_path_.c_str(), O_RDONLY, false, &err);
    if (source_fd_ == nullptr) {
      LOG(ERROR) << "Unable to open source partition " << install_part_.name
                 << " on slot " << BootControlInterface::SlotName(source_slot)
                 << ", file " << source_path_;
      return false;
    }
  }
  return true;
}

bool PartitionWriter::Init(const InstallPlan* install_plan,
                           bool source_may_exist,
                           size_t next_op_index) {
  const PartitionUpdate& partition = partition_update_;
  uint32_t source_slot = install_plan->source_slot;
  uint32_t target_slot = install_plan->target_slot;
  TEST_AND_RETURN_FALSE(OpenSourcePartition(source_slot, source_may_exist));

  // We shouldn't open the source partition in certain cases, e.g. some dynamic
  // partitions in delta payload, partitions included in the full payload for
  // partial updates. Use the source size as the indicator.

  target_path_ = install_part_.target_path;
  int err;

  int flags = O_RDWR;
  if (!interactive_)
    flags |= O_DSYNC;

  LOG(INFO) << "Opening " << target_path_ << " partition with"
            << (interactive_ ? "out" : "") << " O_DSYNC";

  target_fd_ = OpenFile(target_path_.c_str(), flags, true, &err);
  if (!target_fd_) {
    LOG(ERROR) << "Unable to open target partition "
               << partition.partition_name() << " on slot "
               << BootControlInterface::SlotName(target_slot) << ", file "
               << target_path_;
    return false;
  }

  LOG(INFO) << "Applying " << partition.operations().size()
            << " operations to partition \"" << partition.partition_name()
            << "\"";

  // Discard the end of the partition, but ignore failures.
  DiscardPartitionTail(target_fd_, install_part_.target_size);

  return true;
}

bool PartitionWriter::PerformReplaceOperation(const InstallOperation& operation,
                                              const void* data,
                                              size_t count) {
  // Setup the ExtentWriter stack based on the operation type.
  std::unique_ptr<ExtentWriter> writer = CreateBaseExtentWriter();
  writer->Init(operation.dst_extents(), block_size_);
  return install_op_executor_.ExecuteReplaceOperation(
      operation, std::move(writer), data, count);
}

bool PartitionWriter::PerformZeroOrDiscardOperation(
    const InstallOperation& operation) {
#ifdef BLKZEROOUT
  int request =
      (operation.type() == InstallOperation::ZERO ? BLKZEROOUT : BLKDISCARD);
#else   // !defined(BLKZEROOUT)
  auto writer = CreateBaseExtentWriter();
  return install_op_executor_.ExecuteZeroOrDiscardOperation(operation,
                                                            writer.get());
#endif  // !defined(BLKZEROOUT)

  for (const Extent& extent : operation.dst_extents()) {
    const uint64_t start = extent.start_block() * block_size_;
    const uint64_t length = extent.num_blocks() * block_size_;
    int result = 0;
    if (target_fd_->BlkIoctl(request, start, length, &result) && result == 0) {
      continue;
    }
    // In case of failure, we fall back to writing 0 for the entire operation.
    PLOG(WARNING) << "BlkIoctl failed. Falling back to write 0s for remainder "
                     "of this operation.";
    auto writer = CreateBaseExtentWriter();
    writer->Init(operation.dst_extents(), block_size_);
    return install_op_executor_.ExecuteZeroOrDiscardOperation(operation,
                                                              writer.get());
  }
  return true;
}

std::ostream& operator<<(std::ostream& out,
                         const RepeatedPtrField<Extent>& extents) {
  if (extents.size() == 0) {
    out << "[]";
    return out;
  }
  out << "[";
  auto begin = extents.begin();
  out << *begin;
  for (int i = 1; i < extents.size(); i++) {
    ++begin;
    out << ", " << *begin;
  }
  out << "]";
  return out;
}

bool PartitionWriter::PerformSourceCopyOperation(
    const InstallOperation& operation, ErrorCode* error) {
  TEST_AND_RETURN_FALSE(source_fd_ != nullptr);

  // The device may optimize the SOURCE_COPY operation.
  // Being this a device-specific optimization let DynamicPartitionController
  // decide it the operation should be skipped.
  const PartitionUpdate& partition = partition_update_;

  InstallOperation buf;
  const bool should_optimize = dynamic_control_->OptimizeOperation(
      partition.partition_name(), operation, &buf);
  const InstallOperation& optimized = should_optimize ? buf : operation;

  // Invoke ChooseSourceFD with original operation, so that it can properly
  // verify source hashes. Optimized operation might contain a smaller set of
  // extents, or completely empty.
  auto source_fd = ChooseSourceFD(operation, error);
  if (source_fd == nullptr) {
    LOG(ERROR) << "Unrecoverable source hash mismatch found on partition "
               << partition.partition_name()
               << " extents: " << operation.src_extents();
    return false;
  }

  auto writer = CreateBaseExtentWriter();
  writer->Init(optimized.dst_extents(), block_size_);
  return install_op_executor_.ExecuteSourceCopyOperation(
      optimized, writer.get(), source_fd);
}

bool PartitionWriter::PerformSourceBsdiffOperation(
    const InstallOperation& operation,
    ErrorCode* error,
    const void* data,
    size_t count) {
  FileDescriptorPtr source_fd = ChooseSourceFD(operation, error);
  TEST_AND_RETURN_FALSE(source_fd != nullptr);

  auto writer = CreateBaseExtentWriter();
  writer->Init(operation.dst_extents(), block_size_);
  return install_op_executor_.ExecuteSourceBsdiffOperation(
      operation, std::move(writer), source_fd, data, count);
}

bool PartitionWriter::PerformPuffDiffOperation(
    const InstallOperation& operation,
    ErrorCode* error,
    const void* data,
    size_t count) {
  FileDescriptorPtr source_fd = ChooseSourceFD(operation, error);
  TEST_AND_RETURN_FALSE(source_fd != nullptr);

  auto writer = CreateBaseExtentWriter();
  writer->Init(operation.dst_extents(), block_size_);
  return install_op_executor_.ExecutePuffDiffOperation(
      operation, std::move(writer), source_fd, data, count);
}

FileDescriptorPtr PartitionWriter::ChooseSourceFD(
    const InstallOperation& operation, ErrorCode* error) {
  if (source_fd_ == nullptr) {
    LOG(ERROR) << "ChooseSourceFD fail: source_fd_ == nullptr";
    return nullptr;
  }

  if (!operation.has_src_sha256_hash()) {
    // When the operation doesn't include a source hash, we attempt the error
    // corrected device first since we can't verify the block in the raw
    // device at this point, but we first need to make sure all extents are
    // readable since the error corrected device can be shorter or not
    // available.
    if (OpenCurrentECCPartition() &&
        fd_utils::ReadAndHashExtents(
            source_ecc_fd_, operation.src_extents(), block_size_, nullptr)) {
      return source_ecc_fd_;
    }
    return source_fd_;
  }

  brillo::Blob source_hash;
  brillo::Blob expected_source_hash(operation.src_sha256_hash().begin(),
                                    operation.src_sha256_hash().end());
  if (fd_utils::ReadAndHashExtents(
          source_fd_, operation.src_extents(), block_size_, &source_hash) &&
      source_hash == expected_source_hash) {
    return source_fd_;
  }
  // We fall back to use the error corrected device if the hash of the raw
  // device doesn't match or there was an error reading the source partition.
  if (!OpenCurrentECCPartition()) {
    // The following function call will return false since the source hash
    // mismatches, but we still want to call it so it prints the appropriate
    // log message.
    ValidateSourceHash(source_hash, operation, source_fd_, error);
    return nullptr;
  }
  LOG(WARNING) << "Source hash from RAW device mismatched: found "
               << base::HexEncode(source_hash.data(), source_hash.size())
               << ", expected "
               << base::HexEncode(expected_source_hash.data(),
                                  expected_source_hash.size());

  if (fd_utils::ReadAndHashExtents(
          source_ecc_fd_, operation.src_extents(), block_size_, &source_hash) &&
      ValidateSourceHash(source_hash, operation, source_ecc_fd_, error)) {
    // At this point reading from the error corrected device worked, but
    // reading from the raw device failed, so this is considered a recovered
    // failure.
    source_ecc_recovered_failures_++;
    return source_ecc_fd_;
  }
  return nullptr;
}

bool PartitionWriter::OpenCurrentECCPartition() {
  // No support for ECC for full payloads.
  // Full payload should not have any opeartion that requires ECC partitions.
  if (source_ecc_fd_)
    return true;

  if (source_ecc_open_failure_)
    return false;

#if USE_FEC
  const PartitionUpdate& partition = partition_update_;
  const InstallPlan::Partition& install_part = install_part_;
  std::string path = install_part.source_path;
  FileDescriptorPtr fd(new FecFileDescriptor());
  if (!fd->Open(path.c_str(), O_RDONLY, 0)) {
    PLOG(ERROR) << "Unable to open ECC source partition "
                << partition.partition_name() << ", file " << path;
    source_ecc_open_failure_ = true;
    return false;
  }
  source_ecc_fd_ = fd;
#else
  // No support for ECC compiled.
  source_ecc_open_failure_ = true;
#endif  // USE_FEC

  return !source_ecc_open_failure_;
}

int PartitionWriter::Close() {
  int err = 0;
  if (source_fd_ && !source_fd_->Close()) {
    err = errno;
    PLOG(ERROR) << "Error closing source partition";
    if (!err)
      err = 1;
  }
  source_fd_.reset();
  source_path_.clear();

  if (target_fd_ && !target_fd_->Close()) {
    err = errno;
    PLOG(ERROR) << "Error closing target partition";
    if (!err)
      err = 1;
  }
  target_fd_.reset();
  target_path_.clear();

  if (source_ecc_fd_ && !source_ecc_fd_->Close()) {
    err = errno;
    PLOG(ERROR) << "Error closing ECC source partition";
    if (!err)
      err = 1;
  }
  source_ecc_fd_.reset();
  source_ecc_open_failure_ = false;
  return -err;
}

void PartitionWriter::CheckpointUpdateProgress(size_t next_op_index) {
  target_fd_->Flush();
}

std::unique_ptr<ExtentWriter> PartitionWriter::CreateBaseExtentWriter() {
  return std::make_unique<DirectExtentWriter>(target_fd_);
}

}  // namespace chromeos_update_engine
