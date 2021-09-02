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
#include <memory>
#include <utility>
#include <vector>

#include <fcntl.h>
#include <glob.h>
#include <linux/fs.h>

#include <base/files/memory_mapped_file.h>
#include <bsdiff/bspatch.h>
#include <puffin/puffpatch.h>
#include <sys/mman.h>

#include "update_engine/common/utils.h"
#include "update_engine/payload_consumer/bzip_extent_writer.h"
#include "update_engine/payload_consumer/cached_file_descriptor.h"
#include "update_engine/payload_consumer/extent_reader.h"
#include "update_engine/payload_consumer/extent_writer.h"
#include "update_engine/payload_consumer/file_descriptor.h"
#include "update_engine/payload_consumer/file_descriptor_utils.h"
#include "update_engine/payload_consumer/xz_extent_writer.h"
#include "update_engine/payload_generator/delta_diff_generator.h"
#include "update_engine/update_metadata.pb.h"

namespace chromeos_update_engine {

class BsdiffExtentFile : public bsdiff::FileInterface {
 public:
  BsdiffExtentFile(std::unique_ptr<ExtentReader> reader, size_t size)
      : BsdiffExtentFile(std::move(reader), nullptr, size) {}
  BsdiffExtentFile(std::unique_ptr<ExtentWriter> writer, size_t size)
      : BsdiffExtentFile(nullptr, std::move(writer), size) {}

  ~BsdiffExtentFile() override = default;

  bool Read(void* buf, size_t count, size_t* bytes_read) override {
    TEST_AND_RETURN_FALSE(reader_->Read(buf, count));
    *bytes_read = count;
    offset_ += count;
    return true;
  }

  bool Write(const void* buf, size_t count, size_t* bytes_written) override {
    TEST_AND_RETURN_FALSE(writer_->Write(buf, count));
    *bytes_written = count;
    offset_ += count;
    return true;
  }

  bool Seek(off_t pos) override {
    if (reader_ != nullptr) {
      TEST_AND_RETURN_FALSE(reader_->Seek(pos));
      offset_ = pos;
    } else {
      // For writes technically there should be no change of position, or it
      // should be equivalent of current offset.
      TEST_AND_RETURN_FALSE(offset_ == static_cast<uint64_t>(pos));
    }
    return true;
  }

  bool Close() override { return true; }

  bool GetSize(uint64_t* size) override {
    *size = size_;
    return true;
  }

 private:
  BsdiffExtentFile(std::unique_ptr<ExtentReader> reader,
                   std::unique_ptr<ExtentWriter> writer,
                   size_t size)
      : reader_(std::move(reader)),
        writer_(std::move(writer)),
        size_(size),
        offset_(0) {}

  std::unique_ptr<ExtentReader> reader_;
  std::unique_ptr<ExtentWriter> writer_;
  uint64_t size_;
  uint64_t offset_;

  DISALLOW_COPY_AND_ASSIGN(BsdiffExtentFile);
};
// A class to be passed to |puffpatch| for reading from |source_fd_| and writing
// into |target_fd_|.
class PuffinExtentStream : public puffin::StreamInterface {
 public:
  // Constructor for creating a stream for reading from an |ExtentReader|.
  PuffinExtentStream(std::unique_ptr<ExtentReader> reader, uint64_t size)
      : PuffinExtentStream(std::move(reader), nullptr, size) {}

  // Constructor for creating a stream for writing to an |ExtentWriter|.
  PuffinExtentStream(std::unique_ptr<ExtentWriter> writer, uint64_t size)
      : PuffinExtentStream(nullptr, std::move(writer), size) {}

  ~PuffinExtentStream() override = default;

  bool GetSize(uint64_t* size) const override {
    *size = size_;
    return true;
  }

  bool GetOffset(uint64_t* offset) const override {
    *offset = offset_;
    return true;
  }

  bool Seek(uint64_t offset) override {
    if (is_read_) {
      TEST_AND_RETURN_FALSE(reader_->Seek(offset));
      offset_ = offset;
    } else {
      // For writes technically there should be no change of position, or it
      // should equivalent of current offset.
      TEST_AND_RETURN_FALSE(offset_ == offset);
    }
    return true;
  }

  bool Read(void* buffer, size_t count) override {
    TEST_AND_RETURN_FALSE(is_read_);
    TEST_AND_RETURN_FALSE(reader_->Read(buffer, count));
    offset_ += count;
    return true;
  }

  bool Write(const void* buffer, size_t count) override {
    TEST_AND_RETURN_FALSE(!is_read_);
    TEST_AND_RETURN_FALSE(writer_->Write(buffer, count));
    offset_ += count;
    return true;
  }

  bool Close() override { return true; }

 private:
  PuffinExtentStream(std::unique_ptr<ExtentReader> reader,
                     std::unique_ptr<ExtentWriter> writer,
                     uint64_t size)
      : reader_(std::move(reader)),
        writer_(std::move(writer)),
        size_(size),
        offset_(0),
        is_read_(reader_ ? true : false) {}

  std::unique_ptr<ExtentReader> reader_;
  std::unique_ptr<ExtentWriter> writer_;
  uint64_t size_;
  uint64_t offset_;
  bool is_read_;

  DISALLOW_COPY_AND_ASSIGN(PuffinExtentStream);
};

bool InstallOperationExecutor::ExecuteReplaceOperation(
    const InstallOperation& operation,
    std::unique_ptr<ExtentWriter> writer,
    const void* data,
    size_t count) {
  TEST_AND_RETURN_FALSE(operation.type() == InstallOperation::REPLACE ||
                        operation.type() == InstallOperation::REPLACE_BZ ||
                        operation.type() == InstallOperation::REPLACE_XZ);
  // Setup the ExtentWriter stack based on the operation type.
  if (operation.type() == InstallOperation::REPLACE_BZ) {
    writer.reset(new BzipExtentWriter(std::move(writer)));
  } else if (operation.type() == InstallOperation::REPLACE_XZ) {
    writer.reset(new XzExtentWriter(std::move(writer)));
  }
  TEST_AND_RETURN_FALSE(writer->Init(operation.dst_extents(), block_size_));
  TEST_AND_RETURN_FALSE(writer->Write(data, operation.data_length()));

  return true;
}

bool InstallOperationExecutor::ExecuteZeroOrDiscardOperation(
    const InstallOperation& operation, ExtentWriter* writer) {
  TEST_AND_RETURN_FALSE(operation.type() == InstallOperation::ZERO ||
                        operation.type() == InstallOperation::DISCARD);
  using base::MemoryMappedFile;
  using Access = base::MemoryMappedFile::Access;
  using Region = base::MemoryMappedFile::Region;
  writer->Init(operation.dst_extents(), block_size_);
  // Mmap a region of /dev/zero, as we don't need any actual memory to store
  // these 0s, so mmap a region of "free memory".
  base::File dev_zero(base::FilePath("/dev/zero"),
                      base::File::FLAG_OPEN | base::File::FLAG_READ);
  MemoryMappedFile buffer;
  TEST_AND_RETURN_FALSE_ERRNO(buffer.Initialize(
      std::move(dev_zero),
      Region{
          0,
          static_cast<size_t>(utils::BlocksInExtents(operation.dst_extents()) *
                              block_size_)},
      Access::READ_ONLY));
  writer->Write(buffer.data(), buffer.length());
  return true;
}

bool InstallOperationExecutor::ExecuteSourceCopyOperation(
    const InstallOperation& operation,
    ExtentWriter* writer,
    FileDescriptorPtr source_fd) {
  TEST_AND_RETURN_FALSE(operation.type() == InstallOperation::SOURCE_COPY);
  TEST_AND_RETURN_FALSE(writer->Init(operation.dst_extents(), block_size_));
  return fd_utils::CommonHashExtents(
      source_fd, operation.src_extents(), writer, block_size_, nullptr);
}

bool InstallOperationExecutor::ExecuteDiffOperation(
    const InstallOperation& operation,
    std::unique_ptr<ExtentWriter> writer,
    FileDescriptorPtr source_fd,
    const void* data,
    size_t count) {
  TEST_AND_RETURN_FALSE(source_fd != nullptr);
  switch (operation.type()) {
    case InstallOperation::SOURCE_BSDIFF:
    case InstallOperation::BSDIFF:
    case InstallOperation::BROTLI_BSDIFF:
      return ExecuteSourceBsdiffOperation(
          operation, std::move(writer), source_fd, data, count);
    case InstallOperation::PUFFDIFF:
      return ExecutePuffDiffOperation(
          operation, std::move(writer), source_fd, data, count);
    case InstallOperation::ZUCCHINI:
      return ExecuteZucchiniOperation(
          operation, std::move(writer), source_fd, data, count);
    default:
      LOG(ERROR) << "Unexpected operation type when executing diff ops "
                 << operation.type();
      return false;
  }
}

bool InstallOperationExecutor::ExecuteSourceBsdiffOperation(
    const InstallOperation& operation,
    std::unique_ptr<ExtentWriter> writer,
    FileDescriptorPtr source_fd,
    const void* data,
    size_t count) {
  auto reader = std::make_unique<DirectExtentReader>();
  TEST_AND_RETURN_FALSE(
      reader->Init(source_fd, operation.src_extents(), block_size_));
  auto src_file = std::make_unique<BsdiffExtentFile>(
      std::move(reader),
      utils::BlocksInExtents(operation.src_extents()) * block_size_);

  TEST_AND_RETURN_FALSE(writer->Init(operation.dst_extents(), block_size_));
  auto dst_file = std::make_unique<BsdiffExtentFile>(
      std::move(writer),
      utils::BlocksInExtents(operation.dst_extents()) * block_size_);

  TEST_AND_RETURN_FALSE(bsdiff::bspatch(std::move(src_file),
                                        std::move(dst_file),
                                        reinterpret_cast<const uint8_t*>(data),
                                        count) == 0);
  return true;
}

bool InstallOperationExecutor::ExecutePuffDiffOperation(
    const InstallOperation& operation,
    std::unique_ptr<ExtentWriter> writer,
    FileDescriptorPtr source_fd,
    const void* data,
    size_t count) {
  auto reader = std::make_unique<DirectExtentReader>();
  TEST_AND_RETURN_FALSE(
      reader->Init(source_fd, operation.src_extents(), block_size_));
  puffin::UniqueStreamPtr src_stream(new PuffinExtentStream(
      std::move(reader),
      utils::BlocksInExtents(operation.src_extents()) * block_size_));

  TEST_AND_RETURN_FALSE(writer->Init(operation.dst_extents(), block_size_));
  puffin::UniqueStreamPtr dst_stream(new PuffinExtentStream(
      std::move(writer),
      utils::BlocksInExtents(operation.dst_extents()) * block_size_));

  constexpr size_t kMaxCacheSize = 5 * 1024 * 1024;  // Total 5MB cache.
  TEST_AND_RETURN_FALSE(
      puffin::PuffPatch(std::move(src_stream),
                        std::move(dst_stream),
                        reinterpret_cast<const uint8_t*>(data),
                        count,
                        kMaxCacheSize));
  return true;
}

bool InstallOperationExecutor::ExecuteZucchiniOperation(
    const InstallOperation& operation,
    std::unique_ptr<ExtentWriter> writer,
    FileDescriptorPtr source_fd,
    const void* data,
    size_t count) {
  LOG(ERROR) << "zucchini operation isn't supported";
  return false;
}

}  // namespace chromeos_update_engine
