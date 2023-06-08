//
// Copyright (C) 2023 The Android Open Source Project
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

#include "android-base/stringprintf.h"
#include "android-base/unique_fd.h"
#include "common/utils.h"
#include "update_engine/payload_generator/ext2_filesystem.h"
#include "update_engine/payload_generator/erofs_filesystem.h"
#include "update_engine/payload_generator/filesystem_interface.h"

namespace chromeos_update_engine {

int WriteBlockMap(const char* img,
                  const FilesystemInterface* fs,
                  const char* output_file) {
  std::vector<FilesystemInterface::File> files;
  if (!fs->GetFiles(&files)) {
    LOG(ERROR) << "Failed to parse file info in " << img;
    return -2;
  }
  android::base::unique_fd fd(
      open(output_file, O_RDWR | O_CREAT | O_TRUNC | O_CLOEXEC, 0644));
  if (fd < 0) {
    PLOG(ERROR) << "Failed to open " << output_file;
    return -errno;
  }
  for (const auto& file : files) {
    if (file.extents.empty()) {
      continue;
    }
    std::string output_line;
    output_line.append(file.name);
    for (const auto& extent : file.extents) {
      if (extent.num_blocks() <= 0) {
        continue;
      }
      output_line.append(" ");
      if (extent.num_blocks() == 1) {
        output_line.append(std::to_string(extent.start_block()));
        continue;
      }
      const auto extent_str = android::base::StringPrintf(
          "%lu-%lu",
          extent.start_block(),
          extent.start_block() + extent.num_blocks() - 1);
      output_line.append(extent_str);
    }
    output_line.append("\n");
    if (!utils::WriteAll(fd.get(), output_line.data(), output_line.size())) {
      PLOG(ERROR) << "Failed to write to " << output_file;
      return -errno;
    }
  }
  return 0;
}

int Main(int argc, const char* argv[]) {
  const char* img = argv[1];
  const char* output_file = argv[2];
  std::unique_ptr<FilesystemInterface> fs;
  fs = ErofsFilesystem::CreateFromFile(img);
  if (fs != nullptr) {
    return WriteBlockMap(img, fs.get(), output_file);
  }
  fs = Ext2Filesystem::CreateFromFile(img);
  if (fs != nullptr) {
    return WriteBlockMap(img, fs.get(), output_file);
  }
  LOG(ERROR) << "Failed to parse " << img;
  return -1;
}
}  // namespace chromeos_update_engine

int main(int argc, const char* argv[]) {
  return chromeos_update_engine::Main(argc, argv);
}