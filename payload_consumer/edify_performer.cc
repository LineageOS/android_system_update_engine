//
// Copyright (C) 2012 The Android Open Source Project
// Copyright (C) 2020 The Android Open Kang Project
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

#include "update_engine/payload_consumer/edify_performer.h"

#include <errno.h>
#ifdef __linux__
#include <linux/fs.h>
#endif

#include <algorithm>
#include <cstring>
#include <memory>
#include <string>
#include <utility>
#include <vector>

#include <base/files/file_util.h>
#include <base/format_macros.h>
#include <base/metrics/histogram_macros.h>
#include <base/strings/string_number_conversions.h>
#include <base/strings/string_util.h>
#include <base/strings/stringprintf.h>
#include <base/time/time.h>
#include <brillo/data_encoding.h>
#include <bsdiff/bspatch.h>
#include <google/protobuf/repeated_field.h>
#include <puffin/puffpatch.h>

#include "update_engine/common/constants.h"
#include "update_engine/common/hardware_interface.h"
#include "update_engine/common/prefs_interface.h"
#include "update_engine/common/subprocess.h"
#include "update_engine/common/terminator.h"
#include "update_engine/payload_consumer/bzip_extent_writer.h"
#include "update_engine/payload_consumer/cached_file_descriptor.h"
#include "update_engine/payload_consumer/download_action.h"
#include "update_engine/payload_consumer/extent_reader.h"
#include "update_engine/payload_consumer/extent_writer.h"
#include "update_engine/payload_consumer/file_descriptor_utils.h"
#include "update_engine/payload_consumer/mount_history.h"
#if USE_MTD
#include "update_engine/payload_consumer/mtd_file_descriptor.h"
#endif
#include "update_engine/payload_consumer/payload_constants.h"
#include "update_engine/payload_consumer/payload_verifier.h"
#include "update_engine/payload_consumer/xz_extent_writer.h"

#include <ziparchive/zip_archive.h>

/*
 * XXX: Stupid hack alert.  libfsupdater does not currently compile on
 * the host, so work around it here.
 */
#ifdef __BIONIC__

#include <edify/expr.h>
#include <fsupdater/fsupdater.h>

#else

// edify
struct Expr {};
struct State {
  State(const std::string& script, void* cookie) {}
  const std::string script;
  std::string errmsg;
};

static void RegisterBuiltins() {}
static int parse_string(const char* str, std::unique_ptr<Expr>* root, int* error_count) { return 0; }
static bool Evaluate(State* state, const std::unique_ptr<Expr>& expr, std::string* result) { return true; }

// fsupdater
typedef struct {
    FILE* cmd_pipe;
    ZipArchiveHandle package_zip;
    int version;

    uint8_t* package_zip_addr;
    size_t package_zip_len;
} FsUpdaterInfo;

enum FsUpdaterMode : int {
  kFsUpdaterModeStrict,
  kFsUpdaterModeLenient,
};

static void RegisterFsUpdaterFunctions() {}
static void SetFsUpdaterRoot(const std::string& src_root, const std::string& tgt_root) {}
static void SetFsUpdaterMode(FsUpdaterMode mode) {}

#endif

using google::protobuf::RepeatedPtrField;
using std::min;
using std::string;
using std::vector;

namespace chromeos_update_engine {

const unsigned EdifyPerformer::kProgressLogMaxChunks = 10;
const unsigned EdifyPerformer::kProgressLogTimeoutSeconds = 30;
const unsigned EdifyPerformer::kProgressDownloadWeight = 50;
const unsigned EdifyPerformer::kProgressOperationsWeight = 50;


// Computes the ratio of |part| and |total|, scaled to |norm|, using integer
// arithmetic.
static uint64_t IntRatio(uint64_t part, uint64_t total, uint64_t norm) {
  return part * norm / total;
}

void EdifyPerformer::LogProgress(const char* message_prefix) {
  // Format operations total count and percentage.
  string total_operations_str("?");
  string completed_percentage_str("");
  if (num_total_operations_) {
    total_operations_str = std::to_string(num_total_operations_);
    // Upcasting to 64-bit to avoid overflow, back to size_t for formatting.
    completed_percentage_str =
        base::StringPrintf(" (%" PRIu64 "%%)",
                           IntRatio(next_operation_num_, num_total_operations_,
                                    100));
  }

  // Format download total count and percentage.
  size_t payload_size = payload_->size;
  string payload_size_str("?");
  string downloaded_percentage_str("");
  if (payload_size) {
    payload_size_str = std::to_string(payload_size);
    // Upcasting to 64-bit to avoid overflow, back to size_t for formatting.
    downloaded_percentage_str =
        base::StringPrintf(" (%" PRIu64 "%%)",
                           IntRatio(total_bytes_received_, payload_size, 100));
  }

  LOG(INFO) << (message_prefix ? message_prefix : "") << next_operation_num_
            << "/" << total_operations_str << " operations"
            << completed_percentage_str << ", " << total_bytes_received_
            << "/" << payload_size_str << " bytes downloaded"
            << downloaded_percentage_str << ", overall progress "
            << overall_progress_ << "%";
}

void EdifyPerformer::UpdateOverallProgress(bool force_log,
                                           const char* message_prefix) {
  // Compute our download and overall progress.
  unsigned new_overall_progress = 0;
  static_assert(kProgressDownloadWeight + kProgressOperationsWeight == 100,
                "Progress weights don't add up");
  // Only consider download progress if its total size is known; otherwise
  // adjust the operations weight to compensate for the absence of download
  // progress. Also, make sure to cap the download portion at
  // kProgressDownloadWeight, in case we end up downloading more than we
  // initially expected (this indicates a problem, but could generally happen).
  // TODO(garnold) the correction of operations weight when we do not have the
  // total payload size, as well as the conditional guard below, should both be
  // eliminated once we ensure that the payload_size in the install plan is
  // always given and is non-zero. This currently isn't the case during unit
  // tests (see chromium-os:37969).
  size_t payload_size = payload_->size;
  unsigned actual_operations_weight = kProgressOperationsWeight;
  if (payload_size)
    new_overall_progress += min(
        static_cast<unsigned>(IntRatio(total_bytes_received_, payload_size,
                                       kProgressDownloadWeight)),
        kProgressDownloadWeight);
  else
    actual_operations_weight += kProgressDownloadWeight;

  // Only add completed operations if their total number is known; we definitely
  // expect an update to have at least one operation, so the expectation is that
  // this will eventually reach |actual_operations_weight|.
  if (num_total_operations_)
    new_overall_progress += IntRatio(next_operation_num_, num_total_operations_,
                                     actual_operations_weight);

  // Progress ratio cannot recede, unless our assumptions about the total
  // payload size, total number of operations, or the monotonicity of progress
  // is breached.
  if (new_overall_progress < overall_progress_) {
    LOG(WARNING) << "progress counter receded from " << overall_progress_
                 << "% down to " << new_overall_progress << "%; this is a bug";
    force_log = true;
  }
  overall_progress_ = new_overall_progress;

  // Update chunk index, log as needed: if forced by called, or we completed a
  // progress chunk, or a timeout has expired.
  base::Time curr_time = base::Time::Now();
  unsigned curr_progress_chunk =
      overall_progress_ * kProgressLogMaxChunks / 100;
  if (force_log || curr_progress_chunk > last_progress_chunk_ ||
      curr_time > forced_progress_log_time_) {
    forced_progress_log_time_ = curr_time + forced_progress_log_wait_;
    LogProgress(message_prefix);
  }
  last_progress_chunk_ = curr_progress_chunk;
}


int EdifyPerformer::Close() {
  int err = -CloseCurrentPartition();
  LOG_IF(ERROR, !payload_hash_calculator_.Finalize() ||
                !signed_hash_calculator_.Finalize())
      << "Unable to finalize the hash.";
  if (!buffer_.empty()) {
    LOG(INFO) << "Discarding " << buffer_.size() << " unused downloaded bytes";
    if (err >= 0)
      err = 1;
  }
  return -err;
}

int EdifyPerformer::CloseCurrentPartition() {
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
  return -err;
}

// Wrapper around write. Returns true if all requested bytes
// were written, or false on any error, regardless of progress
// and stores an action exit code in |error|.
bool EdifyPerformer::Write(const void* bytes, size_t count, ErrorCode *error) {
  *error = ErrorCode::kSuccess;

  // Update the total byte downloaded count and the progress logs.
  total_bytes_received_ += count;
  UpdateOverallProgress(false, "Completed ");

  const uint8_t* c_bytes = reinterpret_cast<const uint8_t*>(bytes);
  buffer_.insert(buffer_.end(), c_bytes, c_bytes + count);

  if (buffer_.size() == payload_->size) {
    DoUpdate();
  }

  return true;
}

bool EdifyPerformer::IsManifestValid() {
  return manifest_valid_;
}

bool EdifyPerformer::ParseManifestPartitions(ErrorCode* error) {
  //XXX: do we need this?
  return false;
}

bool EdifyPerformer::GetPublicKeyFromResponse(base::FilePath *out_tmp_key) {
  if (hardware_->IsOfficialBuild() ||
      utils::FileExists(public_key_path_.c_str()) ||
      install_plan_->public_key_rsa.empty())
    return false;

  if (!utils::DecodeAndStoreBase64String(install_plan_->public_key_rsa,
                                         out_tmp_key))
    return false;

  return true;
}

ErrorCode EdifyPerformer::VerifyPayload(
    const brillo::Blob& update_check_response_hash,
    const uint64_t update_check_response_size) {

  LOG(INFO) << "Skipping payload verify";

  // At this point, we are guaranteed to have downloaded a full payload, i.e
  // the one whose size matches the size mentioned in Omaha response. If any
  // errors happen after this, it's likely a problem with the payload itself or
  // the state of the system and not a problem with the URL or network.  So,
  // indicate that to the download delegate so that AU can backoff
  // appropriately.
  if (download_delegate_)
    download_delegate_->DownloadComplete();

  return ErrorCode::kSuccess;
}

static constexpr const char* SCRIPT_NAME = "META-INF/com/google/android/updater-script";
static constexpr int kRecoveryApiVersion = 3;

bool EdifyPerformer::DoUpdate() {
  bool ret = false;

  const std::string filename = "zip"; //XXX

  ZipArchiveHandle za;
  ret = OpenArchiveFromMemory(buffer_.data(), buffer_.size(), filename.c_str(), &za);
  if (ret != 0) {
    LOG(ERROR) << "failed to open package " << filename << ": " << ErrorCodeString(ret);
    CloseArchive(za);
    return false;
  }

  ZipString script_name(SCRIPT_NAME);
  ZipEntry script_entry;
  ret = FindEntry(za, script_name, &script_entry);
  if (ret != 0) {
    LOG(ERROR) << "failed to find " << SCRIPT_NAME << " in " << filename << ": "
               << ErrorCodeString(ret);
    CloseArchive(za);
    return false;
  }

  std::string script;
  script.resize(script_entry.uncompressed_length);
  ret = ExtractToMemory(za, &script_entry,
                        reinterpret_cast<uint8_t*>(&script[0]),
                        script_entry.uncompressed_length);
  if (ret != 0) {
    LOG(ERROR) << "failed to read script from package: " << ErrorCodeString(ret);
    CloseArchive(za);
    return false;
  }

  // Configure edify functions
  RegisterBuiltins();
  RegisterFsUpdaterFunctions();

  SetFsUpdaterRoot("/", "/mnt/install");
  SetFsUpdaterMode(kFsUpdaterModeLenient);

  // Parse the script
  std::unique_ptr<Expr> root;
  int error_count = 0;
  int error = parse_string(script.c_str(), &root, &error_count);
  if (error != 0 || error_count > 0) {
    LOG(ERROR) << error_count << " parse errors in updater-script";
    CloseArchive(za);
    return false;
  }

  // Evaluate the parsed script
  FsUpdaterInfo updater_info;
  updater_info.cmd_pipe = nullptr;
  updater_info.package_zip = za;
  updater_info.version = kRecoveryApiVersion;
  updater_info.package_zip_addr = buffer_.data();
  updater_info.package_zip_len = buffer_.size();

  State state(script, &updater_info);
  //XXX: set state.is_retry

  LOG(INFO) << "EdifyPerformer::DoUpdate: evaluate script";

  std::string result;
  bool status = Evaluate(&state, root, &result);
  if (status) {
    LOG(INFO) << "script succeeded";
    ret = true;
  }
  else {
    LOG(ERROR) << "script failed: " << state.errmsg;
  }

  // Handle errors and such

  if (updater_info.package_zip) {
    CloseArchive(updater_info.package_zip);
  }

  return ret;
}

bool EdifyPerformer::CheckpointUpdateProgress() {
  Terminator::set_exit_blocked(true);
  if (last_updated_buffer_offset_ != buffer_offset_) {
    // Resets the progress in case we die in the middle of the state update.
    ResetUpdateProgress(prefs_, true);
    TEST_AND_RETURN_FALSE(
        prefs_->SetString(kPrefsUpdateStateSHA256Context,
                          payload_hash_calculator_.GetContext()));
    TEST_AND_RETURN_FALSE(
        prefs_->SetString(kPrefsUpdateStateSignedSHA256Context,
                          signed_hash_calculator_.GetContext()));
    TEST_AND_RETURN_FALSE(prefs_->SetInt64(kPrefsUpdateStateNextDataOffset,
                                           buffer_offset_));
    last_updated_buffer_offset_ = buffer_offset_;

    if (next_operation_num_ < num_total_operations_) {
      size_t partition_index = current_partition_;
      while (next_operation_num_ >= acc_num_operations_[partition_index])
        partition_index++;
      const size_t partition_operation_num = next_operation_num_ - (
          partition_index ? acc_num_operations_[partition_index - 1] : 0);
      const InstallOperation& op =
          partitions_[partition_index].operations(partition_operation_num);
      TEST_AND_RETURN_FALSE(prefs_->SetInt64(kPrefsUpdateStateNextDataLength,
                                             op.data_length()));
    } else {
      TEST_AND_RETURN_FALSE(prefs_->SetInt64(kPrefsUpdateStateNextDataLength,
                                             0));
    }
  }
  TEST_AND_RETURN_FALSE(prefs_->SetInt64(kPrefsUpdateStateNextOperation,
                                         next_operation_num_));
  return true;
}

}  // namespace chromeos_update_engine
