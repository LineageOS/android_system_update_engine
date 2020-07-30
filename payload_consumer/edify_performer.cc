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

#include <edify/expr.h>
#include <fsupdater/fsupdater.h>

using google::protobuf::RepeatedPtrField;
using std::min;
using std::string;
using std::vector;

namespace chromeos_update_engine {

const unsigned EdifyPerformer::kProgressLogMaxChunks = 10;
const unsigned EdifyPerformer::kProgressLogTimeoutSeconds = 30;
const unsigned EdifyPerformer::kProgressDownloadWeight = 50;
const unsigned EdifyPerformer::kProgressOperationsWeight = 50;
const uint64_t EdifyPerformer::kCheckpointFrequencySeconds = 1;


// Computes the ratio of |part| and |total|, scaled to |norm|, using integer
// arithmetic.
static uint64_t IntRatio(uint64_t part, uint64_t total, uint64_t norm) {
  return part * norm / total;
}

void EdifyPerformer::LogProgress(const char* message_prefix) {
  // Format operations total count and percentage.
  string total_operations_str("?");

  // Format download total count and percentage.
  size_t payload_size = payload_->size;
  string payload_size_str("?");
  string downloaded_percentage_str("");
  if (payload_size) {
    payload_size_str = std::to_string(payload_size);
  }

  LOG(INFO) << (message_prefix ? message_prefix : "")
            << total_bytes_received_ << "/" << payload_size_str << " bytes downloaded"
            << downloaded_percentage_str << ", overall progress " << overall_progress_ << "%";
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
    new_overall_progress +=
        min(static_cast<unsigned>(IntRatio(
                total_bytes_received_, payload_size, kProgressDownloadWeight)),
            kProgressDownloadWeight);
  else
    actual_operations_weight += kProgressDownloadWeight;

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
  base::TimeTicks curr_time = base::TimeTicks::Now();
  if (force_log || curr_time > forced_progress_log_time_) {
    forced_progress_log_time_ = curr_time + forced_progress_log_wait_;
    LogProgress(message_prefix);
  }
}


int EdifyPerformer::Close() {
  LOG_IF(ERROR,
         !payload_hash_calculator_.Finalize())
      << "Unable to finalize the hash.";
  return 0;
}

bool EdifyPerformer::CanShare() {
  return buffer_.size() == payload_->size;
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

  payload_hash_calculator_.Update(bytes, count);

  return true;
}

bool EdifyPerformer::GetPublicKey(string* out_public_key) {
  out_public_key->clear();

  if (utils::FileExists(public_key_path_.c_str())) {
    LOG(INFO) << "Verifying using public key: " << public_key_path_;
    return utils::ReadFile(public_key_path_, out_public_key);
  }

  return false;
}

bool EdifyPerformer::GetSignature(brillo::Blob* signature, uint64_t* signed_len) {
#define FOOTER_SIZE 6
  if (buffer_.size() < FOOTER_SIZE) {
    LOG(ERROR) << "not big enough to contain footer";
    return false;
  }

  const uint8_t* footer = buffer_.data() + buffer_.size() - FOOTER_SIZE;
  if (footer[2] != 0xff || footer[3] != 0xff) {
    LOG(ERROR) << "footer is wrong";
    return false;
  }

  size_t comment_size = footer[4] + (footer[5] << 8);
  size_t signature_start = footer[0] + (footer[1] << 8);
  LOG(INFO) << "comment is " << comment_size << " bytes; signature is " << signature_start
            << " bytes from end";

  if (signature_start > comment_size) {
    LOG(ERROR) << "signature start: " << signature_start
               << " is larger than comment size: " << comment_size;
    return false;
  }

  if (signature_start <= FOOTER_SIZE) {
    LOG(ERROR) << "Signature start is in the footer";
    return false;
  }

#define EOCD_HEADER_SIZE 22

  // The end-of-central-directory record is 22 bytes plus any comment length.
  size_t eocd_size = comment_size + EOCD_HEADER_SIZE;

  if (buffer_.size() < eocd_size) {
    LOG(ERROR) << "not big enough to contain EOCD";
    return false;
  }

  // Determine how much of the file is covered by the signature. This is everything except the
  // signature data and length, which includes all of the EOCD except for the comment length field
  // (2 bytes) and the comment data.
  *signed_len = buffer_.size() - eocd_size + EOCD_HEADER_SIZE - 2;

  signature->assign(buffer_.end() - signature_start,
                    buffer_.end() - FOOTER_SIZE);

  return true;
}

ErrorCode EdifyPerformer::VerifyPayload(
    const brillo::Blob& update_check_response_hash,
    const uint64_t update_check_response_size) {
  string public_key;
  if (!GetPublicKey(&public_key)) {
    LOG(ERROR) << "Failed to get public key.";
    return ErrorCode::kDownloadPayloadPubKeyVerificationError;
  }

  // Verifies the download size.
  if (update_check_response_size != total_bytes_received_) {
    LOG(ERROR) << "update_check_response_size (" << update_check_response_size
               << ") doesn't match payload size (" << payload_->size << ").";
    return ErrorCode::kPayloadSizeMismatchError;
  }

  // OTA zip files do not have a hash, so ignore update_check_response_hash

  // Verifies the signed payload hash.
  if (public_key.empty()) {
    LOG(WARNING) << "Not verifying signed delta payload -- missing public key.";
    if (!DoUpdate()) {
      LOG(ERROR) << "VerifyPayload: update failed";
      return ErrorCode::kError;
    }
    return ErrorCode::kSuccess;
  }

  brillo::Blob signature;
  uint64_t signed_len;
  if (!GetSignature(&signature, &signed_len)) {
    LOG(ERROR) << "Failed to get payload signature.";
    return ErrorCode::kDownloadPayloadPubKeyVerificationError;
  }

  HashCalculator signed_hash_calculator;
  signed_hash_calculator.Update(buffer_.data(), signed_len);
  signed_hash_calculator.Finalize();

  brillo::Blob hash_data = signed_hash_calculator.raw_hash();
  if (signature.size() != kSHA256Size) {
    LOG(ERROR) << "VerifyPayload: signature size " << signature.size() << " != " << kSHA256Size;
//XXX    return ErrorCode::kDownloadPayloadPubKeyVerificationError;
  }

  std::string sig_str;
  sig_str.assign(signature.begin(), signature.end());

  if (!PayloadVerifier::VerifySignature(sig_str, public_key, hash_data)) {
    // The autoupdate_CatchBadSignatures test checks for this string
    // in log-files. Keep in sync.
    LOG(ERROR) << "Public key verification failed, thus update failed.";
//XXX    return ErrorCode::kDownloadPayloadPubKeyVerificationError;
  }

  if (!DoUpdate()) {
    LOG(ERROR) << "VerifyPayload: update failed";
    return ErrorCode::kError;
  }

  return ErrorCode::kSuccess;
}

static constexpr const char* SCRIPT_NAME = "META-INF/com/google/android/updater-script";
static constexpr int kRecoveryApiVersion = 3;

bool EdifyPerformer::DoUpdate() {
  bool ret = false;

  ZipArchiveHandle za;
  ret = OpenArchiveFromMemory(buffer_.data(), buffer_.size(), "update.zip", &za);
  if (ret != 0) {
    LOG(ERROR) << "failed to open package: " << ErrorCodeString(ret);
    CloseArchive(za);
    return false;
  }

  ZipString script_name(SCRIPT_NAME);
  ZipEntry script_entry;
  ret = FindEntry(za, script_name, &script_entry);
  if (ret != 0) {
    LOG(ERROR) << "failed to find " << SCRIPT_NAME << " in update package: "
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

  SetFsUpdaterRoot("", "/mnt/updater");
  SetFsUpdaterMountContext("u:object_r:mnt_updater_file:s0");
  SetFsUpdaterMode(kFsUpdaterModeLenient);

  // Parse the script
  std::unique_ptr<Expr> root;
  int error_count = 0;
  int error = ParseString(script.c_str(), &root, &error_count);
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

bool EdifyPerformer::CheckpointUpdateProgress(bool force) {
  base::TimeTicks curr_time = base::TimeTicks::Now();
  if (force || curr_time > update_checkpoint_time_) {
    update_checkpoint_time_ = curr_time + update_checkpoint_wait_;
  } else {
    return false;
  }

  Terminator::set_exit_blocked(true);
  if (last_updated_buffer_offset_ != buffer_offset_) {
    // Resets the progress in case we die in the middle of the state update.
    ResetUpdateProgress(prefs_, true);
    TEST_AND_RETURN_FALSE(
        prefs_->SetInt64(kPrefsUpdateStateNextDataOffset, buffer_offset_));
    last_updated_buffer_offset_ = buffer_offset_;

  }
  return true;
}

}  // namespace chromeos_update_engine
