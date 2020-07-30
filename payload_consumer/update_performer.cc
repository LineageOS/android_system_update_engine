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

#include "update_engine/payload_consumer/update_performer.h"
#include "update_engine/payload_consumer/delta_performer.h"

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
#include "update_engine/payload_consumer/payload_constants.h"
#include "update_engine/payload_consumer/payload_verifier.h"
#include "update_engine/payload_consumer/xz_extent_writer.h"

using google::protobuf::RepeatedPtrField;
using std::min;
using std::string;
using std::vector;

namespace chromeos_update_engine {

namespace {

const int kUpdateStateOperationInvalid = -1;
const int kMaxResumedUpdateFailures = 10;

}  // namespace

UpdatePerformer* UpdatePerformer::Instance(UpdateType update_type,
    PrefsInterface* prefs,
    BootControlInterface* boot_control,
    HardwareInterface* hardware,
    DownloadActionDelegate* download_delegate,
    InstallPlan* install_plan,
    InstallPlan::Payload* payload,
    bool is_interactive) {
  switch (update_type) {
  case UT_DELTA:
    return new DeltaPerformer(prefs, boot_control, hardware,
                              download_delegate, install_plan,
                              payload, is_interactive);
  default:
    LOG(ERROR) << "Unknown UpdatePerformerType " << (int)update_type;
    return nullptr;
  }
}

bool UpdatePerformer::CanResumeUpdate(PrefsInterface* prefs,
                                     const string& update_check_response_hash) {
  int64_t next_operation = kUpdateStateOperationInvalid;
  if (!(prefs->GetInt64(kPrefsUpdateStateNextOperation, &next_operation) &&
        next_operation != kUpdateStateOperationInvalid &&
        next_operation > 0))
    return false;

  string interrupted_hash;
  if (!(prefs->GetString(kPrefsUpdateCheckResponseHash, &interrupted_hash) &&
        !interrupted_hash.empty() &&
        interrupted_hash == update_check_response_hash))
    return false;

  int64_t resumed_update_failures;
  // Note that storing this value is optional, but if it is there it should not
  // be more than the limit.
  if (prefs->GetInt64(kPrefsResumedUpdateFailures, &resumed_update_failures) &&
      resumed_update_failures > kMaxResumedUpdateFailures)
    return false;

  // Sanity check the rest.
  int64_t next_data_offset = -1;
  if (!(prefs->GetInt64(kPrefsUpdateStateNextDataOffset, &next_data_offset) &&
        next_data_offset >= 0))
    return false;

  string sha256_context;
  if (!(prefs->GetString(kPrefsUpdateStateSHA256Context, &sha256_context) &&
        !sha256_context.empty()))
    return false;

  int64_t manifest_metadata_size = 0;
  if (!(prefs->GetInt64(kPrefsManifestMetadataSize, &manifest_metadata_size) &&
        manifest_metadata_size > 0))
    return false;

  int64_t manifest_signature_size = 0;
  if (!(prefs->GetInt64(kPrefsManifestSignatureSize,
                        &manifest_signature_size) &&
        manifest_signature_size >= 0))
    return false;

  return true;
}

bool UpdatePerformer::ResetUpdateProgress(PrefsInterface* prefs, bool quick) {
  TEST_AND_RETURN_FALSE(prefs->SetInt64(kPrefsUpdateStateNextOperation,
                                        kUpdateStateOperationInvalid));
  if (!quick) {
    prefs->SetInt64(kPrefsUpdateStateNextDataOffset, -1);
    prefs->SetInt64(kPrefsUpdateStateNextDataLength, 0);
    prefs->SetString(kPrefsUpdateStateSHA256Context, "");
    prefs->SetString(kPrefsUpdateStateSignedSHA256Context, "");
    prefs->SetString(kPrefsUpdateStateSignatureBlob, "");
    prefs->SetInt64(kPrefsManifestMetadataSize, -1);
    prefs->SetInt64(kPrefsManifestSignatureSize, -1);
    prefs->SetInt64(kPrefsResumedUpdateFailures, 0);
    prefs->Delete(kPrefsPostInstallSucceeded);
  }
  return true;
}

bool UpdatePerformer::ValidateSourceHash(const brillo::Blob& calculated_hash,
                                        const InstallOperation& operation,
                                        const FileDescriptorPtr source_fd,
                                        ErrorCode* error) {
  brillo::Blob expected_source_hash(operation.src_sha256_hash().begin(),
                                    operation.src_sha256_hash().end());
  if (calculated_hash != expected_source_hash) {
    LOG(ERROR) << "The hash of the source data on disk for this operation "
               << "doesn't match the expected value. This could mean that the "
               << "delta update payload was targeted for another version, or "
               << "that the source partition was modified after it was "
               << "installed, for example, by mounting a filesystem.";
    LOG(ERROR) << "Expected:   sha256|hex = "
               << base::HexEncode(expected_source_hash.data(),
                                  expected_source_hash.size());
    LOG(ERROR) << "Calculated: sha256|hex = "
               << base::HexEncode(calculated_hash.data(),
                                  calculated_hash.size());

    vector<string> source_extents;
    for (const Extent& ext : operation.src_extents()) {
      source_extents.push_back(
          base::StringPrintf("%" PRIu64 ":%" PRIu64,
                             static_cast<uint64_t>(ext.start_block()),
                             static_cast<uint64_t>(ext.num_blocks())));
    }
    LOG(ERROR) << "Operation source (offset:size) in blocks: "
               << base::JoinString(source_extents, ",");

    // Log remount history if this device is an ext4 partition.
    LogMountHistory(source_fd);

    *error = ErrorCode::kDownloadStateInitializationError;
    return false;
  }
  return true;
}

}  // namespace chromeos_update_engine
