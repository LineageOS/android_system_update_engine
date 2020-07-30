//
// Copyright (C) 2010 The Android Open Source Project
// Copyright (C) 2010 The Android Open Kang Project
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

#ifndef UPDATE_ENGINE_PAYLOAD_CONSUMER_UPDATE_PERFORMER_H_
#define UPDATE_ENGINE_PAYLOAD_CONSUMER_UPDATE_PERFORMER_H_

#include <inttypes.h>

#include <limits>
#include <string>
#include <vector>

#include <base/time/time.h>
#include <brillo/secure_blob.h>

#include "update_engine/common/error_code.h"
#include "update_engine/common/hash_calculator.h"
#include "update_engine/common/platform_constants.h"
#include "update_engine/payload_consumer/file_descriptor.h"
#include "update_engine/payload_consumer/file_writer.h"
#include "update_engine/payload_consumer/install_plan.h"
#include "update_engine/update_metadata.pb.h"

namespace chromeos_update_engine {

class DownloadActionDelegate;
class BootControlInterface;
class HardwareInterface;
class PrefsInterface;

enum UpdateType {
  UT_NONE,
  UT_DELTA,
  UT_LAST
};

// This is the interface for update performer implementations.

class UpdatePerformer : public FileWriter {
 public:
   UpdatePerformer() {}
   virtual ~UpdatePerformer() {}

  static UpdatePerformer* Instance(UpdateType update_type,
                 PrefsInterface* prefs,
                 BootControlInterface* boot_control,
                 HardwareInterface* hardware,
                 DownloadActionDelegate* download_delegate,
                 InstallPlan* install_plan,
                 InstallPlan::Payload* payload,
                 bool is_interactive);

  // Returns |true| only if the manifest has been processed and it's valid.
  virtual bool IsManifestValid() = 0;

  // Verifies the downloaded payload against the signed hash included in the
  // payload, against the update check hash and size using the public key and
  // returns ErrorCode::kSuccess on success, an error code on failure.
  // This method should be called after closing the stream. Note this method
  // skips the signed hash check if the public key is unavailable; it returns
  // ErrorCode::kSignedDeltaPayloadExpectedError if the public key is available
  // but the delta payload doesn't include a signature.
  virtual ErrorCode VerifyPayload(const brillo::Blob& update_check_response_hash,
                          const uint64_t update_check_response_size) = 0;

  // Returns true if a previous update attempt can be continued based on the
  // persistent preferences and the new update check response hash.
  static bool CanResumeUpdate(PrefsInterface* prefs,
                              const std::string& update_check_response_hash);

  // Resets the persistent update progress state to indicate that an update
  // can't be resumed. Performs a quick update-in-progress reset if |quick| is
  // true, otherwise resets all progress-related update state. Returns true on
  // success, false otherwise.
  static bool ResetUpdateProgress(PrefsInterface* prefs, bool quick);

  // Compare |calculated_hash| with source hash in |operation|, return false and
  // dump hash and set |error| if don't match.
  // |source_fd| is the file descriptor of the source partition.
  static bool ValidateSourceHash(const brillo::Blob& calculated_hash,
                                 const InstallOperation& operation,
                                 const FileDescriptorPtr source_fd,
                                 ErrorCode* error);
};

}  // namespace chromeos_update_engine

#endif  // UPDATE_ENGINE_PAYLOAD_CONSUMER_UPDATE_PERFORMER_H_
