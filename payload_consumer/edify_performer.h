//
// Copyright (C) 2010 The Android Open Source Project
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

#ifndef UPDATE_ENGINE_PAYLOAD_CONSUMER_EDIFY_PERFORMER_H_
#define UPDATE_ENGINE_PAYLOAD_CONSUMER_EDIFY_PERFORMER_H_

#include <inttypes.h>

#include <limits>
#include <string>
#include <vector>

#include <base/time/time.h>
#include <brillo/secure_blob.h>
#include <google/protobuf/repeated_field.h>
#include <gtest/gtest_prod.h>  // for FRIEND_TEST

#include "update_engine/common/hash_calculator.h"
#include "update_engine/common/platform_constants.h"
#include "update_engine/payload_consumer/file_descriptor.h"
#include "update_engine/payload_consumer/file_writer.h"
#include "update_engine/payload_consumer/install_plan.h"
#include "update_engine/payload_consumer/payload_metadata.h"
#include "update_engine/payload_consumer/update_performer.h"
#include "update_engine/update_metadata.pb.h"

namespace chromeos_update_engine {

class DownloadActionDelegate;
class BootControlInterface;
class HardwareInterface;
class PrefsInterface;

// This class performs the actions in a edify update synchronously. The edify
// update itself should be passed in in chunks as it is received.

class EdifyPerformer : public UpdatePerformer {
 public:
  // Defines the granularity of progress logging in terms of how many "completed
  // chunks" we want to report at the most.
  static const unsigned kProgressLogMaxChunks;
  // Defines a timeout since the last progress was logged after which we want to
  // force another log message (even if the current chunk was not completed).
  static const unsigned kProgressLogTimeoutSeconds;
  // These define the relative weights (0-100) we give to the different work
  // components associated with an update when computing an overall progress.
  // Currently they include the download progress and the number of completed
  // operations. They must add up to one hundred (100).
  static const unsigned kProgressDownloadWeight;
  static const unsigned kProgressOperationsWeight;
  static const uint64_t kCheckpointFrequencySeconds;

  EdifyPerformer(PrefsInterface* prefs,
                 BootControlInterface* boot_control,
                 HardwareInterface* hardware,
                 DownloadActionDelegate* download_delegate,
                 InstallPlan* install_plan,
                 InstallPlan::Payload* payload,
                 bool interactive)
      : prefs_(prefs),
        boot_control_(boot_control),
        hardware_(hardware),
        download_delegate_(download_delegate),
        install_plan_(install_plan),
        payload_(payload),
        interactive_(interactive) {}

  virtual ~EdifyPerformer() {}

  // FileWriter's Write implementation where caller doesn't care about
  // error codes.
  bool Write(const void* bytes, size_t count) override {
    ErrorCode error;
    return Write(bytes, count, &error);
  }

  // FileWriter's Write implementation that returns a more specific |error| code
  // in case of failures in Write operation.
  bool Write(const void* bytes, size_t count, ErrorCode* error) override;

  // Wrapper around close. Returns 0 on success or -errno on error.
  // Closes both 'path' given to Open() and the kernel path.
  int Close() override;

  // Returns |true| only if the update can be shared.
  bool CanShare() override;

  // Verifies the downloaded payload against the signed hash included in the
  // payload, against the update check hash and size using the public key and
  // returns ErrorCode::kSuccess on success, an error code on failure.
  // This method should be called after closing the stream. Note this method
  // skips the signed hash check if the public key is unavailable; it returns
  // ErrorCode::kSignedDeltaPayloadExpectedError if the public key is available
  // but the delta payload doesn't include a signature.
  ErrorCode VerifyPayload(const brillo::Blob& update_check_response_hash,
                          const uint64_t update_check_response_size) override;

 private:

  bool DoUpdate();

  // Logs the progress of downloading/applying an update.
  void LogProgress(const char* message_prefix);

  // Update overall progress metrics, log as necessary.
  void UpdateOverallProgress(bool force_log, const char* message_prefix);

  // Checkpoints the update progress into persistent storage to allow this
  // update attempt to be resumed after reboot.
  // If |force| is false, checkpoint may be throttled.
  bool CheckpointUpdateProgress(bool force);

  // Primes the required update state. Returns true if the update state was
  // successfully initialized to a saved resume state or if the update is a new
  // update. Returns false otherwise.
  bool PrimeUpdateState();

  // Get the public key to be used to verify metadata signature or payload
  // signature. Always use |public_key_path_| if exists, otherwise if the Omaha
  // response contains a public RSA key and we're allowed to use it (e.g. if
  // we're in developer mode), decode the key from the response and store it in
  // |out_public_key|. Returns false on failures.
  bool GetPublicKey(std::string* out_public_key);

  // Get the offset of the signature in the payload and the length of
  // data that was signed.
  // See bootable/recovery/install/verifier.cpp for details.
  bool GetSignature(brillo::Blob* signature, size_t* signed_len);

  // Get the signature from the payload.
  // Also see bootable/recovery/install/verifier.cpp@verify_file()
  bool GetPayloadSignature(std::string* signature);

  // Update Engine preference store.
  PrefsInterface* prefs_;

  // BootControl and Hardware interface references.
  BootControlInterface* boot_control_;
  HardwareInterface* hardware_;

  // The DownloadActionDelegate instance monitoring the DownloadAction, or a
  // nullptr if not used.
  DownloadActionDelegate* download_delegate_;

  // Install Plan based on Omaha Response.
  InstallPlan* install_plan_;

  // Pointer to the current payload in install_plan_.payloads.
  InstallPlan::Payload* payload_{nullptr};

  // A buffer used for accumulating downloaded data. Initially, it stores the
  // payload metadata; once that's downloaded and parsed, it stores data for the
  // next update operation.
  brillo::Blob buffer_;
  // Offset of buffer_ in the binary blobs section of the update.
  uint64_t buffer_offset_{0};

  // Last |buffer_offset_| value updated as part of the progress update.
  uint64_t last_updated_buffer_offset_{std::numeric_limits<uint64_t>::max()};

  // Calculates the whole payload file hash, including headers and signatures.
  HashCalculator payload_hash_calculator_;

  // The public key to be used. Provided as a member so that tests can
  // override with test keys.
  std::string public_key_path_{constants::kUpdatePayloadPublicKeyPath};

  // The number of bytes received so far, used for progress tracking.
  size_t total_bytes_received_{0};

  // An overall progress counter, which should reflect both download progress
  // and the ratio of applied operations. Range is 0-100.
  unsigned overall_progress_{0};

  // If |true|, the update is user initiated (vs. periodic update checks).
  bool interactive_{false};

  // The timeout after which we should force emitting a progress log (constant),
  // and the actual point in time for the next forced log to be emitted.
  const base::TimeDelta forced_progress_log_wait_{
      base::TimeDelta::FromSeconds(kProgressLogTimeoutSeconds)};
  base::TimeTicks forced_progress_log_time_;

  // The frequency that we should write an update checkpoint (constant), and
  // the point in time at which the next checkpoint should be written.
  const base::TimeDelta update_checkpoint_wait_{
      base::TimeDelta::FromSeconds(kCheckpointFrequencySeconds)};
  base::TimeTicks update_checkpoint_time_;

  DISALLOW_COPY_AND_ASSIGN(EdifyPerformer);
};

}  // namespace chromeos_update_engine

#endif  // UPDATE_ENGINE_PAYLOAD_CONSUMER_EDIFY_PERFORMER_H_
