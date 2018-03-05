//
// Copyright (C) 2016 The Android Open Source Project
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

#include "update_engine/update_attempter_android.h"

#include <algorithm>
#include <map>
#include <utility>

#include <base/bind.h>
#include <base/logging.h>
#include <base/strings/string_number_conversions.h>
#include <brillo/bind_lambda.h>
#include <brillo/data_encoding.h>
#include <brillo/message_loops/message_loop.h>
#include <brillo/strings/string_utils.h>
#include <log/log.h>

#include "update_engine/common/constants.h"
#include "update_engine/common/file_fetcher.h"
#include "update_engine/common/utils.h"
#include "update_engine/daemon_state_interface.h"
#include "update_engine/network_selector.h"
#include "update_engine/payload_consumer/download_action.h"
#include "update_engine/payload_consumer/filesystem_verifier_action.h"
#include "update_engine/payload_consumer/postinstall_runner_action.h"
#include "update_engine/update_status_utils.h"

#ifndef _UE_SIDELOAD
// Do not include support for external HTTP(s) urls when building
// update_engine_sideload.
#include "update_engine/libcurl_http_fetcher.h"
#endif

using base::Bind;
using base::TimeDelta;
using base::TimeTicks;
using std::shared_ptr;
using std::string;
using std::vector;

namespace chromeos_update_engine {

namespace {

// Minimum threshold to broadcast an status update in progress and time.
const double kBroadcastThresholdProgress = 0.01;  // 1%
const int kBroadcastThresholdSeconds = 10;

const char* const kErrorDomain = "update_engine";
// TODO(deymo): Convert the different errors to a numeric value to report them
// back on the service error.
const char* const kGenericError = "generic_error";

// Log and set the error on the passed ErrorPtr.
bool LogAndSetError(brillo::ErrorPtr* error,
                    const tracked_objects::Location& location,
                    const string& reason) {
  brillo::Error::AddTo(error, location, kErrorDomain, kGenericError, reason);
  LOG(ERROR) << "Replying with failure: " << location.ToString() << ": "
             << reason;
  return false;
}

}  // namespace

UpdateAttempterAndroid::UpdateAttempterAndroid(
    DaemonStateInterface* daemon_state,
    PrefsInterface* prefs,
    BootControlInterface* boot_control,
    HardwareInterface* hardware)
    : daemon_state_(daemon_state),
      prefs_(prefs),
      boot_control_(boot_control),
      hardware_(hardware),
      processor_(new ActionProcessor()) {
  network_selector_ = network::CreateNetworkSelector();
}

UpdateAttempterAndroid::~UpdateAttempterAndroid() {
  // Release ourselves as the ActionProcessor's delegate to prevent
  // re-scheduling the updates due to the processing stopped.
  processor_->set_delegate(nullptr);
}

void UpdateAttempterAndroid::Init() {
  // In case of update_engine restart without a reboot we need to restore the
  // reboot needed state.
  if (UpdateCompletedOnThisBoot())
    SetStatusAndNotify(UpdateStatus::UPDATED_NEED_REBOOT);
  else
    SetStatusAndNotify(UpdateStatus::IDLE);
}

bool UpdateAttempterAndroid::ApplyPayload(
    const string& payload_url,
    int64_t payload_offset,
    int64_t payload_size,
    const vector<string>& key_value_pair_headers,
    brillo::ErrorPtr* error) {
  if (status_ == UpdateStatus::UPDATED_NEED_REBOOT) {
    return LogAndSetError(
        error, FROM_HERE, "An update already applied, waiting for reboot");
  }
  if (ongoing_update_) {
    return LogAndSetError(
        error, FROM_HERE, "Already processing an update, cancel it first.");
  }
  DCHECK(status_ == UpdateStatus::IDLE);

  std::map<string, string> headers;
  for (const string& key_value_pair : key_value_pair_headers) {
    string key;
    string value;
    if (!brillo::string_utils::SplitAtFirst(
            key_value_pair, "=", &key, &value, false)) {
      return LogAndSetError(
          error, FROM_HERE, "Passed invalid header: " + key_value_pair);
    }
    if (!headers.emplace(key, value).second)
      return LogAndSetError(error, FROM_HERE, "Passed repeated key: " + key);
  }

  // Unique identifier for the payload. An empty string means that the payload
  // can't be resumed.
  string payload_id = (headers[kPayloadPropertyFileHash] +
                       headers[kPayloadPropertyMetadataHash]);

  // Setup the InstallPlan based on the request.
  install_plan_ = InstallPlan();

  install_plan_.download_url = payload_url;
  install_plan_.version = "";
  base_offset_ = payload_offset;
  InstallPlan::Payload payload;
  payload.size = payload_size;
  if (!payload.size) {
    if (!base::StringToUint64(headers[kPayloadPropertyFileSize],
                              &payload.size)) {
      payload.size = 0;
    }
  }
  if (!brillo::data_encoding::Base64Decode(headers[kPayloadPropertyFileHash],
                                           &payload.hash)) {
    LOG(WARNING) << "Unable to decode base64 file hash: "
                 << headers[kPayloadPropertyFileHash];
  }
  if (!base::StringToUint64(headers[kPayloadPropertyMetadataSize],
                            &payload.metadata_size)) {
    payload.metadata_size = 0;
  }
  // The |payload.type| is not used anymore since minor_version 3.
  payload.type = InstallPayloadType::kUnknown;
  install_plan_.payloads.push_back(payload);

  // The |public_key_rsa| key would override the public key stored on disk.
  install_plan_.public_key_rsa = "";

  install_plan_.hash_checks_mandatory = hardware_->IsOfficialBuild();
  install_plan_.is_resume = !payload_id.empty() &&
                            DeltaPerformer::CanResumeUpdate(prefs_, payload_id);
  if (!install_plan_.is_resume) {
    if (!DeltaPerformer::ResetUpdateProgress(prefs_, false)) {
      LOG(WARNING) << "Unable to reset the update progress.";
    }
    if (!prefs_->SetString(kPrefsUpdateCheckResponseHash, payload_id)) {
      LOG(WARNING) << "Unable to save the update check response hash.";
    }
  }
  install_plan_.source_slot = boot_control_->GetCurrentSlot();
  install_plan_.target_slot = install_plan_.source_slot == 0 ? 1 : 0;

  int data_wipe = 0;
  install_plan_.powerwash_required =
      base::StringToInt(headers[kPayloadPropertyPowerwash], &data_wipe) &&
      data_wipe != 0;

  NetworkId network_id = kDefaultNetworkId;
  if (!headers[kPayloadPropertyNetworkId].empty()) {
    if (!base::StringToUint64(headers[kPayloadPropertyNetworkId],
                              &network_id)) {
      return LogAndSetError(
          error,
          FROM_HERE,
          "Invalid network_id: " + headers[kPayloadPropertyNetworkId]);
    }
    if (!network_selector_->SetProcessNetwork(network_id)) {
      return LogAndSetError(
          error,
          FROM_HERE,
          "Unable to set network_id: " + headers[kPayloadPropertyNetworkId]);
    }
  }

  LOG(INFO) << "Using this install plan:";
  install_plan_.Dump();

  BuildUpdateActions(payload_url);
  // Setup extra headers.
  HttpFetcher* fetcher = download_action_->http_fetcher();
  if (!headers[kPayloadPropertyAuthorization].empty())
    fetcher->SetHeader("Authorization", headers[kPayloadPropertyAuthorization]);
  if (!headers[kPayloadPropertyUserAgent].empty())
    fetcher->SetHeader("User-Agent", headers[kPayloadPropertyUserAgent]);

  SetStatusAndNotify(UpdateStatus::UPDATE_AVAILABLE);
  ongoing_update_ = true;

  // Just in case we didn't update boot flags yet, make sure they're updated
  // before any update processing starts. This will start the update process.
  UpdateBootFlags();
  return true;
}

bool UpdateAttempterAndroid::SuspendUpdate(brillo::ErrorPtr* error) {
  if (!ongoing_update_)
    return LogAndSetError(error, FROM_HERE, "No ongoing update to suspend.");
  processor_->SuspendProcessing();
  return true;
}

bool UpdateAttempterAndroid::ResumeUpdate(brillo::ErrorPtr* error) {
  if (!ongoing_update_)
    return LogAndSetError(error, FROM_HERE, "No ongoing update to resume.");
  processor_->ResumeProcessing();
  return true;
}

bool UpdateAttempterAndroid::CancelUpdate(brillo::ErrorPtr* error) {
  if (!ongoing_update_)
    return LogAndSetError(error, FROM_HERE, "No ongoing update to cancel.");
  processor_->StopProcessing();
  return true;
}

bool UpdateAttempterAndroid::ResetStatus(brillo::ErrorPtr* error) {
  LOG(INFO) << "Attempting to reset state from "
            << UpdateStatusToString(status_) << " to UpdateStatus::IDLE";

  switch (status_) {
    case UpdateStatus::IDLE:
      return true;

    case UpdateStatus::UPDATED_NEED_REBOOT:  {
      // Remove the reboot marker so that if the machine is rebooted
      // after resetting to idle state, it doesn't go back to
      // UpdateStatus::UPDATED_NEED_REBOOT state.
      bool ret_value = prefs_->Delete(kPrefsUpdateCompletedOnBootId);

      // Update the boot flags so the current slot has higher priority.
      if (!boot_control_->SetActiveBootSlot(boot_control_->GetCurrentSlot()))
        ret_value = false;

      // Mark the current slot as successful again, since marking it as active
      // may reset the successful bit. We ignore the result of whether marking
      // the current slot as successful worked.
      if (!boot_control_->MarkBootSuccessfulAsync(Bind([](bool successful){})))
        ret_value = false;

      if (!ret_value) {
        return LogAndSetError(
            error,
            FROM_HERE,
            "Failed to reset the status to ");
      }

      SetStatusAndNotify(UpdateStatus::IDLE);
      LOG(INFO) << "Reset status successful";
      return true;
    }

    default:
      return LogAndSetError(
          error,
          FROM_HERE,
          "Reset not allowed in this state. Cancel the ongoing update first");
  }
}

void UpdateAttempterAndroid::ProcessingDone(const ActionProcessor* processor,
                                            ErrorCode code) {
  LOG(INFO) << "Processing Done.";

  switch (code) {
    case ErrorCode::kSuccess:
      // Update succeeded.
      WriteUpdateCompletedMarker();
      prefs_->SetInt64(kPrefsDeltaUpdateFailures, 0);
      DeltaPerformer::ResetUpdateProgress(prefs_, false);

      LOG(INFO) << "Update successfully applied, waiting to reboot.";
      break;

    case ErrorCode::kFilesystemCopierError:
    case ErrorCode::kNewRootfsVerificationError:
    case ErrorCode::kNewKernelVerificationError:
    case ErrorCode::kFilesystemVerifierError:
    case ErrorCode::kDownloadStateInitializationError:
      // Reset the ongoing update for these errors so it starts from the
      // beginning next time.
      DeltaPerformer::ResetUpdateProgress(prefs_, false);
      LOG(INFO) << "Resetting update progress.";
      break;

    case ErrorCode::kPayloadTimestampError:
      // SafetyNet logging, b/36232423
      android_errorWriteLog(0x534e4554, "36232423");
      break;

    default:
      // Ignore all other error codes.
      break;
  }

  TerminateUpdateAndNotify(code);
}

void UpdateAttempterAndroid::ProcessingStopped(
    const ActionProcessor* processor) {
  TerminateUpdateAndNotify(ErrorCode::kUserCanceled);
}

void UpdateAttempterAndroid::ActionCompleted(ActionProcessor* processor,
                                             AbstractAction* action,
                                             ErrorCode code) {
  // Reset download progress regardless of whether or not the download
  // action succeeded.
  const string type = action->Type();
  if (type == DownloadAction::StaticType()) {
    download_progress_ = 0;
  }
  if (code != ErrorCode::kSuccess) {
    // If an action failed, the ActionProcessor will cancel the whole thing.
    return;
  }
  if (type == DownloadAction::StaticType()) {
    SetStatusAndNotify(UpdateStatus::FINALIZING);
  }
}

void UpdateAttempterAndroid::BytesReceived(uint64_t bytes_progressed,
                                           uint64_t bytes_received,
                                           uint64_t total) {
  double progress = 0;
  if (total)
    progress = static_cast<double>(bytes_received) / static_cast<double>(total);
  if (status_ != UpdateStatus::DOWNLOADING || bytes_received == total) {
    download_progress_ = progress;
    SetStatusAndNotify(UpdateStatus::DOWNLOADING);
  } else {
    ProgressUpdate(progress);
  }
}

bool UpdateAttempterAndroid::ShouldCancel(ErrorCode* cancel_reason) {
  // TODO(deymo): Notify the DownloadAction that it should cancel the update
  // download.
  return false;
}

void UpdateAttempterAndroid::DownloadComplete() {
  // Nothing needs to be done when the download completes.
}

void UpdateAttempterAndroid::ProgressUpdate(double progress) {
  // Self throttle based on progress. Also send notifications if progress is
  // too slow.
  if (progress == 1.0 ||
      progress - download_progress_ >= kBroadcastThresholdProgress ||
      TimeTicks::Now() - last_notify_time_ >=
          TimeDelta::FromSeconds(kBroadcastThresholdSeconds)) {
    download_progress_ = progress;
    SetStatusAndNotify(status_);
  }
}

void UpdateAttempterAndroid::UpdateBootFlags() {
  if (updated_boot_flags_) {
    LOG(INFO) << "Already updated boot flags. Skipping.";
    CompleteUpdateBootFlags(true);
    return;
  }
  // This is purely best effort.
  LOG(INFO) << "Marking booted slot as good.";
  if (!boot_control_->MarkBootSuccessfulAsync(
          Bind(&UpdateAttempterAndroid::CompleteUpdateBootFlags,
               base::Unretained(this)))) {
    LOG(ERROR) << "Failed to mark current boot as successful.";
    CompleteUpdateBootFlags(false);
  }
}

void UpdateAttempterAndroid::CompleteUpdateBootFlags(bool successful) {
  updated_boot_flags_ = true;
  ScheduleProcessingStart();
}

void UpdateAttempterAndroid::ScheduleProcessingStart() {
  LOG(INFO) << "Scheduling an action processor start.";
  brillo::MessageLoop::current()->PostTask(
      FROM_HERE,
      Bind([](ActionProcessor* processor) { processor->StartProcessing(); },
           base::Unretained(processor_.get())));
}

void UpdateAttempterAndroid::TerminateUpdateAndNotify(ErrorCode error_code) {
  if (status_ == UpdateStatus::IDLE) {
    LOG(ERROR) << "No ongoing update, but TerminatedUpdate() called.";
    return;
  }

  download_progress_ = 0;
  actions_.clear();
  UpdateStatus new_status =
      (error_code == ErrorCode::kSuccess ? UpdateStatus::UPDATED_NEED_REBOOT
                                         : UpdateStatus::IDLE);
  SetStatusAndNotify(new_status);
  ongoing_update_ = false;

  for (auto observer : daemon_state_->service_observers())
    observer->SendPayloadApplicationComplete(error_code);
}

void UpdateAttempterAndroid::SetStatusAndNotify(UpdateStatus status) {
  status_ = status;
  size_t payload_size =
      install_plan_.payloads.empty() ? 0 : install_plan_.payloads[0].size;
  for (auto observer : daemon_state_->service_observers()) {
    observer->SendStatusUpdate(
        0, download_progress_, status_, "", payload_size);
  }
  last_notify_time_ = TimeTicks::Now();
}

void UpdateAttempterAndroid::BuildUpdateActions(const string& url) {
  CHECK(!processor_->IsRunning());
  processor_->set_delegate(this);

  // Actions:
  shared_ptr<InstallPlanAction> install_plan_action(
      new InstallPlanAction(install_plan_));

  HttpFetcher* download_fetcher = nullptr;
  if (FileFetcher::SupportedUrl(url)) {
    DLOG(INFO) << "Using FileFetcher for file URL.";
    download_fetcher = new FileFetcher();
  } else {
#ifdef _UE_SIDELOAD
    LOG(FATAL) << "Unsupported sideload URI: " << url;
#else
    LibcurlHttpFetcher* libcurl_fetcher =
        new LibcurlHttpFetcher(&proxy_resolver_, hardware_);
    libcurl_fetcher->set_server_to_check(ServerToCheck::kDownload);
    download_fetcher = libcurl_fetcher;
#endif  // _UE_SIDELOAD
  }
  shared_ptr<DownloadAction> download_action(
      new DownloadAction(prefs_,
                         boot_control_,
                         hardware_,
                         nullptr,             // system_state, not used.
                         download_fetcher));  // passes ownership
  shared_ptr<FilesystemVerifierAction> filesystem_verifier_action(
      new FilesystemVerifierAction());

  shared_ptr<PostinstallRunnerAction> postinstall_runner_action(
      new PostinstallRunnerAction(boot_control_, hardware_));

  download_action->set_delegate(this);
  download_action->set_base_offset(base_offset_);
  download_action_ = download_action;
  postinstall_runner_action->set_delegate(this);

  actions_.push_back(shared_ptr<AbstractAction>(install_plan_action));
  actions_.push_back(shared_ptr<AbstractAction>(download_action));
  actions_.push_back(shared_ptr<AbstractAction>(filesystem_verifier_action));
  actions_.push_back(shared_ptr<AbstractAction>(postinstall_runner_action));

  // Bond them together. We have to use the leaf-types when calling
  // BondActions().
  BondActions(install_plan_action.get(), download_action.get());
  BondActions(download_action.get(), filesystem_verifier_action.get());
  BondActions(filesystem_verifier_action.get(),
              postinstall_runner_action.get());

  // Enqueue the actions.
  for (const shared_ptr<AbstractAction>& action : actions_)
    processor_->EnqueueAction(action.get());
}

bool UpdateAttempterAndroid::WriteUpdateCompletedMarker() {
  string boot_id;
  TEST_AND_RETURN_FALSE(utils::GetBootId(&boot_id));
  prefs_->SetString(kPrefsUpdateCompletedOnBootId, boot_id);
  return true;
}

bool UpdateAttempterAndroid::UpdateCompletedOnThisBoot() {
  // In case of an update_engine restart without a reboot, we stored the boot_id
  // when the update was completed by setting a pref, so we can check whether
  // the last update was on this boot or a previous one.
  string boot_id;
  TEST_AND_RETURN_FALSE(utils::GetBootId(&boot_id));

  string update_completed_on_boot_id;
  return (prefs_->Exists(kPrefsUpdateCompletedOnBootId) &&
          prefs_->GetString(kPrefsUpdateCompletedOnBootId,
                            &update_completed_on_boot_id) &&
          update_completed_on_boot_id == boot_id);
}

}  // namespace chromeos_update_engine
