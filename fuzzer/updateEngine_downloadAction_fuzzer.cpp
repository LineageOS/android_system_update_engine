/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <update_engine/common/download_action.h>
#include <update_engine/common/boot_control_stub.h>
#include <update_engine/common/hardware_interface.h>
#include <update_engine/common/http_fetcher.h>
#include <update_engine/common/error_code.h>
#include <update_engine/common/proxy_resolver.h>
#include <update_engine/common/action_processor.h>
#include <string.h>
#include <utils/Log.h>
#include <fuzzer/FuzzedDataProvider.h>

using namespace chromeos_update_engine;
using namespace std;

constexpr size_t kSizeMin = 1;
constexpr size_t kSizeMax = 1000;
constexpr size_t kHashSize = 32;
constexpr size_t kStringMaxLength = 20;
const string kDownloadUrl = "http://fake_url.invalid";
const string kSourcePath = "/dev/zero";
const string kTargetPath = "/dev/null";

class TestPrefsInterface : public PrefsInterface {
 public:
  TestPrefsInterface(FuzzedDataProvider* fdp) : mFdp(fdp) {
    mMetadataSize = mFdp->ConsumeIntegralInRange<int64_t>(kSizeMin, kSizeMax);
    mSignatureSize = mFdp->ConsumeIntegralInRange<int64_t>(kSizeMin, kSizeMax);
  };

  bool GetString(std::string_view key, std::string* value) const {
    if (key == "manifest-bytes") {
      *value = mFdp->ConsumeRandomLengthString(mMetadataSize + mSignatureSize);
      return true;
    }
    *value = "";
    return false;
  };

  bool SetString(std::string_view /*key*/, std::string_view /*value*/) {
    return true;
  };

  bool GetInt64(std::string_view key, int64_t* value) const {
    if (key == "manifest-metadata-size") {
      *value = mMetadataSize;
      return true;
    }
    if (key == "manifest-signature-size") {
      *value = mSignatureSize;
      return true;
    }
    *value = 0;
    return false;
  }

  bool SetInt64(std::string_view /*key*/, const int64_t /*value*/) {
    return true;
  }

  bool GetBoolean(std::string_view /*key*/, bool* value) const {
    *value = true;
    return true;
  }

  bool SetBoolean(std::string_view /*key*/, const bool /*value*/) {
    return true;
  }

  bool Exists(std::string_view /*key*/) const { return true; }

  bool Delete(std::string_view /*key*/) { return true; }

  bool Delete(std::string_view /*pref_key*/,
              const std::vector<std::string>& /*nss*/) {
    return true;
  }

  bool GetSubKeys(std::string_view /*ns*/,
                  std::vector<std::string>* keys) const {
    keys->push_back("");
    return true;
  }

  void AddObserver(std::string_view /*key*/, ObserverInterface* /*observer*/) {}

  void RemoveObserver(std::string_view /*key*/,
                      ObserverInterface* /*observer*/) {}

 private:
  FuzzedDataProvider* mFdp;
  int64_t mMetadataSize;
  int64_t mSignatureSize;
};

class TestHardwareInterface : public HardwareInterface {
 public:
  bool IsOfficialBuild() const { return true; };

  bool IsNormalBootMode() const { return true; };

  bool AreDevFeaturesEnabled() const { return true; };

  bool IsOOBEEnabled() const { return true; };

  bool IsOOBEComplete(base::Time* /*out_time_of_oobe*/) const { return true; };

  string GetHardwareClass() const { return ""; };

  string GetDeviceRequisition() const { return ""; };

  int32_t GetMinKernelKeyVersion() const { return 0; };

  int32_t GetMinFirmwareKeyVersion() const { return 0; };

  int32_t GetMaxFirmwareKeyRollforward() const { return 0; };

  bool SetMaxFirmwareKeyRollforward(int32_t /*firmware_max_rollforward*/) {
    return true;
  };

  bool SetMaxKernelKeyRollforward(int32_t /*kernel_max_rollforward*/) {
    return true;
  };

  int32_t GetPowerwashCount() const { return 0; };

  bool SchedulePowerwash(bool /*save_rollback_data*/) { return true; };

  bool CancelPowerwash() { return true; };

  bool GetNonVolatileDirectory(base::FilePath* path) const {
    base::FilePath local_path(constants::kNonVolatileDirectory);
    *path = local_path;
    return true;
  };

  bool GetPowerwashSafeDirectory(base::FilePath* /*path*/) const {
    return false;
  };

  int64_t GetBuildTimestamp() const { return 0; };

  bool AllowDowngrade() const { return true; };

  bool GetFirstActiveOmahaPingSent() const { return true; };

  bool SetFirstActiveOmahaPingSent() { return true; };

  void SetWarmReset(bool /*warm_reset*/){};

  void SetVbmetaDigestForInactiveSlot(bool /*reset*/){};

  string GetVersionForLogging(const string& /*partition_name*/) const {
    return "";
  };

  ErrorCode IsPartitionUpdateValid(const string& /*partition_name*/,
                                   const string& /*new_version*/) const {
    return ErrorCode::kSuccess;
  };

  const char* GetPartitionMountOptions(const string& /*partition_name*/) const {
    return "";
  };
};

class TestProxyResolver : public ProxyResolver {
 public:
  virtual ~TestProxyResolver() {}

  ProxyRequestId GetProxiesForUrl(const string& /*url*/,
                                  const ProxiesResolvedFn& /*callback*/) {
    return 0;
  };

  bool CancelProxyRequest(ProxyRequestId /*request*/) { return true; };
};

class TestHttpFetcher : public HttpFetcher {
 public:
  TestHttpFetcher(ProxyResolver* proxy_resolver, FuzzedDataProvider* fdp)
      : HttpFetcher(proxy_resolver), mFdp(fdp){};
  virtual ~TestHttpFetcher() {}

  void SetOffset(off_t /*offset*/) {}

  void SetLength(size_t /*length*/) {}
  void UnsetLength() {}

  void BeginTransfer(const string& /*url*/) {
    if (mFdp->remaining_bytes() > 0) {
      size_t maxSize = mFdp->ConsumeIntegralInRange<size_t>(kSizeMin, kSizeMax);
      vector<uint8_t> data = mFdp->ConsumeBytes<uint8_t>(maxSize);
      delegate()->ReceivedBytes(this, data.data(), data.size());
    }
  }

  void TerminateTransfer() {}

  void SetHeader(const string& /*header_name*/,
                 const string& /*header_value*/) {}

  bool GetHeader(const string& /*header_name*/, string* header_value) const {
    *header_value = "";
    return true;
  }

  void Pause() {}

  void Unpause() {}

  void set_idle_seconds(int32_t /*seconds*/) {}
  void set_retry_seconds(int32_t /*seconds*/) {}

  void set_low_speed_limit(int32_t /*low_speed_bps*/,
                           int32_t /*low_speed_sec*/) {}

  void set_connect_timeout(int32_t /*connect_timeout_seconds*/) {}

  void set_max_retry_count(int32_t /*max_retry_count*/) {}

  size_t GetBytesDownloaded() { return 0; }

 private:
  FuzzedDataProvider* mFdp;
};

class TestActionProcessor : public ActionProcessor {
 public:
  void StartProcessing() {}

  void EnqueueAction(unique_ptr<AbstractAction> /*action*/){};

  void ActionComplete(AbstractAction* /*actionptr*/, ErrorCode /*code*/){};
};

class chromeos_update_engine::DownloadActionTest {
 public:
  DownloadActionTest() : mActionPipe(new ActionPipe<InstallPlan>()) {}
  ~DownloadActionTest() { mActionPipe = nullptr; }

  void fuzzDownloadAction(const uint8_t* data, size_t size);

 private:
  shared_ptr<ActionPipe<InstallPlan>> mActionPipe = nullptr;
};

void DownloadActionTest::fuzzDownloadAction(const uint8_t* data, size_t size) {
  FuzzedDataProvider fdp = FuzzedDataProvider(data, size);

  InstallPlan install_plan;
  install_plan.download_url = kDownloadUrl;
  install_plan.version = fdp.ConsumeRandomLengthString(kStringMaxLength);
  install_plan.target_slot = fdp.ConsumeBool() ? 0 : 1;
  install_plan.hash_checks_mandatory = fdp.ConsumeBool();
  InstallPlan::Partition partition;
  partition.name = fdp.ConsumeRandomLengthString(kStringMaxLength);
  partition.source_path = kSourcePath;
  partition.source_size = fdp.ConsumeIntegralInRange(kSizeMin, kSizeMax);
  partition.target_path = kTargetPath;
  partition.target_size = fdp.ConsumeIntegralInRange(kSizeMin, kSizeMax);
  install_plan.partitions.push_back(partition);
  InstallPlan::Payload payload;
  payload.payload_urls.emplace_back(kDownloadUrl);
  payload.size = fdp.ConsumeIntegralInRange(kSizeMin, kSizeMax);
  payload.metadata_size =
      fdp.ConsumeIntegralInRange<uint64_t>(kSizeMin, kSizeMax),
  payload.hash = fdp.ConsumeBytes<uint8_t>(kHashSize),
  payload.already_applied = fdp.ConsumeBool();
  install_plan.payloads.push_back(payload);
  install_plan.is_resume = fdp.ConsumeBool();
  mActionPipe->set_contents(install_plan);

  TestPrefsInterface prefs(&fdp);
  BootControlStub boot_control;
  TestHardwareInterface hardwareInterface;
  TestProxyResolver proxyResolver;
  TestHttpFetcher* httpFetcher = new TestHttpFetcher(&proxyResolver, &fdp);
  bool interactive = fdp.ConsumeBool();
  unique_ptr<DownloadAction> downloadAction = make_unique<DownloadAction>(
      &prefs, &boot_control, &hardwareInterface, httpFetcher, interactive);

  downloadAction->set_in_pipe(mActionPipe);
  TestActionProcessor actionProcessor;
  downloadAction->SetProcessor(&actionProcessor);

  downloadAction->PerformAction();
}
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
  DownloadActionTest downloadActionFuzzer;
  downloadActionFuzzer.fuzzDownloadAction(data, size);
  return 0;
}
