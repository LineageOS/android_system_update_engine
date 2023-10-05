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
#include <update_engine/aosp/permission.h>

#include <array>
#include <algorithm>
#include <android-base/stringprintf.h>
#include <android-base/logging.h>

namespace chromeos_update_engine {

android::binder::Status CheckCallingUid() {
  const auto calling_uid = android::BinderWrapper::Get()->GetCallingUid();
  if (!Contains(kAllowedUids, calling_uid)) {
    LOG(ERROR) << "Calling UID " << calling_uid
               << " is not allowed to access update_engine APIs";
    auto message =
        android::base::StringPrintf("UID %d is not allowed", calling_uid);
    return android::binder::Status::fromExceptionCode(
        android::binder::Status::EX_SECURITY,
        android::String8(message.c_str()));
  }
  return android::binder::Status::ok();
}

}  // namespace chromeos_update_engine
