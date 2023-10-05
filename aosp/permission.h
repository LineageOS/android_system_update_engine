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

#ifndef UPDATE_ENGINE_COMMON_PERMISSION_H_
#define UPDATE_ENGINE_COMMON_PERMISSION_H_

#include <binder/Status.h>
#include <binderwrapper/binder_wrapper.h>
#ifdef __ANDROID__
#include <array>
#include <private/android_filesystem_config.h>
#include <algorithm>

namespace chromeos_update_engine {
static constexpr std::array<uid_t, 2> kAllowedUids = {AID_ROOT, AID_SYSTEM};

template <typename Container, typename T>
bool Contains(const Container& container, const T& t) {
  return std::find(container.begin(), container.end(), t) != container.end();
}

android::binder::Status CheckCallingUid();

}  // namespace chromeos_update_engine
#endif  // __ANDROID__

#endif  // UPDATE_ENGINE_COMMON_PERMISSION_H_
