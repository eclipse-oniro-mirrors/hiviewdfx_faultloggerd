/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DFX_ARK_H
#define DFX_ARK_H

#include <cstdint>
#include <mutex>
#include <string>

namespace OHOS {
namespace HiviewDFX {
class DfxArk {
public:
    static int StepArkManagedNativeFrame(int pid, uintptr_t* pc, uintptr_t* fp, uintptr_t* sp, char* buf, size_t bufSize);
    static int GetArkJsHeapCrashInfo(int pid, uintptr_t* x20, uintptr_t* fp, int outJsInfo, char* buf, size_t bufSize);
private:
    static void* handle_;
    static std::mutex mutex_;
};
} // namespace HiviewDFX
} // namespace OHOS

#endif
