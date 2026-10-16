/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef DFX_BINDER_RECORD_H
#define DFX_BINDER_RECORD_H

#include <string>
#include <vector>

#include <sys/types.h>

namespace OHOS {
namespace HiviewDFX {
struct BinderRecord {
    bool isSync = false;
    int pid = -1;
    int nsPid = -1;
    int tid = -1;
    int nsTid = -1;
    std::string cmdLine;
};
std::vector<BinderRecord> ParseSyncBinderProcInfo(pid_t pid, pid_t tid);

BinderRecord ParseAsyncBinderProcInfo(pid_t callerPid);
}
}

#endif
