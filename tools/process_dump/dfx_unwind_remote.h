/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#ifndef DFX_UNWIND_REMOTE_H
#define DFX_UNWIND_REMOTE_H

#ifdef __clang__
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Wextern-c-compat"
#endif

#include <map>
#include <memory>

#include "dfx_define.h"
#include "dfx_dump_request.h"
#include "dfx_process.h"
#include "nocopyable.h"
#include "unwinder.h"

namespace OHOS {
namespace HiviewDFX {
class DfxUnwindRemote final {
public:
    static DfxUnwindRemote &GetInstance();
    ~DfxUnwindRemote() = default;

    bool UnwindProcess(const ProcessDumpRequest& request, DfxProcess& process, Unwinder& unwinder, pid_t vmPid = 0);
    bool InitProcessAllThreadRegs(const ProcessDumpRequest& request, DfxProcess& process);
    static void ParseSymbol(const ProcessDumpRequest& request, DfxProcess& process, Unwinder& unwinder);
    static void PrintUnwindResultInfo(const ProcessDumpRequest& request, DfxProcess& process,
        Unwinder& unwinder, pid_t vmPid);
private:
    DfxUnwindRemote() = default;
    bool UnwindKeyThread(const ProcessDumpRequest& request, DfxProcess& process, Unwinder& unwinder, pid_t vmPid = 0);
    int UnwindOtherThread(DfxProcess& process, Unwinder& unwinder, pid_t vmPid = 0);

    DISALLOW_COPY_AND_MOVE(DfxUnwindRemote);
    static bool InitTargetKeyThreadRegs(const ProcessDumpRequest& request, DfxProcess& process);
    void InitOtherThreadRegs(DfxProcess& process);
    bool isVmProcAttach = false;
};
}   // namespace HiviewDFX
}   // namespace OHOS

#endif  // DFX_UNWIND_REMOTE_H
