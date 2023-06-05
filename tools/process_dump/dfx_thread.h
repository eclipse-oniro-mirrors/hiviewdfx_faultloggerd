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

#ifndef DFX_THREAD_H
#define DFX_THREAD_H

#include <cstdint>
#include <string>
#include <sys/types.h>
#include <vector>
#include "dfx_define.h"
#include "dfx_fault_stack.h"
#include "dfx_frame.h"
#include "dfx_maps.h"
#include "dfx_regs.h"

namespace OHOS {
namespace HiviewDFX {
enum class ThreadStatus {
    THREAD_STATUS_INVALID = -1,
    THREAD_STATUS_INIT = 0,
    THREAD_STATUS_ATTACHED = 1
};

struct DfxThreadInfo {
    pid_t pid = 0;
    pid_t tid = 0;
    pid_t nsTid = 0;
    bool isKeyThread = false;
    ThreadStatus threadStatus = ThreadStatus::THREAD_STATUS_INVALID;
    std::string threadName = "";
};

class DfxThread {
public:
    static std::shared_ptr<DfxThread> Create(pid_t pid, pid_t tid, pid_t nsTid);
    DfxThread(pid_t pid, pid_t tid, pid_t nsTid, const ucontext_t &context);
    DfxThread(pid_t pid, pid_t tid, pid_t nsTid);
    ~DfxThread();

    std::shared_ptr<DfxRegs> GetThreadRegs() const;
    void SetThreadRegs(const std::shared_ptr<DfxRegs> &regs);
    void AddFrame(std::shared_ptr<DfxFrame> frame);
    const std::vector<std::shared_ptr<DfxFrame>>& GetFrames() const;
    std::string ToString() const;

    void Detach();
    bool Attach();

    DfxThreadInfo threadInfo_;
private:
    void InitThreadInfo(pid_t pid, pid_t tid, pid_t nsTid);

    std::shared_ptr<DfxRegs> regs_;
    std::vector<std::shared_ptr<DfxFrame>> frames_;
};
} // namespace HiviewDFX
} // namespace OHOS

#endif
