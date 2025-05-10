/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef DFX_PROCESS_H
#define DFX_PROCESS_H

#include <cinttypes>
#include <map>
#include <memory>
#include <set>
#include <string>

#include "dfx_dump_request.h"
#include "dfx_regs.h"
#include "dfx_thread.h"

namespace OHOS {
namespace HiviewDFX {
struct DfxProcessInfo {
    pid_t pid = 0;
    pid_t nsPid = 0;
    uid_t uid = 0;
    std::string processName = "";
};
struct CrashLogConfig {
    bool enabledCrashLogConfig = false;
    bool extendPcLrPrinting = false;
    bool simplifyVmaPrinting = false;
    uint32_t logFileCutoffSizeBytes = 0;
};
class DfxProcess final {
public:
    void InitProcessInfo(pid_t pid, pid_t nsPid, uid_t uid, const std::string& processName);
    void Attach(bool hasKey = false);
    void Detach();
    bool InitKeyThread(const ProcessDumpRequest& request);
    bool InitOtherThreads(pid_t requestTid);
    std::vector<std::shared_ptr<DfxThread>>& GetOtherThreads();
    std::shared_ptr<DfxThread>& GetKeyThread()
    {
        return keyThread_;
    }

    const DfxProcessInfo& GetProcessInfo() const
    {
        return processInfo_;
    }

    void SetFaultThreadRegisters(std::shared_ptr<DfxRegs> regs)
    {
        regs_ = regs;
    }

    const std::shared_ptr<DfxRegs>& GetFaultThreadRegisters() const
    {
        return regs_;
    }

    void SetReason(const std::string& reason)
    {
        reason_ = reason;
    }

    const std::string& GetReason() const
    {
        return reason_;
    }

    const std::string& GetCrashInfoJson() const
    {
        return crashInfoJson_;
    }

    void SetCrashInfoJson(const std::string& crashInfoJson)
    {
        crashInfoJson_ = crashInfoJson;
    }

    void SetVmPid(pid_t pid)
    {
        vmPid_ = pid;
    }

    pid_t GetVmPid() const
    {
        return vmPid_;
    }

    const CrashLogConfig& GetCrashLogConfig()
    {
        return crashLogConfig_;
    }

    void SetCrashLogConfig(const CrashLogConfig& crashLogConfig)
    {
        crashLogConfig_ = crashLogConfig;
    }

    const std::vector<uintptr_t>& GetStackValues()
    {
        return stackValues_;
    }

    void SetStackValues(const std::vector<uintptr_t>& stackValues)
    {
        stackValues_ = stackValues;
    }
    
    void ClearOtherThreads();
    pid_t ChangeTid(pid_t tid, bool ns);

    void AppendFatalMessage(const std::string &msg);
    const std::string& GetFatalMessage() const;
    std::string GetProcessLifeCycle();
private:
    DfxProcessInfo processInfo_;
    CrashLogConfig crashLogConfig_;
    std::shared_ptr<DfxRegs> regs_;
    std::shared_ptr<DfxThread> keyThread_ = nullptr; // comment: crash thread or dump target thread
    std::vector<std::shared_ptr<DfxThread>> otherThreads_;
    std::string reason_ = "";
    std::string fatalMsg_ = "";
    std::map<int, int> kvThreads_;
    std::string crashInfoJson_ = "";
    pid_t vmPid_ = 0;
    std::vector<uintptr_t> stackValues_;
};
} // namespace HiviewDFX
} // namespace OHOS
#endif
