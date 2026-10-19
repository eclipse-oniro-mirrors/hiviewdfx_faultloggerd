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

#include "dump_catcher.h"

#include "dfx_define.h"
#include "dfx_dump_catcher.h"
#include "dfx_json_formatter.h"
#include "dfx_kernel_stack.h"
#include "dfx_log.h"
#include "dfx_ptrace.h"
#include "dump_utils.h"
#include "elapsed_time.h"
#include "file_util.h"
#include "proc_util.h"
#include "procinfo.h"
#include "string_printf.h"
#include "string_util.h"
#include "unwind_context.h"
#include "unwinder.h"
#include "unwinder_config.h"
#ifndef is_ohos_lite
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "if_system_ability_manager.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#endif

namespace OHOS {
namespace HiviewDFX {
namespace {
constexpr int WAIT_GET_KERNEL_STACK_TIMEOUT = 1000;

#ifndef is_ohos_lite
sptr<AppExecFwk::IBundleMgr> GetBundleManager()
{
    auto systemManager = SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (!systemManager) {
        DFXLOGE("Get system ability manager failed");
        return nullptr;
    }
    auto remoteObject = systemManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (!remoteObject) {
        DFXLOGE("Get system ability failed");
        return nullptr;
    }
    sptr<AppExecFwk::IBundleMgr> bundleMgrProxy = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    return bundleMgrProxy;
}
#endif

std::string GetBundleNameByUid(int32_t uid)
{
#ifndef is_ohos_lite
    constexpr long minUid = 10000; // 10000 : minimum uid for hap
    if (uid < minUid) {
        return "";
    }
    auto bundleInstance = GetBundleManager();
    if (bundleInstance == nullptr) {
        DFXLOGE("bundleInstance is nullptr");
        return "";
    }
    std::string bundleName;
    auto ret = bundleInstance->GetNameForUid(uid, bundleName);
    if (ret != ERR_OK) {
        DFXLOGE("GetNameForUid failed! ret = %{public}d", ret);
        return "";
    }
    return bundleName;
#endif
    return "";
}
}
DumpCatcher &DumpCatcher::GetInstance()
{
    static DumpCatcher ins;
    return ins;
}

void DumpCatcher::Dump(const DumpOptions& dumpOpt) const
{
    // 容器内进程走专用转储路径(见 DumpContainerStack):其模块路径在
    // 宿主命名空间不可直达,常规 DfxDumpCatcher 路径打不开容器内的 so。
    if (IsContainerProcess(dumpOpt.pid)) {
        DumpContainerStack(dumpOpt);
        return;
    }
    ElapsedTime counter;
    DfxDumpCatcher dfxDump;
    std::string msg = "";
    int timeout = dumpOpt.timeout > WAIT_GET_KERNEL_STACK_TIMEOUT ? dumpOpt.timeout : WAIT_GET_KERNEL_STACK_TIMEOUT;
    auto dumpResult = dfxDump.DumpCatchWithTimeout(dumpOpt.pid, msg, timeout, dumpOpt.tid);
    auto dumpTime = counter.Elapsed<std::chrono::milliseconds>();
    std::string toFind = "Result:";
    size_t startPos = msg.find(toFind);
    if (startPos != std::string::npos) {
        size_t endPos = msg.find("\n", startPos);
        if (endPos != std::string::npos) {
            msg.erase(startPos, endPos - startPos + 1);
        }
    }
    if (dumpResult.first == -1) {
        printf("Result:dump failed.\n");
    } else if (dumpResult.first == 0) {
        printf("Result:dump normal stack success.\n");
    } else if (dumpResult.first == 1) {
        printf("Result:dump kernel stack success.\n");
    }
    printf("%s", dumpResult.second.c_str());
    printf("%s\n", msg.c_str());
    printf("total cost:(%" PRId64 ")ms\n", dumpTime);
}

void DumpCatcher::DumpKernelStack(const DumpOptions& dumpOpt) const
{
    ElapsedTime counter;
    std::string kernelStackInfo;
    std::function<bool(int)> stackTask = [&kernelStackInfo, &dumpOpt](int tid) {
        if (tid <= 0) {
            return false;
        }
        std::string tidKernelStackInfo;
        auto ret = DfxGetKernelStack(tid, tidKernelStackInfo, dumpOpt.needArk);
        if (ret == 0) {
            kernelStackInfo.append(tidKernelStackInfo);
        }
        return true;
    };
    std::vector<int> tids;
    (void)GetTidsByPidWithFunc(dumpOpt.pid, tids, stackTask);
    auto getKernelStackTime = counter.Elapsed<std::chrono::milliseconds>();
    counter.Reset();
    std::string parsedKernelStack;
    bool ret = false;
    time_t parseSymbolTime = 0;
    if (dumpOpt.needParse) {
        std::string bundleName = GetBundleName(dumpOpt.pid);
        ret = DfxJsonFormatter::FormatKernelStack(kernelStackInfo, parsedKernelStack, false, true, bundleName);
        parseSymbolTime = counter.Elapsed<std::chrono::milliseconds>();
    }
    if (ret) {
        printf("%s\n", parsedKernelStack.c_str());
    } else {
        printf("no need to format kernel stack or format failed.\n");
        printf("%s\n", kernelStackInfo.c_str());
    }
    printf("threads size:(%zu)\n", tids.size());
    printf("get kernel stack cost:(%" PRId64 ")ms\n", getKernelStackTime);
    if (dumpOpt.needParse) {
        printf("parse symbol cost:(%" PRId64 ")ms\n", parseSymbolTime);
    }
}

std::string DumpCatcher::GetBundleName(int32_t pid) const
{
    long uid = 0;
    uint64_t sigBlk = 0;
    if (!GetUidAndSigBlk(pid, uid, sigBlk)) {
        printf("GetUidAndSigBlk failed for pid(%d).\n", pid);
        return "";
    }
    return GetBundleNameByUid(uid);
}

// 判定目标是否容器内进程:读 /proc/<pid>/status 的 NSpid 行,列出两个及
// 以上 pid 说明目标处于独立的 pid namespace(嵌套);此时第二列是容器
// 内视角的 pid,不为 1(即不是该 namespace 的 init 自身)则按容器进程
// 处理。非容器进程 NSpid 只有一列,返回 false。
bool DumpCatcher::IsContainerProcess(int32_t pid) const
{
    if (pid <= 0) {
        return false;
    }
    std::string path = StringPrintf("/proc/%d/status", pid);
    std::string content;
    if (!LoadStringFromFile(path, content) || content.empty()) {
        return false;
    }

    static const std::string nspidTag = "NSpid:";
    size_t pos = content.find(nspidTag);
    if (pos == std::string::npos) {
        return false;
    }

    size_t endPos = content.find('\n', pos);
    if (endPos == std::string::npos) {
        endPos = content.size();
    }
    std::string nspidLine = content.substr(pos + nspidTag.size(), endPos - pos - nspidTag.size());

    std::vector<std::string> pids;
    size_t start = 0;
    while (start < nspidLine.size()) {
        size_t tabPos = nspidLine.find('\t', start);
        std::string part;
        if (tabPos == std::string::npos) {
            part = nspidLine.substr(start);
        } else {
            part = nspidLine.substr(start, tabPos - start);
        }
        Trim(part);
        if (!part.empty()) {
            pids.push_back(part);
        }
        if (tabPos == std::string::npos) {
            break;
        }
        start = tabPos + 1;
    }

    constexpr size_t CONTAINER_PROCESS_PID_COUNT = 2;
    constexpr size_t CONTAINER_PID_INDEX = 1;
    if (pids.size() < CONTAINER_PROCESS_PID_COUNT) {
        return false;
    }
    return pids[CONTAINER_PID_INDEX] != "1";
}

// 容器进程栈转储:改由 Unwinder 直接回溯,DfxMap::FormatMapName 会把
// map 名拼成 /proc/<pid>/root 前缀路径,宿主侧即可打开容器内的模块;
// 开启 miniDebugInfo 以解析容器内应用的 so 符号。逐 tid ptrace attach
// 后回溯、完毕即 detach;未指定 tid 时遍历目标全部线程。
void DumpCatcher::DumpContainerStack(const DumpOptions& dumpOpt) const
{
    ElapsedTime counter;
    DFXLOGI("DUMP PID %{public}d, TID %{public}d", dumpOpt.pid, dumpOpt.tid);
    printf("DUMP PID %d\n", dumpOpt.pid);

    UnwinderConfig::SetEnableMiniDebugInfo(true);
    auto unwinder = std::make_shared<Unwinder>(dumpOpt.pid);

    auto unwindSingleThread = [&](pid_t tid) -> std::string {
        if (!DfxPtrace::Attach(tid)) {
            printf("Failed to attach tid %d\n", tid);
            return "";
        }

        if (!unwinder->UnwindRemote(tid, false, DEFAULT_MAX_FRAME_NUM, 0)) {
            printf("Failed to unwind tid %d\n", tid);
            DfxPtrace::Detach(tid);
            return "";
        }
        auto frames = unwinder->GetFrames();
        auto framesStr = Unwinder::GetFramesStr(frames);
        DFXLOGI("frames:\n  %{public}s", framesStr.c_str());
        DfxPtrace::Detach(tid);
        return framesStr;
    };

    std::string framesStr;
    if (dumpOpt.tid != 0) {
        framesStr = unwindSingleThread(dumpOpt.tid);
    } else {
        std::vector<int> tids;
        std::function<bool(int)> unwindFunc = [&](int tid) -> bool {
            if (tid <= 0) {
                return false;
            }
            std::string threadName;
            ReadThreadName(tid, threadName);
            framesStr += "Tid:" + std::to_string(tid) + ", Name:" + threadName + "\n";
            framesStr += unwindSingleThread(tid);
            return true;
        };
        GetTidsByPidWithFunc(dumpOpt.pid, tids, unwindFunc);
    }

    auto dumpTime = counter.Elapsed<std::chrono::milliseconds>();
    printf("%s", framesStr.c_str());
    printf("total cost:(%" PRId64 ")ms\n", dumpTime);
}
} // namespace HiviewDFX
} // namespace OHOS
