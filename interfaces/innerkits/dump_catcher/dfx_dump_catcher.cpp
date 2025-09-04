/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "dfx_dump_catcher.h"

#include <atomic>
#include <cerrno>
#include <condition_variable>
#include <mutex>
#include <thread>
#include <vector>

#include <dlfcn.h>
#include <poll.h>
#include <securec.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>

#include "backtrace_local.h"
#include "dfx_define.h"
#include "dfx_dump_catcher_errno.h"
#include "dfx_dump_catcher_slow_policy.h"
#include "dfx_dump_res.h"
#include "dfx_log.h"
#include "dfx_socket_request.h"
#include "dfx_trace_dlsym.h"
#include "dfx_util.h"
#include "elapsed_time.h"
#include "faultloggerd_client.h"
#include "file_ex.h"
#include "kernel_stack_async_collector.h"
#include "procinfo.h"
#include "smart_fd.h"
#include "string_printf.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002D11
#endif

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "DfxDumpCatcher"
#endif
static const int DUMP_CATCHE_WORK_TIME_S = 60;
static constexpr int WAIT_GET_KERNEL_STACK_TIMEOUT = 1000; // 1000 : time out 1000 ms
static constexpr uint32_t HIVIEW_UID = 1201;
static constexpr uint32_t FOUNDATION_UID = 5523;

enum DfxDumpStatRes : int32_t {
    DUMP_RES_NO_KERNELSTACK = -2,
    DUMP_RES_WITH_KERNELSTACK = -1,
    DUMP_RES_WITH_USERSTACK = 0,
    DUMP_RES_WITH_USERSTACK_NO_PARSE_SYMBOL = 1,
    DUMP_RES_WITH_USERSTACK_PARSE_SYMBOL_TIMEOUT = 2,
};
}

struct DumpCatcherPipeData {
    DumpCatcherPipeData(int32_t pid, int32_t bufPipe, int32_t resPipe) : pid(pid), bufFd(bufPipe), resFd(resPipe) {}
    ~DumpCatcherPipeData()
    {
        // request close fds in faultloggerd
        RequestDelPipeFd(pid);
    }
    DumpCatcherPipeData(const DumpCatcherPipeData&) = delete;
    DumpCatcherPipeData& operator=(const DumpCatcherPipeData&) = delete;

    int pid{-1};
    SmartFd bufFd;
    SmartFd resFd;
    std::string bufMsg = "";
    std::string resMsg = "";
} ;

static bool IsLinuxKernel()
{
    static bool isLinux = [] {
        std::string content;
        LoadStringFromFile("/proc/version", content);
        if (content.empty()) {
            return true;
        }
        if (content.find("Linux") != std::string::npos) {
            return true;
        }
        return false;
    }();
    return isLinux;
}

class DfxDumpCatcher::Impl {
public:
    bool DumpCatch(int pid, int tid, std::string& msg, size_t maxFrameNums, bool isJson);
    bool DumpCatchFd(int pid, int tid, std::string& msg, int fd, size_t maxFrameNums);
    bool DumpCatchMultiPid(const std::vector<int> &pids, std::string& msg);
    std::pair<int, std::string> DumpCatchWithTimeout(int pid, std::string& msg, int timeout, int tid, bool isJson);
private:
    bool DoDumpCurrTid(const size_t skipFrameNum, std::string& msg, size_t maxFrameNums);
    bool DoDumpLocalTid(const int tid, std::string& msg, size_t maxFrameNums);
    bool DoDumpLocalPid(int pid, std::string& msg, size_t maxFrameNums);
    bool DoDumpLocalLocked(int pid, int tid, std::string& msg, size_t maxFrameNums);
    int32_t DoDumpRemoteLocked(int pid, int tid, std::string& msg, bool isJson = false,
        int timeout = DUMPCATCHER_REMOTE_TIMEOUT);
    int32_t DoDumpCatchRemote(int pid, int tid, std::string& msg, bool isJson = false,
        int timeout = DUMPCATCHER_REMOTE_TIMEOUT);
    int DoDumpRemotePid(int pid, std::string& msg, DumpCatcherPipeData& pipeData,
        bool isJson = false, int32_t timeout = DUMPCATCHER_REMOTE_TIMEOUT);
    bool HandlePollError(int pid, const uint64_t endTime, int& remainTime, int& pollRet, std::string& resMsg);
    bool HandlePollTimeout(int pid, const int timeout, int& remainTime, int& pollRet, std::string& resMsg);
    bool HandlePollEvents(int pid, const struct pollfd (&readFds)[2],
        bool& bPipeConnect, int& pollRet, DumpCatcherPipeData& pipeData);
    int DumpRemotePoll(int pid, const int timeout, DumpCatcherPipeData& pipeData);
    int DoDumpRemotePoll(int pid, int timeout, std::string& msg, DumpCatcherPipeData& pipeData, bool isJson = false);
    bool DoReadBuf(DumpCatcherPipeData& pipeData);
    bool DoReadRes(int& pollRet, DumpCatcherPipeData& pipeData);
    void DealAfterPollFail(int pid, std::string& msg);
    void DealWithPollRet(int pollRet, int pid, int32_t& ret, std::string& msg);
    void DealWithSdkDumpRet(int sdkdumpRet, int pid, int32_t& ret, std::string& msg);
    std::pair<int, std::string> DealWithDumpCatchRet(int pid, int32_t& ret, std::string& msg);
    void ReportDumpCatcherStats(int32_t pid, uint64_t requestTime, int32_t ret, void* retAddr);
    void GetKernelStack(int32_t uid, int pid);

    static int32_t KernelRet2DumpcatchRet(int32_t ret);
    static const int DUMPCATCHER_REMOTE_P90_TIMEOUT = 1000;
    static const int DUMPCATCHER_REMOTE_TIMEOUT = 10000;

    std::mutex mutex_;
    bool notifyCollect_ = false;
    KernelStackAsyncCollector stackKit_;
    KernelStackAsyncCollector::KernelResult stack_;
};

DfxDumpCatcher::DfxDumpCatcher() : impl_(std::make_shared<Impl>())
{}

bool DfxDumpCatcher::DumpCatch(int pid, int tid, std::string& msg, size_t maxFrameNums, bool isJson)
{
    return impl_->DumpCatch(pid, tid, msg, maxFrameNums, isJson);
}

bool DfxDumpCatcher::DumpCatchFd(int pid, int tid, std::string& msg, int fd, size_t maxFrameNums)
{
    return impl_->DumpCatchFd(pid, tid, msg, fd, maxFrameNums);
}

bool DfxDumpCatcher::DumpCatchMultiPid(const std::vector<int> &pids, std::string& msg)
{
    return impl_->DumpCatchMultiPid(pids, msg);
}

std::pair<int, std::string> DfxDumpCatcher::DumpCatchWithTimeout(int pid, std::string& msg,
    int timeout, int tid, bool isJson)
{
    return impl_->DumpCatchWithTimeout(pid, msg, timeout, tid, isJson);
}

bool DfxDumpCatcher::Impl::DoDumpCurrTid(const size_t skipFrameNum, std::string& msg, size_t maxFrameNums)
{
    bool ret = false;

    ret = GetBacktrace(msg, skipFrameNum + 1, false, maxFrameNums);
    if (!ret) {
        int currTid = gettid();
        msg.append("Failed to dump curr thread:" + std::to_string(currTid) + ".\n");
    }
    DFXLOGD("DoDumpCurrTid :: return %{public}d.", ret);
    return ret;
}

bool DfxDumpCatcher::Impl::DoDumpLocalTid(const int tid, std::string& msg, size_t maxFrameNums)
{
    bool ret = false;
    if (tid <= 0) {
        DFXLOGE("DoDumpLocalTid :: return false as param error.");
        return ret;
    }
    ret = GetBacktraceStringByTid(msg, tid, 0, false, maxFrameNums);
    if (!ret) {
        msg.append("Failed to dump thread:" + std::to_string(tid) + ".\n");
    }
    DFXLOGD("DoDumpLocalTid :: return %{public}d.", ret);
    return ret;
}

bool DfxDumpCatcher::Impl::DoDumpLocalPid(int pid, std::string& msg, size_t maxFrameNums)
{
    bool ret = false;
    if (pid <= 0) {
        DFXLOGE("DoDumpLocalPid :: return false as param error.");
        return ret;
    }
    size_t skipFramNum = 5; // 5: skip 5 frame

    msg = GetStacktraceHeader();
    std::function<bool(int)> func = [&](int tid) {
        if (tid <= 0) {
            return false;
        }
        std::string threadMsg;
        if (tid == gettid()) {
            ret = DoDumpCurrTid(skipFramNum, threadMsg, maxFrameNums);
        } else {
            ret = DoDumpLocalTid(tid, threadMsg, maxFrameNums);
        }
        msg += threadMsg;
        return ret;
    };
    std::vector<int> tids;
    ret = GetTidsByPidWithFunc(getpid(), tids, func);
    DFXLOGD("DoDumpLocalPid :: return %{public}d.", ret);
    return ret;
}

int32_t DfxDumpCatcher::Impl::DoDumpRemoteLocked(int pid, int tid, std::string& msg, bool isJson, int timeout)
{
    return DoDumpCatchRemote(pid, tid, msg, isJson, timeout);
}

bool DfxDumpCatcher::Impl::DoDumpLocalLocked(int pid, int tid, std::string& msg, size_t maxFrameNums)
{
    bool ret = false;
    if (tid == gettid()) {
        size_t skipFramNum = 4; // 4: skip 4 frame
        ret = DoDumpCurrTid(skipFramNum, msg, maxFrameNums);
    } else if (tid == 0) {
        ret = DoDumpLocalPid(pid, msg, maxFrameNums);
    } else {
        if (!IsThreadInPid(pid, tid)) {
            msg.append("tid(" + std::to_string(tid) + ") is not in pid(" + std::to_string(pid) + ").\n");
        } else {
            ret = DoDumpLocalTid(tid, msg, maxFrameNums);
        }
    }

    DFXLOGD("DoDumpLocal :: ret(%{public}d).", ret);
    return ret;
}

static int32_t ConvertDumpResultToDumpStats(int32_t dumpRes)
{
    int32_t stats = DUMP_RES_WITH_KERNELSTACK;
    switch (dumpRes) {
        case DUMPCATCH_ESUCCESS:
            stats = DUMP_RES_WITH_USERSTACK;
            break;
        case DUMPCATCH_DUMP_ESYMBOL_NO_PARSE:
            stats = DUMP_RES_WITH_USERSTACK_NO_PARSE_SYMBOL;
            break;
        case DUMPCATCH_DUMP_ESYMBOL_PARSE_TIMEOUT:
            stats = DUMP_RES_WITH_USERSTACK_PARSE_SYMBOL_TIMEOUT;
            break;
        default:
            break;
    }
    return stats;
}

void DfxDumpCatcher::Impl::ReportDumpCatcherStats(int32_t pid,
    uint64_t requestTime, int32_t ret, void* retAddr)
{
    std::vector<uint8_t> buf(sizeof(struct FaultLoggerdStatsRequest), 0);
    auto stat = reinterpret_cast<struct FaultLoggerdStatsRequest*>(buf.data());
    stat->type = DUMP_CATCHER;
    stat->pid = pid;
    stat->requestTime = requestTime;
    stat->dumpCatcherFinishTime = GetTimeMilliSeconds();
    stat->result = ConvertDumpResultToDumpStats(ret);
    if ((stat->result == DUMP_RES_WITH_KERNELSTACK) && stack_.msg.empty()) {
        stat->result = DUMP_RES_NO_KERNELSTACK;
    }
    stat->targetProcessThreadCount = stack_.threadCount;
    size_t copyLen;
    std::string processName;
    ReadProcessName(pid, processName);
    copyLen = std::min(sizeof(stat->targetProcess) - 1, processName.size());
    if (memcpy_s(stat->targetProcess, sizeof(stat->targetProcess) - 1, processName.c_str(), copyLen) != 0) {
        DFXLOGE("Failed to copy target process");
        return;
    }

    if (ret != DUMPCATCH_ESUCCESS) {
        std::string summary = DfxDumpCatchError::ToString(ret);
        copyLen = std::min(sizeof(stat->summary) - 1, summary.size());
        if (memcpy_s(stat->summary, sizeof(stat->summary) - 1, summary.c_str(), copyLen) != 0) {
            DFXLOGE("Failed to copy dumpcatcher summary");
            return;
        }
    }

    Dl_info info;
    if (dladdr(retAddr, &info) != 0) {
        copyLen = std::min(sizeof(stat->callerElf) - 1, strlen(info.dli_fname));
        if (memcpy_s(stat->callerElf, sizeof(stat->callerElf) - 1, info.dli_fname, copyLen) != 0) {
            DFXLOGE("Failed to copy caller elf info");
            return;
        }
        stat->offset = reinterpret_cast<uintptr_t>(retAddr) - reinterpret_cast<uintptr_t>(info.dli_fbase);
    }

    std::string cmdline;
    if (OHOS::LoadStringFromFile("/proc/self/cmdline", cmdline)) {
        copyLen = std::min(sizeof(stat->callerProcess) - 1, cmdline.size());
        if (memcpy_s(stat->callerProcess, sizeof(stat->callerProcess) - 1,
            cmdline.c_str(), copyLen) != 0) {
            DFXLOGE("Failed to copy caller cmdline");
            return;
        }
    }
    ReportDumpStats(stat);
}

static bool IsBitOn(const std::string& content, const std::string& filed, int signal)
{
    if (content.find(filed) == std::string::npos) {
        return false;
    }
    //SigBlk:   0000000000000000
    std::string num = content.substr(content.find(filed) + filed.size() + 2, 16);
    uint64_t hexValue = strtoul(num.c_str(), nullptr, 16);
    uint64_t mask = 1ULL << (signal - 1);

    return (hexValue & mask) != 0;
}

static bool IsSignalBlocked(int pid, int32_t& ret)
{
    std::vector<int> tids;
    std::vector<int> nstids;
    GetTidsByPid(pid, tids, nstids);
    std::string threadName;
    std::string content;
    int targetTid = -1;
    for (size_t i = 0; i < tids.size(); ++i) {
        ReadThreadNameByPidAndTid(pid, tids[i], threadName);
        if (threadName == "OS_DfxWatchdog") {
            targetTid = tids[i];
            break;
        }
    }
    if (targetTid != -1) {
        std::string threadStatusPath = StringPrintf("/proc/%d/task/%d/status", pid, targetTid);
        if (!LoadStringFromFile(threadStatusPath, content) || content.empty()) {
            DFXLOGE("the pid(%{public}d)thread(%{public}d) read status fail, errno(%{public}d)", pid, targetTid, errno);
            ret = DUMPCATCH_TIMEOUT_PARSE_FAIL_READ_ESTATUS;
            return true;
        }

        if (IsBitOn(content, "SigBlk", SIGDUMP) || IsBitOn(content, "SigIgn", SIGDUMP)) {
            DFXLOGI("the pid(%{public}d)thread(%{public}d) signal has been blocked by target process", pid, targetTid);
            ret = DUMPCATCH_TIMEOUT_SIGNAL_BLOCK;
            return true;
        }
    }
    return false;
}

static bool IsFrozen(int pid, int32_t& ret)
{
    std::string content;
    std::string cgroupPath = StringPrintf("/proc/%d/cgroup", pid);
    if (!LoadStringFromFile(cgroupPath, content)) {
        DFXLOGE("the pid (%{public}d) read cgroup fail, errno (%{public}d)", pid, errno);
        ret = DUMPCATCH_TIMEOUT_PARSE_FAIL_READ_ECGROUP;
        return true;
    }

    if (content.find("Frozen") != std::string::npos) {
        DFXLOGI("the pid (%{public}d) has been frozen", pid);
        ret = DUMPCATCH_TIMEOUT_KERNEL_FROZEN;
        return true;
    }
    return false;
}

static void AnalyzeTimeoutReason(int pid, int32_t& ret)
{
    std::string statusPath = StringPrintf("/proc/%d/status", pid);
    if (access(statusPath.c_str(), F_OK) != 0) {
        DFXLOGI("the pid (%{public}d) process exit during the dump, errno (%{public}d)", pid, errno);
        ret = DUMPCATCH_TIMEOUT_PROCESS_KILLED;
        return;
    }

    if (IsSignalBlocked(pid, ret)) {
        return;
    }

    if (IsFrozen(pid, ret)) {
        return;
    }

    DFXLOGI("the pid (%{public}d) dump slow", pid);
    ret = DUMPCATCH_TIMEOUT_DUMP_SLOW;
}

void DfxDumpCatcher::Impl::DealAfterPollFail(int pid, std::string& msg)
{
    // get result
    if (notifyCollect_) {
        stack_ = stackKit_.GetCollectedStackResult();
    } else {
        stack_ = stackKit_.GetProcessStackWithTimeout(pid, WAIT_GET_KERNEL_STACK_TIMEOUT);
    }

    std::string halfProcStatus;
    std::string halfProcWchan;
    ReadProcessStatus(halfProcStatus, pid);
    if (IsLinuxKernel()) {
        ReadProcessWchan(halfProcWchan, pid, false, true);
    }
    msg.append(std::move(halfProcStatus));
    msg.append(std::move(halfProcWchan));
}

void DfxDumpCatcher::Impl::DealWithPollRet(int pollRet, int pid, int32_t& ret, std::string& msg)
{
    bool isPollFail = true;

    switch (pollRet) {
        case DUMP_POLL_OK:
            ret = DUMPCATCH_ESUCCESS;
            isPollFail = false;
            break;
        case DUMP_POLL_NO_PARSE_SYMBOL:
            ret = DUMPCATCH_DUMP_ESYMBOL_NO_PARSE;
            isPollFail = false;
            break;
        case DUMP_POLL_PARSE_SYMBOL_TIMEOUT:
            ret = DUMPCATCH_DUMP_ESYMBOL_PARSE_TIMEOUT;
            isPollFail = false;
            break;
        case DUMP_POLL_FD:
            ret = DUMPCATCH_EFD;
            break;
        case DUMP_POLL_FAILED:
            ret = DUMPCATCH_EPOLL;
            break;
        case DUMP_POLL_TIMEOUT:
            AnalyzeTimeoutReason(pid, ret);
            if (ret == DUMPCATCH_TIMEOUT_DUMP_SLOW) {
                DfxDumpCatcherSlowPolicy::GetInstance().SetDumpCatcherSlowStat(pid);
            }
            break;
        case DUMP_POLL_RETURN:
            if (msg.find("ptrace attach thread failed") != std::string::npos) {
                ret = DUMPCATCH_DUMP_EPTRACE;
            } else if (msg.find("stop unwinding") != std::string::npos) {
                ret = DUMPCATCH_DUMP_EUNWIND;
            } else if (msg.find("mapinfo is not exist") != std::string::npos) {
                ret = DUMPCATCH_DUMP_EMAP;
            } else {
                ret = DUMPCATCH_DUMP_ERROR;
            }
            break;
        default:
            ret = DUMPCATCH_UNKNOWN;
            break;
    }

    if (isPollFail) {
        DealAfterPollFail(pid, msg);
    }
}

void DfxDumpCatcher::Impl::GetKernelStack(int32_t uid, int pid)
{
    if (uid == HIVIEW_UID || uid == FOUNDATION_UID) {
        stack_ = stackKit_.GetProcessStackWithTimeout(pid, WAIT_GET_KERNEL_STACK_TIMEOUT);
    }
}

void DfxDumpCatcher::Impl::DealWithSdkDumpRet(int sdkdumpRet, int pid, int32_t& ret, std::string& msg)
{
    uint32_t uid = getuid();
    if (sdkdumpRet == ResponseCode::SDK_DUMP_REPEAT) {
        stack_ = stackKit_.GetProcessStackWithTimeout(pid, WAIT_GET_KERNEL_STACK_TIMEOUT);
        msg.append("Result: pid(" + std::to_string(pid) + ") process is dumping.\n");
        ret = DUMPCATCH_IS_DUMPING;
    } else if (sdkdumpRet == ResponseCode::REQUEST_REJECT) {
        msg.append("Result: pid(" + std::to_string(pid) + ") process check permission error.\n");
        ret = DUMPCATCH_EPERMISSION;
    } else if (sdkdumpRet == ResponseCode::SDK_DUMP_NOPROC) {
        msg.append("Result: pid(" + std::to_string(pid) + ") process has exited.\n");
        ret = DUMPCATCH_NO_PROCESS;
    } else if (sdkdumpRet == ResponseCode::SDK_PROCESS_CRASHED) {
        GetKernelStack(uid, pid);
        msg.append("Result: pid(" + std::to_string(pid) + ") process has been crashed.\n");
        ret = DUMPCATCH_HAS_CRASHED;
    } else if (sdkdumpRet == ResponseCode::CONNECT_FAILED) {
        GetKernelStack(uid, pid);
        msg.append("Result: pid(" + std::to_string(pid) + ") process fail to conntect faultloggerd.\n");
        ret = DUMPCATCH_ECONNECT;
    } else if (sdkdumpRet == ResponseCode::SEND_DATA_FAILED) {
        GetKernelStack(uid, pid);
        msg.append("Result: pid(" + std::to_string(pid) + ") process fail to write to faultloggerd.\n");
        ret = DUMPCATCH_EWRITE;
    } else {
        GetKernelStack(uid, pid);
        msg.append("Result: pid(" + std::to_string(pid) + ") faultloggerd maybe exception occurred.\n");
        ret = DUMPCATCH_EFAULTLOGGERD;
    }
    DFXLOGW("%{public}s :: %{public}s", __func__, msg.c_str());
}

std::pair<int, std::string> DfxDumpCatcher::Impl::DealWithDumpCatchRet(int pid, int32_t& ret, std::string& msg)
{
    int result = ret == 0 ? 0 : -1;
    std::string reason;
    if (result == 0) {
        reason = "Reason:" + DfxDumpCatchError::ToString(ret) + "\n";
    } else if (ret == DUMPCATCH_DUMP_ESYMBOL_NO_PARSE || ret == DUMPCATCH_DUMP_ESYMBOL_PARSE_TIMEOUT) {
        reason = "Reason:" + DfxDumpCatchError::ToString(ret) + "\n";
        result = 0;
    } else {
        reason = "Reason:\nnormal stack:" + DfxDumpCatchError::ToString(ret) + "\n";
        if (stack_.errorCode != KernelStackAsyncCollector::STACK_SUCCESS) {
            ret = KernelRet2DumpcatchRet(stack_.errorCode);
            reason += "kernel stack:" + DfxDumpCatchError::ToString(ret) + "\n";
        } else if (!stack_.msg.empty()) {
            msg.append(stack_.msg);
            result = 1;
        } else {
            reason += "kernel stack:" + DfxDumpCatchError::ToString(DUMPCATCH_KERNELSTACK_NONEED) + "\n";
        }
    }

    return std::make_pair(result, reason);
}

std::pair<int, std::string> DfxDumpCatcher::Impl::DumpCatchWithTimeout(int pid, std::string& msg, int timeout,
                                                                       int tid, bool isJson)
{
    DfxEnableTraceDlsym(true);
    ElapsedTime counter;
    uint64_t requestTime = GetTimeMilliSeconds();
    int32_t dumpcatchErrno = DUMPCATCH_UNKNOWN;
    bool reportStat = false;
    do {
        if (pid <= 0 || tid <0 || timeout <= WAIT_GET_KERNEL_STACK_TIMEOUT) {
            DFXLOGE("DumpCatchWithTimeout:: param error.");
            dumpcatchErrno = DUMPCATCH_EPARAM;
            break;
        }
        if (!IsLinuxKernel()) {
            std::string statusPath = StringPrintf("/proc/%d/status", pid);
            if (access(statusPath.c_str(), F_OK) != 0 && errno != EACCES) {
                DFXLOGE("DumpCatchWithTimeout:: the pid(%{public}d) process has exited, errno(%{public}d)", pid, errno);
                msg.append("Result: pid(" + std::to_string(pid) + ") process has exited.\n");
                dumpcatchErrno = DUMPCATCH_NO_PROCESS;
                break;
            }
        }
        std::unique_lock<std::mutex> lck(mutex_);
        int currentPid = getpid();
        if (pid == currentPid) {
            bool ret = DoDumpLocalLocked(pid, tid, msg, DEFAULT_MAX_FRAME_NUM);
            dumpcatchErrno = ret ? DUMPCATCH_ESUCCESS : DUMPCATCH_DUMP_SELF_FAIL;
        } else {
            DFXLOGI("Receive DumpCatch request for cPid:(%{public}d), pid(%{public}d)", currentPid, pid);
            dumpcatchErrno = DoDumpRemoteLocked(pid, tid, msg, isJson, timeout);
            reportStat = true;
        }
    } while (false);

    auto result = DealWithDumpCatchRet(pid, dumpcatchErrno, msg);
    if (reportStat) {
        void* retAddr = __builtin_return_address(0);
        ReportDumpCatcherStats(pid, requestTime, dumpcatchErrno, retAddr);
    }

    DFXLOGI("dump_catch : pid = %{public}d, elapsed time = %{public}" PRId64 " ms, " \
        "msgLength = %{public}zu, ret = %{public}d\n%{public}s",
        pid, counter.Elapsed<std::chrono::milliseconds>(), msg.size(), result.first, result.second.c_str());
    DfxEnableTraceDlsym(false);
    return result;
}

bool DfxDumpCatcher::Impl::DumpCatch(int pid, int tid, std::string& msg, size_t maxFrameNums, bool isJson)
{
    bool ret = false;
    if (pid <= 0 || tid < 0) {
        DFXLOGE("dump_catch :: param error.");
        return ret;
    }
    if (!IsLinuxKernel()) {
        std::string statusPath = StringPrintf("/proc/%d/status", pid);
        DFXLOGI("DumpCatch:: access pid(%{public}d) status", pid);
        if (access(statusPath.c_str(), F_OK) != 0 && errno != EACCES) {
            DFXLOGE("DumpCatch:: the pid(%{public}d) process has exited, errno(%{public}d)", pid, errno);
            msg.append("Result: pid(" + std::to_string(pid) + ") process has exited.\n");
            return ret;
        }
    }
    DfxEnableTraceDlsym(true);
    ElapsedTime counter;
    std::unique_lock<std::mutex> lck(mutex_);
    stack_ = {};
    notifyCollect_ = false;
    int currentPid = getpid();
    uint64_t requestTime = GetTimeMilliSeconds();
    DFXLOGI("Receive DumpCatch request for cPid:(%{public}d), pid(%{public}d), " \
        "tid:(%{public}d).", currentPid, pid, tid);
    if (pid == currentPid) {
        ret = DoDumpLocalLocked(pid, tid, msg, maxFrameNums);
    } else {
        if (maxFrameNums != DEFAULT_MAX_FRAME_NUM) {
            DFXLOGI("dump_catch :: maxFrameNums does not support setting " \
                "when pid is not equal to caller pid");
        }
        int timeout = (tid == 0 ? 3 : 10) * 1000; // when tid not zero, timeout is 10s
        int32_t res = DoDumpRemoteLocked(pid, tid, msg, isJson, timeout);
        if (res == DUMPCATCH_ESUCCESS ||
            res == DUMPCATCH_DUMP_ESYMBOL_NO_PARSE ||
            res == DUMPCATCH_DUMP_ESYMBOL_PARSE_TIMEOUT) {
            ret = true;
        }
        if (!ret && stack_.errorCode != KernelStackAsyncCollector::STACK_SUCCESS) {
            res = KernelRet2DumpcatchRet(stack_.errorCode);
        }
        void* retAddr = __builtin_return_address(0);
        ReportDumpCatcherStats(pid, requestTime, res, retAddr);
    }
    DFXLOGI("dump_catch : pid = %{public}d, elapsed time = %{public}" PRId64 " ms, ret = %{public}d, " \
        "msgLength = %{public}zu",
        pid, counter.Elapsed<std::chrono::milliseconds>(), ret, msg.size());
    DfxEnableTraceDlsym(false);
    return ret;
}

bool DfxDumpCatcher::Impl::DumpCatchFd(int pid, int tid, std::string& msg, int fd, size_t maxFrameNums)
{
    bool ret = false;
    ret = DumpCatch(pid, tid, msg, maxFrameNums, false);
    if (fd > 0) {
        ret = OHOS_TEMP_FAILURE_RETRY(write(fd, msg.c_str(), msg.length()));
    }
    return ret;
}

int32_t DfxDumpCatcher::Impl::DoDumpCatchRemote(int pid, int tid, std::string& msg, bool isJson, int timeout)
{
    DFX_TRACE_SCOPED_DLSYM("DoDumpCatchRemote");
    int32_t ret = DUMPCATCH_UNKNOWN;

    if (pid <= 0 || tid < 0 || timeout <= WAIT_GET_KERNEL_STACK_TIMEOUT) {
        msg.append("Result: pid(" + std::to_string(pid) + ") param error.\n");
        DFXLOGW("%{public}s :: %{public}s", __func__, msg.c_str());
        return DUMPCATCH_EPARAM;
    }

    if (IsFrozen(pid, ret) && ret == DUMPCATCH_TIMEOUT_KERNEL_FROZEN) {
        stack_ = stackKit_.GetProcessStackWithTimeout(pid, WAIT_GET_KERNEL_STACK_TIMEOUT);
        return ret;
    }
    if (DfxDumpCatcherSlowPolicy::GetInstance().IsDumpCatcherInSlowPeriod(pid)) {
        DFXLOGW("dumpcatch in slow period, return pid (%{public}d) kernel stack directly!", pid);
        msg.append("Result: pid(" + std::to_string(pid) + ") last dump slow, return kernel stack directly.\n");
        stack_ = stackKit_.GetProcessStackWithTimeout(pid, WAIT_GET_KERNEL_STACK_TIMEOUT);
        return DUMPCATCH_TIMEOUT_DUMP_IN_SLOWPERIOD;
    }

    int pipeReadFd[] = { -1, -1 };
    uint64_t sdkDumpStartTime = GetAbsTimeMilliSeconds();
    int sdkdumpRet = RequestSdkDump(pid, tid, pipeReadFd, isJson, timeout);
    if (sdkdumpRet != ResponseCode::REQUEST_SUCCESS) {
        DealWithSdkDumpRet(sdkdumpRet, pid, ret, msg);
        return ret;
    }
    DumpCatcherPipeData pipeData(pid, pipeReadFd[PIPE_BUF_INDEX], pipeReadFd[PIPE_RES_INDEX]);
    // timeout sub the cost time of sdkdump
    timeout -= static_cast<int>(GetAbsTimeMilliSeconds() - sdkDumpStartTime);

    int pollRet = DoDumpRemotePid(pid, msg, pipeData, isJson, timeout);
    DealWithPollRet(pollRet, pid, ret, msg);
    DFXLOGI("%{public}s :: pid(%{public}d) ret: %{public}d", __func__, pid, ret);
    return ret;
}

int DfxDumpCatcher::Impl::DoDumpRemotePid(int pid, std::string& msg, DumpCatcherPipeData& pipeData,
                                          bool isJson, int32_t timeout)
{
    DFX_TRACE_SCOPED_DLSYM("DoDumpRemotePid");
    if (timeout <= 0) {
        DFXLOGW("timeout less than 0, try to get kernel stack and return directly!");
        stack_ = stackKit_.GetProcessStackWithTimeout(pid, WAIT_GET_KERNEL_STACK_TIMEOUT);
        return DUMP_POLL_TIMEOUT;
    } else if (timeout < 1000) { // 1000 : one thousand milliseconds
        DFXLOGW("timeout less than 1 seconds, get kernel stack directly!");
        notifyCollect_ = stackKit_.NotifyStartCollect(pid);
    }
    int ret = DoDumpRemotePoll(pid, timeout, msg, pipeData, isJson);
    DFXLOGI("%{public}s :: pid(%{public}d) poll ret: %{public}d", __func__, pid, ret);
    return ret;
}

int32_t DfxDumpCatcher::Impl::KernelRet2DumpcatchRet(int32_t ret)
{
    switch (ret) {
        case KernelStackAsyncCollector::STACK_ECREATE:
             return DUMPCATCH_KERNELSTACK_ECREATE;
        case KernelStackAsyncCollector::STACK_EOPEN:
             return DUMPCATCH_KERNELSTACK_EOPEN;
        case KernelStackAsyncCollector::STACK_EIOCTL:
             return DUMPCATCH_KERNELSTACK_EIOCTL;
        case KernelStackAsyncCollector::STACK_TIMEOUT:
            return DUMPCATCH_KERNELSTACK_TIMEOUT;
        case KernelStackAsyncCollector::STACK_OVER_LIMIT:
            return DUMPCATCH_KERNELSTACK_OVER_LIMIT;
        default:
            return DUMPCATCH_UNKNOWN;
    }
}

bool DfxDumpCatcher::Impl::HandlePollError(int pid, const uint64_t endTime, int& remainTime,
                                           int& pollRet, std::string& resMsg)
{
    if (errno == EINTR) {
        uint64_t now = GetAbsTimeMilliSeconds();
        if (now >= endTime) {
            pollRet = DUMP_POLL_TIMEOUT;
            resMsg.append("Result: poll timeout.\n");
            return false;
        }
        if (!notifyCollect_ && (remainTime == DUMPCATCHER_REMOTE_P90_TIMEOUT)) {
            notifyCollect_ = stackKit_.NotifyStartCollect(pid);
        }
        remainTime = static_cast<int>(endTime - now);
        return true;
    }
    pollRet = DUMP_POLL_FAILED;
    resMsg.append("Result: poll error, errno(" + std::to_string(errno) + ")\n");
    return false;
}

bool DfxDumpCatcher::Impl::HandlePollTimeout(int pid, const int timeout, int& remainTime,
                                             int& pollRet, std::string& resMsg)
{
    if (!notifyCollect_ && (remainTime == DUMPCATCHER_REMOTE_P90_TIMEOUT)) {
        notifyCollect_ = stackKit_.NotifyStartCollect(pid);
        remainTime = timeout - DUMPCATCHER_REMOTE_P90_TIMEOUT;
        return true;
    }
    pollRet = DUMP_POLL_TIMEOUT;
    resMsg.append("Result: poll timeout.\n");
    return false;
}

bool DfxDumpCatcher::Impl::HandlePollEvents(int pid, const struct pollfd (&readFds)[2], bool& bPipeConnect,
                                            int& pollRet, DumpCatcherPipeData& pipeData)
{
    bool bufRet = true;
    bool resRet = false;
    bool eventRet = true;
    for (auto& readFd : readFds) {
        if (!bPipeConnect && (static_cast<uint32_t>(readFd.revents) & POLLIN)) {
            bPipeConnect = true;
        }

        if (bPipeConnect &&
            ((static_cast<uint32_t>(readFd.revents) & POLLERR) || (static_cast<uint32_t>(readFd.revents) & POLLHUP))) {
            eventRet = false;
            pipeData.resMsg.append("Result: poll events error.\n");
            break;
        }

        if ((static_cast<uint32_t>(readFd.revents) & POLLIN) != POLLIN) {
            continue;
        }

        if (readFd.fd == pipeData.bufFd.GetFd()) {
            bufRet = DoReadBuf(pipeData);
        } else if (readFd.fd == pipeData.resFd.GetFd()) {
            resRet = DoReadRes(pollRet, pipeData);
        }
    }

    if ((eventRet == false) || (bufRet == false) || (resRet == true)) {
        DFXLOGI("eventRet:%{public}d bufRet:%{public}d resRet:%{public}d", eventRet, bufRet, resRet);
        return false;
    }
    return true;
}

int DfxDumpCatcher::Impl::DumpRemotePoll(int pid, const int timeout, DumpCatcherPipeData& pipeData)
{
    int pollRet = DUMP_POLL_INIT;
    struct pollfd readFds[2];
    (void)memset_s(readFds, sizeof(readFds), 0, sizeof(readFds));
    readFds[0].fd = pipeData.bufFd.GetFd();
    readFds[0].events = POLLIN;
    readFds[1].fd = pipeData.resFd.GetFd();
    readFds[1].events = POLLIN;
    int fdsSize = sizeof(readFds) / sizeof(readFds[0]);
    bool bPipeConnect = false;
    int remainTime = DUMPCATCHER_REMOTE_P90_TIMEOUT < timeout ? DUMPCATCHER_REMOTE_P90_TIMEOUT : timeout;
    uint64_t startTime = GetAbsTimeMilliSeconds();
    uint64_t endTime = startTime + static_cast<uint64_t>(timeout);
    bool isContinue = true;
    do {
        int pRet = poll(readFds, fdsSize, remainTime);
        if (pRet < 0) {
            isContinue = HandlePollError(pid, endTime, remainTime, pollRet, pipeData.resMsg);
            continue;
        } else if (pRet == 0) {
            isContinue = HandlePollTimeout(pid, timeout, remainTime, pollRet, pipeData.resMsg);
            continue;
        }
        if (!HandlePollEvents(pid, readFds, bPipeConnect, pollRet, pipeData)) {
            break;
        }
        uint64_t now = GetAbsTimeMilliSeconds();
        if (now >= endTime) {
            pollRet = DUMP_POLL_TIMEOUT;
            pipeData.resMsg.append("Result: poll timeout.\n");
            break;
        }
        remainTime = static_cast<int>(endTime - now);
    } while (isContinue);
    return pollRet;
}

int DfxDumpCatcher::Impl::DoDumpRemotePoll(int pid, int timeout, std::string& msg,
    DumpCatcherPipeData& pipeData, bool isJson)
{
    DFX_TRACE_SCOPED_DLSYM("DoDumpRemotePoll");
    if (!pipeData.bufFd || !pipeData.resFd) {
        if (!isJson) {
            msg = "Result: bufFd or resFd < 0.\n";
        }
        DFXLOGE("invalid bufFd or resFd");
        return DUMP_POLL_FD;
    }

    int res = DumpRemotePoll(pid, timeout, pipeData);
    bool isDumpSuccess = (res == DUMP_POLL_OK) || (res == DUMP_POLL_NO_PARSE_SYMBOL)
        || (res == DUMP_POLL_PARSE_SYMBOL_TIMEOUT);
    DFXLOGI("%{public}s :: %{public}s", __func__, pipeData.resMsg.c_str());
    msg = isJson && isDumpSuccess ? pipeData.bufMsg : (pipeData.resMsg + pipeData.bufMsg);
    return res;
}

bool DfxDumpCatcher::Impl::DoReadBuf(DumpCatcherPipeData& pipeData)
{
    std::vector<char> buffer(MAX_PIPE_SIZE, 0);
    ssize_t nread = OHOS_TEMP_FAILURE_RETRY(read(pipeData.bufFd.GetFd(), buffer.data(), MAX_PIPE_SIZE));
    if (nread <= 0) {
        DFXLOGW("%{public}s :: read error", __func__);
        return false;
    }
    DFXLOGD("%{public}s :: nread: %{public}zu", __func__, nread);
    pipeData.bufMsg.append(buffer.data(), static_cast<size_t>(nread));
    return true;
}

bool DfxDumpCatcher::Impl::DoReadRes(int& pollRet, DumpCatcherPipeData& pipeData)
{
    int32_t res = DumpErrorCode::DUMP_ESUCCESS;
    ssize_t nread = OHOS_TEMP_FAILURE_RETRY(read(pipeData.resFd.GetFd(), &res, sizeof(res)));
    if (nread <= 0 || nread != sizeof(res)) {
        DFXLOGW("%{public}s :: read error", __func__);
        return false;
    }

    switch (res) {
        case DUMP_ESUCCESS:
            pollRet = DUMP_POLL_OK;
            break;
        case DUMP_ESYMBOL_NO_PARSE:
            pollRet = DUMP_POLL_NO_PARSE_SYMBOL;
            break;
        case DUMP_ESYMBOL_PARSE_TIMEOUT:
            pollRet = DUMP_POLL_PARSE_SYMBOL_TIMEOUT;
            break;
        default:
            pollRet = DUMP_POLL_RETURN;
            break;
    }

    pipeData.resMsg.append("Result: " + DfxDumpRes::ToString(res) + "\n");
    return true;
}

bool DfxDumpCatcher::Impl::DumpCatchMultiPid(const std::vector<int>& pids, std::string& msg)
{
    bool ret = false;
    int pidSize = (int)pids.size();
    if (pidSize <= 0) {
        DFXLOGE("%{public}s :: param error, pidSize(%{public}d).", __func__, pidSize);
        return ret;
    }

    std::unique_lock<std::mutex> lck(mutex_);
    int currentPid = getpid();
    int currentTid = gettid();
    DFXLOGD("%{public}s :: cPid(%{public}d), cTid(%{public}d), pidSize(%{public}d).",
        __func__, currentPid, currentTid, pidSize);

    time_t startTime = time(nullptr);
    if (startTime > 0) {
        DFXLOGD("%{public}s :: startTime(%{public}" PRId64 ").", __func__, startTime);
    }

    for (int i = 0; i < pidSize; i++) {
        int pid = pids[i];
        std::string pidStr;
        bool ret = DoDumpRemoteLocked(pid, 0, pidStr) == DUMPCATCH_ESUCCESS;
        if (ret) {
            msg.append(pidStr + "\n");
        } else {
            msg.append("Failed to dump process:" + std::to_string(pid));
        }

        time_t currentTime = time(nullptr);
        if (currentTime > 0) {
            DFXLOGD("%{public}s :: startTime(%{public}" PRId64 "), currentTime(%{public}" PRId64 ").",
                __func__, startTime, currentTime);
            if (currentTime > startTime + DUMP_CATCHE_WORK_TIME_S) {
                break;
            }
        }
    }

    DFXLOGD("%{public}s :: msg(%{public}s).", __func__, msg.c_str());
    if (msg.find("Tid:") != std::string::npos) {
        ret = true;
    }
    return ret;
}
} // namespace HiviewDFX
} // namespace OHOS
