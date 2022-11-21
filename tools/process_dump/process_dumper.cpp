/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

/* This files contains process dump main module. */

#include "process_dumper.h"

#include <cerrno>
#include <cinttypes>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <memory>
#include <string>

#include <fcntl.h>
#include <pthread.h>
#include <syscall.h>
#include <ucontext.h>
#include <unistd.h>

#include <faultloggerd_client.h>
#include <securec.h>

#include "cppcrash_reporter.h"
#include "dfx_config.h"
#include "dfx_define.h"
#include "dfx_dump_res.h"
#include "dfx_logger.h"
#include "dfx_process.h"
#include "dfx_ring_buffer_wrapper.h"
#include "dfx_signal.h"
#include "dfx_thread.h"
#include "dfx_unwind_remote.h"
#include "dfx_util.h"

namespace OHOS {
namespace HiviewDFX {
ProcessDumper &ProcessDumper::GetInstance()
{
    static ProcessDumper ins;
    return ins;
}

void ProcessDumper::PrintDumpProcessWithSignalContextHeader(std::shared_ptr<DfxProcess> process,
    std::shared_ptr<ProcessDumpRequest> request)
{
    auto info = request->GetSiginfo();
    auto msg = request->GetLastFatalMessage();
    if (info.si_signo != SIGDUMP) {
        DfxRingBufferWrapper::GetInstance().AppendMsg("Timestamp:" + GetCurrentTimeStr(request->GetTimeStamp()));
    } else {
        DfxRingBufferWrapper::GetInstance().AppendMsg("Timestamp:" + GetCurrentTimeStr());
    }
    DfxRingBufferWrapper::GetInstance().AppendBuf("Pid:%d\n", process->GetPid());
    DfxRingBufferWrapper::GetInstance().AppendBuf("Uid:%d\n", process->GetUid());
    DfxRingBufferWrapper::GetInstance().AppendBuf("Process name:%s\n", process->GetProcessName().c_str());

    if (info.si_signo != SIGDUMP) {
        DfxRingBufferWrapper::GetInstance().AppendBuf("Reason:");
        DfxRingBufferWrapper::GetInstance().AppendMsg(PrintSignal(info));
        if (info.si_signo == SIGABRT && !msg.empty()) {
            DfxRingBufferWrapper::GetInstance().AppendBuf("LastFatalMessage:%s\n", msg.c_str());
        }

        auto traceId = request->GetTraceInfo();
        if (traceId.chainId != 0) {
            DfxRingBufferWrapper::GetInstance().AppendBuf("TraceId:%llx\n",
                static_cast<unsigned long long>(traceId.chainId));
        }

        if (process->GetThreads().size() != 0) {
            DfxRingBufferWrapper::GetInstance().AppendBuf("Fault thread Info:\n");
        }
    }
}

int ProcessDumper::InitPrintThread(bool fromSignalHandler, std::shared_ptr<ProcessDumpRequest> request, \
    std::shared_ptr<DfxProcess> process)
{
    int fd = -1;
    if (!fromSignalHandler) {
        fd = STDOUT_FILENO;
        DfxRingBufferWrapper::GetInstance().SetWriteFunc(ProcessDumper::WriteDumpBuf);
    } else {
        int32_t pid = request->GetPid();
        int32_t signo = request->GetSiginfo().si_signo;
        bool isCrash = (signo != SIGDUMP);
        FaultLoggerType type = isCrash ? FaultLoggerType::CPP_CRASH : FaultLoggerType::CPP_STACKTRACE;

        struct FaultLoggerdRequest faultloggerdRequest;
        if (memset_s(&faultloggerdRequest, sizeof(faultloggerdRequest), 0, sizeof(struct FaultLoggerdRequest)) != 0) {
            DfxLogError("memset_s error.");
            return fd;
        }

        if (isCrash) {
            faultloggerdRequest.type = (int32_t)type;
            faultloggerdRequest.pid = request->GetPid();
            faultloggerdRequest.tid = request->GetTid();
            faultloggerdRequest.uid = request->GetUid();
            faultloggerdRequest.time = request->GetTimeStamp();
            if (strncpy_s(faultloggerdRequest.module, sizeof(faultloggerdRequest.module),
                process->GetProcessName().c_str(), sizeof(faultloggerdRequest.module) - 1) != 0) {
                DfxLogWarn("Failed to set process name.");
                return fd;
            }
            fd = RequestFileDescriptorEx(&faultloggerdRequest);

            DfxRingBufferWrapper::GetInstance().SetWriteFunc(ProcessDumper::WriteDumpBuf);
            reporter_ = std::make_shared<CppCrashReporter>(request->GetTimeStamp(), signo, process);
        } else {
            fd = RequestPipeFd(pid, FaultLoggerPipeType::PIPE_FD_WRITE_BUF);
            DfxLogDebug("write buf fd: %d", fd);

            resFd_ = RequestPipeFd(pid, FaultLoggerPipeType::PIPE_FD_WRITE_RES);
            DfxLogDebug("write res fd: %d", resFd_);
        }

        if (fd < 0) {
            DfxLogWarn("Failed to request fd from faultloggerd.");
        }
    }

    DfxRingBufferWrapper::GetInstance().SetWriteBufFd(fd);
    DfxRingBufferWrapper::GetInstance().StartThread();
    return fd;
}

int ProcessDumper::DumpProcessWithSignalContext(std::shared_ptr<DfxProcess> &process,
                                                std::shared_ptr<ProcessDumpRequest> request)
{
    int dumpRes = ProcessDumpRes::DUMP_ESUCCESS;
    do {
        ssize_t readCount = read(STDIN_FILENO, request.get(), sizeof(ProcessDumpRequest));
        if (readCount != static_cast<long>(sizeof(ProcessDumpRequest))) {
            DfxLogError("Fail to read DumpRequest(%d).", errno);
            dumpRes = ProcessDumpRes::DUMP_EREADREQUEST;
            break;
        }

        std::string storeThreadName = request->GetThreadNameString();
        std::string storeProcessName = request->GetProcessNameString();
        // We need check pid is same with getppid().
        // As in signal handler, current process is a child process, and target pid is our parent process.
        // If pid namespace is enalbed, both ppid and pid are equal one.
        // In this case, we have to parse /proc/self/stat
        if (syscall(SYS_getppid) != request->GetPid()) {
            DfxLogError("Target process(%s:%d) is not parent pid(%d), exit processdump for signal(%d).",
                storeProcessName.c_str(), request->GetPid(), syscall(SYS_getppid), request->GetSiginfo().si_signo);
            dumpRes = ProcessDumpRes::DUMP_EGETPPID;
            break;
        }

        // move those assignment to process.cpp
        int tid = request->GetSiginfo().si_value.sival_int;
        int targetPid = request->GetPid();
        int targetTid = request->GetTid();
        bool isCrash = (request->GetSiginfo().si_signo != SIGDUMP);
        FaultLoggerType type = isCrash ? FaultLoggerType::CPP_CRASH : FaultLoggerType::CPP_STACKTRACE;
        bool isPidNsEnabled = (targetPid == 1);
        if (isPidNsEnabled) {
            int realPid = GetRealTargetPid();
            targetPid = (realPid == 0) ? 1 : realPid; // real init case
            isPidNsEnabled = (targetPid != 1);
            if (targetPid == -1) {
                DfxLogError("Failed to get real target.");
                return dumpRes;
            }
            request->SetPid(targetPid);
        }

        if (DfxConfig::GetInstance().GetLogPersist()) {
            InitDebugLog((int)type, targetPid, targetTid, request->GetUid());
        }

        DfxLogDebug("processdump tid:%d, targetPid:%d, targetTid:%d.", tid, targetPid, targetTid);
        // if Nspid is enabled, target tid and real tid should be paresed from /proc/pid/task
        std::shared_ptr<DfxThread> keyThread = isCrash ?
            std::make_shared<DfxThread>(targetPid, targetTid, targetTid, request->GetContext()) :
            std::make_shared<DfxThread>(targetPid, tid == 0 ? targetPid : tid, targetTid);
        if (!keyThread->Attach()) {
            DfxLogError("Fail to attach key thread.");
            dumpRes = ProcessDumpRes::DUMP_EATTACH;
            break;
        }

        keyThread->SetIsCrashThread(true);
        if ((keyThread->GetThreadName()).empty()) {
            keyThread->SetThreadName(storeThreadName);
        }

        process = DfxProcess::CreateProcessWithKeyThread(targetPid, keyThread);
        if (!process) {
            DfxLogError("Fail to init process with key thread.");
            dumpRes = ProcessDumpRes::DUMP_EATTACH;
            break;
        }

        if ((process->GetProcessName()).empty()) {
            process->SetProcessName(storeProcessName);
        }

        process->SetIsSignalDump(!isCrash);
        process->SetNs(isPidNsEnabled);
        process->SetUid(request->GetUid());
        process->SetRecycleTid(request->GetRecycleTid());
        if (tid == 0) {
            process->InitOtherThreads(isCrash);
        }

        if (InitPrintThread(true, request, process) < 0) {
            DfxLogError("Failed to init print thread.");
            dumpRes = ProcessDumpRes::DUMP_EGETFD;
        }

        PrintDumpProcessWithSignalContextHeader(process, request);

        if (DfxUnwindRemote::GetInstance().UnwindProcess(process) == false) {
            DfxLogError("Failed to unwind process.");
            dumpRes = ProcessDumpRes::DUMP_ESTOPUNWIND;
        }

        if (!isPidNsEnabled && (syscall(SYS_getppid) != request->GetPid())) {
            DfxRingBufferWrapper::GetInstance().AppendBuf(
                "Target process has been killed, the crash log may not be fully generated.");
            dumpRes = ProcessDumpRes::DUMP_EGETPPID;
            break;
        }
    } while (false);

    return dumpRes;
}

void ProcessDumper::Dump()
{
    std::shared_ptr<ProcessDumpRequest> request = std::make_shared<ProcessDumpRequest>();
    if (!request) {
        DfxLogError("Failed to create dump request.");
        return;
    }

    std::shared_ptr<DfxProcess> process = nullptr;
    resDump_ = DumpProcessWithSignalContext(process, request);
    if (process == nullptr) {
        DfxLogError("Dump process failed, please check permission and whether pid is valid.");
    } else {
        if (process->GetIsSignalDump()) {
            process->Detach();
        }
    }

    WriteDumpRes(resDump_);
    DfxRingBufferWrapper::GetInstance().StopThread();
    DfxLogInfo("Finish dump stacktrace for %s(%d:%d).",
        request->GetProcessNameString().c_str(), request->GetPid(), request->GetTid());
    CloseDebugLog();

    if (reporter_ != nullptr) {
        reporter_->ReportToHiview();
    }

    _exit(0);
}

int ProcessDumper::WriteDumpBuf(int fd, const char* buf, const int len)
{
    if (buf == nullptr) {
        return -1;
    }
    return WriteLog(fd, "%s", buf);
}

void ProcessDumper::WriteDumpRes(int32_t res)
{
    DfxLogDebug("%s :: res: %d", __func__, res);
    DumpResMsg dumpResMsg;
    dumpResMsg.res = res;
    const char* strRes = DfxDumpRes::GetInstance().GetResStr(res);
    if (strncpy_s(dumpResMsg.strRes, sizeof(dumpResMsg.strRes), strRes, strlen(strRes)) != 0) {
        DfxLogError("%s :: strncpy failed.", __func__);
    }
    if (resFd_ > 0) {
        write(resFd_, &dumpResMsg, sizeof(struct DumpResMsg));
    } else {
        if (res != DUMP_ESUCCESS) {
            DfxRingBufferWrapper::GetInstance().AppendMsg("Result:\n");
            DfxRingBufferWrapper::GetInstance().AppendMsg(DfxDumpRes::GetInstance().ToString() + "\n");
        }
    }
}

} // namespace HiviewDFX
} // namespace OHOS
