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

/* This files contains process dump entry function. */

#include <cstdlib>
#include <cstdio>
#include <cstring>
#include <iostream>
#include <securec.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#include "directory_ex.h"
#include "faultloggerd_client.h"
#include "file_ex.h"

#include "dfx_config.h"
#include "dfx_define.h"
#include "dfx_dump_writer.h"
#include "dfx_log.h"
#include "process_dumper.h"

#if defined(DEBUG_PROCESS_DUMP_CRASH)
#include "dfx_crash_local_handler.h"
#include "dfx_cutil.h"
#include "dfx_signal_handler.h"
#endif

static const int SIGNAL_HANDLER = 1;
static const int DUMP_THIRD = 3;
static const int DUMP_FIVE = 5;
static const int DUMP_ARG_TWO = 2;
static const int DUMP_ARG_THREE = 3;
static const int DUMP_ARG_FOUR = 4;

static const std::string DUMP_STACK_TAG_USAGE = "usage:";
static const std::string DUMP_STACK_TAG_FAILED = "failed:";

static void PrintCommandHelp()
{
    std::cout << DUMP_STACK_TAG_USAGE << std::endl;
    std::cout << "-p pid -t tid    dump the stacktrace of the thread with given tid." << std::endl;
    std::cout << "-p pid    dump the stacktrace of all the threads with given pid." << std::endl;
}

static void PrintPermissionCheckFailed()
{
    std::cout << DUMP_STACK_TAG_FAILED << std::endl;
    std::cout << "Only BMS and the process owner can dump stacktrace." << std::endl;
}

static void PrintFailedConnect()
{
    std::cout << DUMP_STACK_TAG_FAILED << std::endl;
    std::cout << "faultloggerd is not available" << std::endl;
}

static void PrintPidTidCheckFailed(int32_t pid, int32_t tid)
{
    std::cout << DUMP_STACK_TAG_FAILED << std::endl;
    std::cout << "The " << tid  << " is not a thread of " << pid << std::endl;
    std::cout << "The pid or tid is invalid." << std::endl;
}

// Check whether the tid is owned by pid.
static bool CheckPidTid(OHOS::HiviewDFX::ProcessDumpType type, int32_t pid, int32_t tid)
{
    // check pid
    if ((pid == 0) || (pid < 0)) {
        DfxLogWarn("pid is zero or negative.");
        return false;
    }

    // user specified a tid, we need to check tid / pid is valid or not.
    if (type == OHOS::HiviewDFX::DUMP_TYPE_THREAD) {
        if (tid > 0) {
            std::vector<std::string> files;

            std::string path = "/proc/" + std::to_string(pid) + "/task/" + std::to_string(tid);

            OHOS::GetDirFiles(path, files);
            if (files.size() == 0) {
                DfxLogWarn("Cannot find tid(%d) in process(%d).", tid, pid);
                return false;
            }
        } else {
            DfxLogWarn("tid is zero or negative.");
            return false;
        }
    }

    // check pid, make sure /proc/xxx/maps is valid.
    if (pid > 0) {
        std::vector<std::string> files;
        std::string path = "/proc/" + std::to_string(pid);

        OHOS::GetDirFiles(path, files);
        if (files.size() == 0) {
            DfxLogWarn("Cannot find pid(%d) in /proc.", pid);
            return false;
        }
    } else {
        DfxLogWarn("pid is zero or negative.");
        return false;
    }

    return true;
}

static bool ParseParamters(int argc, char *argv[], bool &isSignalHdlr, OHOS::HiviewDFX::ProcessDumpType &type,
    int32_t &pid, int32_t &tid)
{
    switch (argc) {
        case SIGNAL_HANDLER:
            if (!strcmp("-signalhandler", argv[0])) {
                isSignalHdlr = true;
                return true;
            }
            break;
        case DUMP_THIRD:
            if (!strcmp("-p", argv[1])) {
                type = OHOS::HiviewDFX::DUMP_TYPE_PROCESS;
                pid = atoi(argv[DUMP_ARG_TWO]);
                return true;
            }
            break;
        case DUMP_FIVE:
            if (!strcmp("-p", argv[1])) {
                type = OHOS::HiviewDFX::DUMP_TYPE_PROCESS;
                pid = atoi(argv[DUMP_ARG_TWO]);

                if (!strcmp("-t", argv[DUMP_ARG_THREE])) {
                    type = OHOS::HiviewDFX::DUMP_TYPE_THREAD;
                    tid = atoi(argv[DUMP_ARG_FOUR]);
                    return true;
                }
            } else if (!strcmp("-t", argv[1])) {
                type = OHOS::HiviewDFX::DUMP_TYPE_THREAD;
                tid = atoi(argv[DUMP_ARG_TWO]);

                if (!strcmp("-p", argv[DUMP_ARG_THREE])) {
                    pid = atoi(argv[DUMP_ARG_FOUR]);
                    return true;
                }
            }
            break;
        default:
            break;
    }
    return false;
}

#if defined(DEBUG_PROCESS_DUMP_CRASH)
static struct ProcessDumpRequest g_request;
static void InitDumpRequest(int sig)
{
    (void)memset_s(&g_request, sizeof(g_request), 0, sizeof(g_request));
    if (strncpy_s(g_request.processName, sizeof(g_request.processName), "processdump", strlen("processdump")) != 0) {
        DfxLogWarn("Failed to set process name.");
    }

    g_request.type = sig;
    g_request.tid = gettid();
    g_request.pid = getpid();
    g_request.uid = (int32_t)getuid();
    g_request.reserved = 0;
    g_request.timeStamp = GetTimeMillseconds();
    GetThreadName(g_request.threadName, sizeof(g_request.threadName));
}

static void SignalHandler(int sig, siginfo_t *si, void *context)
{
    InitDumpRequest(sig);
    CrashLocalHandler(&g_request, si, (ucontext *)context);
}

static void RegisterLocalSighandler()
{
    sigset_t set;
    sigemptyset (&set);
    struct sigaction action;
    memset_s(&action, sizeof(action), 0, sizeof(action));
    sigfillset(&action.sa_mask);
    action.sa_sigaction = SignalHandler;
    action.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;
    int platformSignals[] = {
        SIGABRT, SIGBUS, SIGILL, SIGSEGV
    };
    for (size_t i = 0; i < sizeof(platformSignals) / sizeof(platformSignals[0]); i++) {
        int32_t sig = platformSignals[i];
        sigaddset(&set, sig);
        if (sigaction(sig, &action, nullptr) != 0) {
            DfxLogError("Failed to register signal. %{public}d", sig);
        }
    }
    sigprocmask(SIG_UNBLOCK, &set, NULL);
}
#endif

int main(int argc, char *argv[])
{
#if defined(DEBUG_PROCESS_DUMP_CRASH)
    RegisterLocalSighandler();
#endif
    bool isSignalHdlr = false;
    OHOS::HiviewDFX::ProcessDumpType type = OHOS::HiviewDFX::DUMP_TYPE_PROCESS;
    int32_t pid = 0;
    int32_t tid = 0;

    alarm(PROCESSDUMP_TIMEOUT); // wait 30s for process dump done
    setsid();
    if (!ParseParamters(argc, argv, isSignalHdlr, type, pid, tid)) {
        PrintCommandHelp();
        return 0;
    }

    if (!isSignalHdlr) { // We need do permission check when "false == isSignalHdlr" dump.
        if (!CheckConnectStatus()) {
            PrintFailedConnect();
            return 0;
        }
        if (!CheckPidTid(type, pid, tid)) { // check pid tid is valid
            PrintPidTidCheckFailed(pid, tid);
            return 0;
        }
        if (!RequestCheckPermission(pid)) { // check permission
            PrintPermissionCheckFailed();
            return 0;
        }
    }

    OHOS::HiviewDFX::DfxConfig::GetInstance().ReadConfig();
    OHOS::HiviewDFX::ProcessDumper::GetInstance().Dump(isSignalHdlr, type, pid, tid);

    return 0;
}
