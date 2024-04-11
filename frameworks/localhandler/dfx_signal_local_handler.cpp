/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "dfx_signal_local_handler.h"

#include <securec.h>
#include <csignal>
#include <sigchain.h>
#include <cstdint>
#include <cstdio>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <sys/wait.h>
#include <linux/futex.h>
#include "dfx_allocator.h"
#include "dfx_crash_local_handler.h"
#include "dfx_cutil.h"
#include "dfx_log.h"

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002D11
#endif

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "DfxSignalLocalHandler"
#endif

#define LOCAL_HANDLER_STACK_SIZE (128 * 1024) // 128K

static CrashFdFunc g_crashFdFn = nullptr;
static void *g_reservedChildStack = nullptr;
static struct ProcessDumpRequest g_request;
static pthread_mutex_t g_signalHandlerMutex = PTHREAD_MUTEX_INITIALIZER;

static int g_platformSignals[] = {
    SIGABRT, SIGBUS, SIGILL, SIGSEGV,
};

static void ReserveChildThreadSignalStack(void)
{
    // reserve stack for fork
    g_reservedChildStack = mmap(nullptr, LOCAL_HANDLER_STACK_SIZE, \
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, 1, 0);
    if (g_reservedChildStack == MAP_FAILED) {
        DFXLOG_ERROR("Failed to alloc memory for child stack.");
        return;
    }
    g_reservedChildStack = static_cast<void *>(static_cast<uint8_t *>(g_reservedChildStack) +
        LOCAL_HANDLER_STACK_SIZE - 1);
}

AT_UNUSED static void FutexWait(volatile void* ftx, int value)
{
    syscall(__NR_futex, ftx, FUTEX_WAIT, value, NULL, NULL, 0);
}

static int DoCrashHandler(void* arg)
{
    (void)arg;
    RegisterAllocator();
    if (g_crashFdFn == nullptr) {
        CrashLocalHandler(&g_request);
    } else {
        int fd = g_crashFdFn();
        CrashLocalHandlerFd(fd, &g_request);
    }
    UnregisterAllocator();
    pthread_mutex_unlock(&g_signalHandlerMutex);
    syscall(__NR_exit, 0);
    return 0;
}

static void DFX_SignalLocalHandler(int sig, siginfo_t * si, void * context)
{
    pthread_mutex_lock(&g_signalHandlerMutex);
    (void)memset_s(&g_request, sizeof(g_request), 0, sizeof(g_request));
    g_request.type = static_cast<ProcessDumpType>(sig);
    g_request.tid = gettid();
    g_request.pid = getpid();
    g_request.timeStamp = GetTimeMilliseconds();
    DFXLOG_INFO("DFX_SignalLocalHandler :: sig(%d), pid(%d), tid(%d).", sig, g_request.pid, g_request.tid);

    GetThreadNameByTid(g_request.tid, g_request.threadName, sizeof(g_request.threadName));
    GetProcessName(g_request.processName, sizeof(g_request.processName));

    int ret = memcpy_s(&(g_request.siginfo), sizeof(siginfo_t), si, sizeof(siginfo_t));
    if (ret < 0) {
        DFXLOG_ERROR("memcpy_s siginfo fail, ret=%d", ret);
    }
    ret = memcpy_s(&(g_request.context), sizeof(ucontext_t), context, sizeof(ucontext_t));
    if (ret < 0) {
        DFXLOG_ERROR("memcpy_s context fail, ret=%d", ret);
    }
#ifdef __aarch64__
    DoCrashHandler(NULL);
#else
    int pseudothreadTid = -1;
    pid_t childTid = clone(DoCrashHandler, g_reservedChildStack, \
        CLONE_THREAD | CLONE_SIGHAND | CLONE_VM | CLONE_CHILD_SETTID | CLONE_CHILD_CLEARTID, \
        &pseudothreadTid, NULL, NULL, &pseudothreadTid);
    if (childTid == -1) {
        DFXLOG_ERROR("Failed to create thread for crash local handler");
        pthread_mutex_unlock(&g_signalHandlerMutex);
        return;
    }

    FutexWait(&pseudothreadTid, -1);
    FutexWait(&pseudothreadTid, childTid);

    DFXLOG_INFO("child thread(%d) exit.", childTid);
    syscall(__NR_exit, 0);
#endif
}

void DFX_GetCrashFdFunc(CrashFdFunc fn)
{
    g_crashFdFn = fn;
}

void DFX_InstallLocalSignalHandler(void)
{
    ReserveChildThreadSignalStack();

    sigset_t set;
    sigemptyset(&set);
    struct sigaction action;
    (void)memset_s(&action, sizeof(action), 0, sizeof(action));
    sigfillset(&action.sa_mask);
    action.sa_sigaction = DFX_SignalLocalHandler;
    action.sa_flags = SA_RESTART | SA_SIGINFO | SA_ONSTACK;

    for (size_t i = 0; i < sizeof(g_platformSignals) / sizeof(g_platformSignals[0]); i++) {
        int32_t sig = g_platformSignals[i];
        remove_all_special_handler(sig);

        sigaddset(&set, sig);
        if (sigaction(sig, &action, nullptr) != 0) {
            DFXLOG_ERROR("Failed to register signal(%d)", sig);
        }
    }
    sigprocmask(SIG_UNBLOCK, &set, nullptr);
}
