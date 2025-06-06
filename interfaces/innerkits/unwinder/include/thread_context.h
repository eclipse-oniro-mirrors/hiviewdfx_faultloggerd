/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef THREAD_CONTEXT_H
#define THREAD_CONTEXT_H

#include <atomic>
#include <cstdint>
#include <condition_variable>
#include <csignal>
#include <mutex>
#include <nocopyable.h>
#include <string>
#include <vector>

#include "dfx_define.h"
#include "dfx_maps.h"
#include "dfx_regs.h"

namespace OHOS {
namespace HiviewDFX {
enum ThreadContextStatus : int32_t {
    CONTEXT_UNUSED = -1,
    CONTEXT_READY = -2,
};

struct ThreadContext {
    std::atomic<int32_t> tid {ThreadContextStatus::CONTEXT_UNUSED};
    // for protecting ctx, shared between threads
    std::mutex mtx;
    // the thread should be suspended while unwinding
    // blocked in the signal handler of target thread
    std::condition_variable cv;
    // store unwind context
    ucontext_t* ctx {nullptr};
    // stack range
    uintptr_t stackBottom;
    uintptr_t stackTop;
#if defined(__aarch64__)
    // unwind in signal handler by fp
    uintptr_t pcs[DEFAULT_MAX_LOCAL_FRAME_NUM] {0};
#endif
    std::atomic<size_t> frameSz {0};
    // first stack pointer
    uintptr_t firstFrameSp;

    ~ThreadContext()
    {
        std::unique_lock<std::mutex> lock(mtx);
        if (ctx != nullptr) {
            delete ctx;
            ctx = nullptr;
        }
    };
};

class LocalThreadContext {
public:
    static LocalThreadContext& GetInstance();

    bool GetStackRange(int32_t tid, uintptr_t& stackBottom, uintptr_t& stackTop);
    std::shared_ptr<ThreadContext> CollectThreadContext(int32_t tid);
    std::shared_ptr<ThreadContext> GetThreadContext(int32_t tid);
    void ReleaseThread(int32_t tid);
    void CleanUp();

private:
    LocalThreadContext() = default;
    DISALLOW_COPY_AND_MOVE(LocalThreadContext);

    bool SignalRequestThread(int32_t tid, ThreadContext* ctx);

private:
    std::mutex localMutex_;
};

constexpr int STACK_BUFFER_SIZE = 64 * 1024;
enum SyncStatus : int32_t {
    INIT = -1,
    WAIT_CTX = 0,
    COPY_START,
    COPY_SUCCESS,
    COPY_FAILED,
};

class LocalThreadContextMix {
public:
    LocalThreadContextMix(const LocalThreadContextMix&) = delete;
    LocalThreadContextMix& operator=(const LocalThreadContextMix&) = delete;
    static LocalThreadContextMix& GetInstance();
    void ReleaseCollectThreadContext();
    bool CollectThreadContext(int32_t tid);
    bool CheckStatusValidate(int status, int32_t tid);
    bool GetSelfStackRangeInSignal();
    void CopyRegister(void *context);
    void CopyStackBuf();
    void SetRegister(std::shared_ptr<DfxRegs> regs);
    void SetStackRang(uintptr_t stackTop, uintptr_t stackBottom);
    int GetMapByPc(uintptr_t pc, std::shared_ptr<DfxMap>& map) const;
    int FindUnwindTable(uintptr_t pc, UnwindTableInfo& outTableInfo) const;
    int AccessMem(uintptr_t addr, uintptr_t *val);
    std::shared_ptr<DfxMaps> GetMaps() const;

private:
    LocalThreadContextMix() = default;
    ~LocalThreadContextMix() = default;
    bool SignalRequestThread(int32_t tid);
    void StartCollectThreadContext(int32_t tid);

private:
    std::mutex mtx_;
    std::condition_variable cv_;
    uintptr_t pc_ {0};
    uintptr_t sp_ {0};
    uintptr_t fp_ {0};
    uintptr_t lr_ {0};
    uintptr_t stackBottom_ {0};
    uintptr_t stackTop_ {0};
    std::vector<uint8_t> stackBuf_;
    int32_t tid_ = -1;
    int status_ = SyncStatus::INIT;
    std::shared_ptr<DfxMaps> maps_ = nullptr;
};
} // namespace Dfx
} // namespace OHOS
#endif
