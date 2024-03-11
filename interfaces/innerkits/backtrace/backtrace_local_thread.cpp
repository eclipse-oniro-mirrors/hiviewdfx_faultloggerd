/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "backtrace_local_thread.h"

// dfx_log header must be included in front of libunwind header
#include "dfx_log.h"

#include <link.h>
#include <libunwind.h>
#include <libunwind_i-ohos.h>
#include <mutex>
#include <pthread.h>
#include <securec.h>
#include <sstream>
#include <unistd.h>

#include "backtrace_local_context.h"
#include "dfx_define.h"
#include "dfx_frame_format.h"
#include "dfx_util.h"
#include "dwarf_unwinder.h"
#include "fp_unwinder.h"
#include "procinfo.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxBacktraceLocal"
}

BacktraceLocalThread::BacktraceLocalThread(int32_t tid) : tid_(tid)
{
    maxFrameNums_ = DEFAULT_MAX_FRAME_NUM;
    frames_.clear();
}

BacktraceLocalThread::~BacktraceLocalThread()
{
    if (tid_ != BACKTRACE_CURRENT_THREAD) {
        BacktraceLocalContext::GetInstance().CleanUp();
    }
    frames_.clear();
}

bool BacktraceLocalThread::UnwindCurrentThread(unw_addr_space_t as, std::shared_ptr<DfxSymbols> symbol,
    size_t skipFrameNum, bool fast)
{
    bool ret = false;
    unw_context_t context;
    (void)memset_s(&context, sizeof(unw_context_t), 0, sizeof(unw_context_t));
    unw_getcontext(&context);

    if (fast) {
#ifdef __aarch64__
        FpUnwinder unwinder;
        ret = unwinder.UnwindWithContext(context, skipFrameNum + 1, maxFrameNums_);
        unwinder.UpdateFrameInfo();
        frames_ = unwinder.GetFrames();
#endif
    }
    if (!ret) {
        DwarfUnwinder unwinder;
        ret = unwinder.UnwindWithContext(as, context, symbol, skipFrameNum + 1, maxFrameNums_);
        frames_ = unwinder.GetFrames();
    }
    return ret;
}

bool BacktraceLocalThread::Unwind(unw_addr_space_t as, std::shared_ptr<DfxSymbols> symbol,
    size_t skipFrameNum, bool fast, bool releaseThread)
{
    static std::mutex mutex;
    std::unique_lock<std::mutex> lock(mutex);
    bool ret = false;

    if (tid_ == BACKTRACE_CURRENT_THREAD) {
        return UnwindCurrentThread(as, symbol, skipFrameNum + 1, fast);
    } else if (tid_ < BACKTRACE_CURRENT_THREAD) {
        return ret;
    }

    auto threadContext = BacktraceLocalContext::GetInstance().CollectThreadContext(tid_);
    if (threadContext == nullptr) {
        DFXLOG_INFO("%s", "Failed to get context");
        return ret;
    }

    if (threadContext->ctx == nullptr && (threadContext->frameSz == 0)) {
        // should never happen
        DFXLOG_INFO("%s", "Failed to get frameSz");
        ReleaseThread();
        return ret;
    }

#if defined(__aarch64__)
    if (threadContext->frameSz > 0) {
        ret = true;
        FpUnwinder fpUnwinder(threadContext->pcs, threadContext->frameSz);
        fpUnwinder.UpdateFrameInfo();
        frames_ = fpUnwinder.GetFrames();
    }
#else
    if (!ret) {
        DwarfUnwinder unwinder;
        std::unique_lock<std::mutex> mlock(threadContext->lock);
        ret = unwinder.UnwindWithContext(as, *(threadContext->ctx), symbol, skipFrameNum, maxFrameNums_);
        frames_ = unwinder.GetFrames();
    }
#endif

    if (releaseThread) {
        ReleaseThread();
    }
    return ret;
}

const std::vector<DfxFrame>& BacktraceLocalThread::GetFrames() const
{
    return frames_;
}

void BacktraceLocalThread::ReleaseThread()
{
    if (tid_ > BACKTRACE_CURRENT_THREAD) {
        BacktraceLocalContext::GetInstance().ReleaseThread(tid_);
    }
}

std::string BacktraceLocalThread::GetFormattedStr(bool withThreadName, bool isJson)
{
    if (frames_.empty()) {
        return "";
    }

    std::ostringstream ss;
    if (withThreadName && (tid_ > 0)) {
        std::string threadName;
        // Tid:1676, Name:IPC_3_1676
        ReadThreadName(tid_, threadName);
        ss << "Tid:" << tid_ << ", Name:" << threadName << std::endl;
    }
    if (isJson) {
#ifndef is_ohos_lite
        ss << DfxFrameFormat::GetFramesJson(frames_);
#endif
    } else {
        ss << DfxFrameFormat::GetFramesStr(frames_);
    }
    return ss.str();
}

void BacktraceLocalThread::SetMaxFrameNums(size_t maxFrameNums)
{
    maxFrameNums_ = maxFrameNums;
}
} // namespace HiviewDFX
} // namespace OHOS
