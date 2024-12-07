/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include "backtrace_local.h"

#include <cstring>
#include <mutex>
#include <vector>

#include <unistd.h>

#include "backtrace_local_thread.h"
#include "elapsed_time.h"
#include "dfx_frame_formatter.h"
#include "dfx_kernel_stack.h"
#include "dfx_log.h"
#include "dfx_util.h"
#include "directory_ex.h"
#include "procinfo.h"
#include "unwinder.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_TAG "DfxBacktrace"
#define LOG_DOMAIN 0xD002D11
}

bool GetBacktraceFramesByTid(std::vector<DfxFrame>& frames, int32_t tid, size_t skipFrameNum, bool fast,
                             size_t maxFrameNums)
{
    std::shared_ptr<Unwinder> unwinder = nullptr;
#ifdef __aarch64__
    if (fast || (tid != BACKTRACE_CURRENT_THREAD)) {
        unwinder = std::make_shared<Unwinder>(false);
    }
#endif
    if (unwinder == nullptr) {
        unwinder = std::make_shared<Unwinder>();
    }
    BacktraceLocalThread thread(tid, unwinder);
    bool ret = thread.Unwind(fast, maxFrameNums, skipFrameNum + 1);
    frames = thread.GetFrames();
    return ret;
}

bool GetBacktraceStringByTid(std::string& out, int32_t tid, size_t skipFrameNum, bool fast,
                             size_t maxFrameNums, bool enableKernelStack)
{
    std::vector<DfxFrame> frames;
    bool ret = GetBacktraceFramesByTid(frames, tid, skipFrameNum + 1, fast, maxFrameNums);
    if (!ret && enableKernelStack) {
        std::string msg = "";
        DfxThreadStack threadStack;
        if (DfxGetKernelStack(tid, msg) == 0 && FormatThreadKernelStack(msg, threadStack)) {
            frames = threadStack.frames;
            ret = true;
            DFXLOGI("Failed to get tid(%{public}d) user stack, try kernel", tid);
        }
    }
    if (ret) {
        out.clear();
        std::string threadHead = GetThreadHead(tid);
        out = threadHead + Unwinder::GetFramesStr(frames);
    }
    return ret;
}

bool PrintBacktrace(int32_t fd, bool fast, size_t maxFrameNums)
{
    DFXLOGI("Receive PrintBacktrace request.");
    std::vector<DfxFrame> frames;
    bool ret = GetBacktraceFramesByTid(frames,
        BACKTRACE_CURRENT_THREAD, 1, fast, maxFrameNums); // 1: skip current frame
    if (!ret) {
        return false;
    }

    for (auto const& frame : frames) {
        auto line = DfxFrameFormatter::GetFrameStr(frame);
        if (fd >= 0) {
            dprintf(fd, "    %s", line.c_str());
        }
        DFXLOGI(" %{public}s", line.c_str());
    }
    return ret;
}

bool GetBacktrace(std::string& out, bool fast, size_t maxFrameNums)
{
    ElapsedTime et;
    bool ret = GetBacktraceStringByTid(out, BACKTRACE_CURRENT_THREAD, 1,
                                       fast, maxFrameNums, false); // 1: skip current frame
    DFXLOGI("GetBacktrace elapsed time: %{public}" PRId64 " ms", et.Elapsed<std::chrono::milliseconds>());
    return ret;
}

bool GetBacktrace(std::string& out, size_t skipFrameNum, bool fast, size_t maxFrameNums)
{
    ElapsedTime et;
    bool ret = GetBacktraceStringByTid(out, BACKTRACE_CURRENT_THREAD, skipFrameNum + 1, fast, maxFrameNums, false);
    DFXLOGI("GetBacktrace with skip, elapsed time: %{public}" PRId64 " ms", et.Elapsed<std::chrono::milliseconds>());
    return ret;
}

bool PrintTrace(int32_t fd, size_t maxFrameNums)
{
    return PrintBacktrace(fd, false, maxFrameNums);
}

const char* GetTrace(size_t skipFrameNum, size_t maxFrameNums)
{
    static std::string trace;
    trace.clear();
    if (!GetBacktrace(trace, skipFrameNum, false, maxFrameNums)) {
        DFXLOGE("Failed to get trace string");
    }
    return trace.c_str();
}

std::string GetProcessStacktrace(size_t maxFrameNums, bool enableKernelStack)
{
    auto unwinder = std::make_shared<Unwinder>();
    std::string ss = "\n" + GetStacktraceHeader();
    std::function<bool(int)> func = [&](int tid) {
        if (tid <= 0 || tid == gettid()) {
            return false;
        }
        BacktraceLocalThread thread(tid, unwinder);
        if (thread.Unwind(false, maxFrameNums, 0)) {
            ss += thread.GetFormattedStr(true) + "\n";
        } else if (enableKernelStack) {
            std::string msg = "";
            DfxThreadStack threadStack;
            if (DfxGetKernelStack(tid, msg) == 0 && FormatThreadKernelStack(msg, threadStack)) {
                thread.SetFrames(threadStack.frames);
                ss += thread.GetFormattedStr(true) + "\n";
                DFXLOGI("Failed to get tid(%{public}d) user stack, try kernel", tid);
            }
        }
        return true;
    };

    std::vector<int> tids;
    GetTidsByPidWithFunc(getpid(), tids, func);

    return ss;
}
} // namespace HiviewDFX
} // namespace OHOS
