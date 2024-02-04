/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include "dfx_stack_info_formatter.h"

#include <cinttypes>
#include <string>

#include "dfx_logger.h"
#include "dfx_process.h"
#include "dfx_signal.h"
#include "dfx_thread.h"
#include "process_dumper.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
static const char NATIVE_CRASH_TYPE[] = "NativeCrash";

void FillJsFrame(const DfxFrame& frame, Json::Value& jsonInfo)
{
    Json::Value frameJson;
    frameJson["file"] = frame.mapName;
    frameJson["symbol"] = frame.funcName;
    frameJson["line"] = frame.line;
    frameJson["column"] = frame.column;
    jsonInfo.append(frameJson);
}
}

bool DfxStackInfoFormatter::GetStackInfo(bool isJsonDump, std::string& jsonStringInfo) const
{
    bool result = false;
#ifndef is_ohos_lite
    DFXLOG_DEBUG("GetStackInfo isJsonDump:%d", isJsonDump);
    Json::Value jsonInfo;
    if (!GetStackInfo(isJsonDump, jsonInfo)) {
        return result;
    }
    jsonStringInfo.append(Json::FastWriter().write(jsonInfo));
    result = true;
#endif
    return result;
}

#ifndef is_ohos_lite
bool DfxStackInfoFormatter::GetStackInfo(bool isJsonDump, Json::Value& jsonInfo) const
{
    if ((process_ == nullptr) || (request_ == nullptr)) {
        DFXLOG_ERROR("GetStackInfo var is null");
        return false;
    }
    if (isJsonDump) {
        GetDumpInfo(jsonInfo);
    } else {
        GetNativeCrashInfo(jsonInfo);
    }
    return true;
}

void DfxStackInfoFormatter::GetNativeCrashInfo(Json::Value& jsonInfo) const
{
    jsonInfo["time"] = request_->timeStamp;
    jsonInfo["uuid"] = "";
    jsonInfo["crash_type"] = NATIVE_CRASH_TYPE;
    jsonInfo["pid"] = process_->processInfo_.pid;
    jsonInfo["uid"] = process_->processInfo_.uid;

    Json::Value signal;
    signal["signo"] = request_->siginfo.si_signo;
    signal["code"] = request_->siginfo.si_code;
    Json::Value exception;
    exception["signal"] = signal;
    exception["message"] = process_->GetFatalMessage();
    exception["thread_name"] = process_->keyThread_->threadInfo_.threadName;
    exception["tid"] = process_->keyThread_->threadInfo_.tid;
    Json::Value frames;
    if (process_->vmThread_ != nullptr) {
        FillFrames(process_->vmThread_, frames);
    } else {
        FillFrames(process_->keyThread_, frames);
    }
    exception["frames"] = frames;
    jsonInfo["exception"] = exception;

    // fill other thread info
    auto otherThreads = process_->GetOtherThreads();
    if (otherThreads.size() > 0) {
        Json::Value threadsJsonArray;
        AppendThreads(otherThreads, threadsJsonArray, true);
        jsonInfo["threads"] = threadsJsonArray;
    }
}

void DfxStackInfoFormatter::GetDumpInfo(Json::Value& jsonInfo) const
{
    Json::Value thread;
    thread["thread_name"] = process_->keyThread_->threadInfo_.threadName;
    thread["tid"] = process_->keyThread_->threadInfo_.tid;
    Json::Value frames;
    FillFrames(process_->keyThread_, frames);
    thread["frames"] = frames;
    jsonInfo.append(thread);

    // fill other thread info
    auto otherThreads = process_->GetOtherThreads();
    if (otherThreads.size() > 0) {
        AppendThreads(otherThreads, jsonInfo, false);
    }
}

bool DfxStackInfoFormatter::FillFrames(const std::shared_ptr<DfxThread>& thread,
                                       Json::Value& jsonInfo, int maxFrame) const
{
    if (thread == nullptr) {
        DFXLOG_ERROR("FillFrames thread is null");
        return false;
    }
    const auto& threadFrames = thread->GetFrames();
    int frameIndex = 0;
    for (const auto& frame : threadFrames) {
        if (frameIndex >= maxFrame) {
            break;
        }

        if (frame.isJsFrame) {
            FillJsFrame(frame, jsonInfo);
            frameIndex++;
            continue;
        }

        FillNativeFrame(frame, jsonInfo);
        frameIndex++;
    }
    return true;
}

void DfxStackInfoFormatter::FillNativeFrame(const DfxFrame& frame, Json::Value& jsonInfo) const
{
    Json::Value frameJson;
#ifdef __LP64__
    frameJson["pc"] = StringPrintf("%016lx", frame.relPc);
#else
    frameJson["pc"] = StringPrintf("%08llx", frame.relPc);
#endif
    frameJson["symbol"] = frame.funcName;
    frameJson["offset"] = frame.funcOffset;
    frameJson["file"] = frame.mapName;
    frameJson["buildId"] = frame.buildId;
    jsonInfo.append(frameJson);
}

void DfxStackInfoFormatter::AppendThreads(const std::vector<std::shared_ptr<DfxThread>>& threads,
                                          Json::Value& jsonInfo, bool isCrash) const
{
    int index = 0;
    for (auto const& oneThread : threads) {
        Json::Value threadJson;
        threadJson["thread_name"] = oneThread->threadInfo_.threadName;
        threadJson["tid"] = oneThread->threadInfo_.tid;
        Json::Value frames;
        FillFrames(oneThread, frames, isCrash ? 32 : DEFAULT_MAX_FRAME_NUM);
        threadJson["frames"] = frames;
        jsonInfo.append(threadJson);
        index++;
        if (isCrash && index > 10) { // 10 : thread numbers limit
            break;
        }
    }
}
#endif
} // namespace HiviewDFX
} // namespace OHOS
