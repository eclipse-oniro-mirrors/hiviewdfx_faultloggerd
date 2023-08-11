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

#include "dfx_frame_format.h"
#include <sstream>
#include <securec.h>
#include "dfx_log.h"
#include "dfx_define.h"
#include "string_printf.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxFrameFormat"
}


std::string DfxFrameFormat::GetFrameStr(const DfxFrame& frame)
{
    return GetFrameStr(std::make_shared<DfxFrame>(frame));
}

std::string DfxFrameFormat::GetFrameStr(const std::shared_ptr<DfxFrame>& frame)
{
    std::string data;
#ifdef __LP64__
    data = StringPrintf("#%02zu pc %016" PRIx64, frame->index, frame->relPc);
#else
    data = StringPrintf("#%02zu pc %08" PRIx64, frame->index, frame->relPc);
#endif

    if (!frame->mapName.empty()) {
        data += "  " + frame->mapName;
    } else {
        data += "  [Unknown]";
    }

    if (!frame->funcName.empty()) {
        data += " (" + frame->funcName;
        data += StringPrintf("+%" PRId64, frame->funcOffset);
        data += ')';
    }
    if (!frame->buildId.empty()) {
        data += "(" + frame->buildId + ')';
    }
    data += "\n";
    return data;
}

std::string DfxFrameFormat::GetFramesStr(const std::vector<DfxFrame>& frames)
{
    if (frames.size() == 0) {
        return "";
    }
    std::ostringstream ss;
    for (const auto& frame : frames) {
        ss << GetFrameStr(frame);
    }
    return ss.str();
}

std::string DfxFrameFormat::GetFramesStr(const std::vector<std::shared_ptr<DfxFrame>>& frames)
{
    if (frames.size() == 0) {
        return "";
    }
    std::ostringstream ss;
    for (const auto& frame : frames) {
        ss << GetFrameStr(frame);
    }
    return ss.str();
}

std::vector<std::shared_ptr<DfxFrame>> DfxFrameFormat::ConvertFrames(const std::vector<DfxFrame>& frames)
{
    std::vector<std::shared_ptr<DfxFrame>> ptrFrames;
    for (const auto& frame : frames) {
        ptrFrames.push_back(std::make_shared<DfxFrame>(frame));
    }
    return ptrFrames;
}
} // namespace HiviewDFX
} // namespace OHOS
