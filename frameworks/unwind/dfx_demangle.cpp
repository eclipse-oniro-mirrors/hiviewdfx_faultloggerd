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

#include "dfx_demangle.h"

#include <algorithm>
#include <cstdlib>
#include <cxxabi.h>
#include "dfx_define.h"
#include "dfx_log.h"
#include "string_util.h"
#ifdef RUSTC_DEMANGLE
#include "rustc_demangle.h"
#endif

namespace OHOS {
namespace HiviewDFX {
static const std::string LINKER_PREFIX = "__dl_";
static const std::string LINKER_PREFIX_NAME = "[linker]";

std::string DfxDemangle::Demangle(const std::string buf)
{
    if (buf.empty()) {
        return "";
    }

    std::string funcName;
    const char *bufStr = buf.c_str();
    bool isLinkerName = false;
    if (StartsWith(buf, LINKER_PREFIX)) {
        bufStr += LINKER_PREFIX.size();
        isLinkerName = true;
        funcName += LINKER_PREFIX_NAME;
    }

    int status = 0;
    auto name = abi::__cxa_demangle(bufStr, nullptr, nullptr, &status);
#ifdef RUSTC_DEMANGLE
    if (name == nullptr) {
        DFXLOG_DEBUG("Fail to __cxa_demangle(%s), will rustc_demangle.", bufStr);
        name = rustc_demangle(bufStr);
    }
#endif
    std::string demangleName;
    if (name != nullptr) {
        demangleName = std::string(name);
        std::free(name);
    } else {
        demangleName = std::string(bufStr);
    }
    funcName += demangleName;
    return funcName;
}
} // namespace HiviewDFX
} // namespace OHOS
