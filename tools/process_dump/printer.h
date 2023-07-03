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

#ifndef CPP_CRASH_PRINTER_H
#define CPP_CRASH_PRINTER_H

#include <cinttypes>
#include <csignal>
#include <memory>
#include <string>
#include "dfx_dump_request.h"
#include "dfx_process.h"
#include "dfx_thread.h"

namespace OHOS {
namespace HiviewDFX {
class Printer {
public:
    static void PrintDumpHeader(std::shared_ptr<ProcessDumpRequest> request, std::shared_ptr<DfxProcess> process);
    static void PrintProcessMapsByConfig(std::shared_ptr<DfxProcess> process);
    static void PrintOtherThreadHeaderByConfig();
    static void PrintThreadHeaderByConfig(std::shared_ptr<DfxThread> thread);
    static void PrintThreadBacktraceByConfig(std::shared_ptr<DfxThread> thread);
    static void PrintThreadRegsByConfig(std::shared_ptr<DfxThread> thread);
    static void PrintThreadFaultStackByConfig(std::shared_ptr<DfxProcess> process, std::shared_ptr<DfxThread> thread);
};
} // namespace HiviewDFX
} // namespace OHOS
#endif
