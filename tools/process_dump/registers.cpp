/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "decorative_dump_info.h"
#include "dfx_log.h"
#include "dfx_buffer_writer.h"
namespace OHOS {
namespace HiviewDFX {
REGISTER_DUMP_INFO_CLASS(Registers);

void Registers::Print(DfxProcess& process, const ProcessDumpRequest& request, Unwinder& unwinder)
{
    DecorativeDumpInfo::Print(process, request, unwinder);
    // Registers of unwThread has been changed, we should print regs from request context.
    process.SetFaultThreadRegisters(DfxRegs::CreateFromUcontext(request.context));
    if (process.GetFaultThreadRegisters() == nullptr) {
        DFXLOGE("Fault thread regs is nullptr!");
        return;
    }
    std::string regsStr = process.GetFaultThreadRegisters()->PrintRegs();
    DfxBufferWriter::GetInstance().WriteMsg(regsStr);
    DfxBufferWriter::GetInstance().AppendBriefDumpInfo(regsStr);
}
}
}