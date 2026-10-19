/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef DFX_INSTRUCTIONS_H
#define DFX_INSTRUCTIONS_H

#include <cstdint>
#include <string>

#include "dfx_memory.h"
#include "dfx_regs.h"
#include "unwind_context.h"

namespace OHOS {
namespace HiviewDFX {
class DfxInstructions {
public:
    DfxInstructions() = default;
    virtual ~DfxInstructions() = default;

    static bool Apply(std::shared_ptr<DfxMemory> memory, DfxRegs& regs, RegLocState& rsState, uint16_t& errCode);

private:
    // Flush 求值单个 RegLoc 并把结果写入 val。当该 RegLoc 是含 AOSP16 DEX1
    // 魔数标记的 DWARF 表达式时,is_dex_pc 置 true,调用方(Apply)应把 val
    // 存入 dex_pc 伪寄存器而非普通寄存器槽位。内存读取/求值失败返回 false。
    static bool Flush(DfxRegs& dfxRegs, std::shared_ptr<DfxMemory> memory, uintptr_t cfa, RegLoc loc,
                      uintptr_t& val, bool& is_dex_pc);
    static bool GetCfa(DfxRegs& regs, std::shared_ptr<DfxMemory> memory, RegLocState& rsState,
                       uintptr_t& cfa, uint16_t& errCode);
};
} // namespace HiviewDFX
} // namespace OHOS

#endif
