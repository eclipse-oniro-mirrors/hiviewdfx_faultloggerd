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

#include <atomic>
#include "dfx_instructions.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>

#include "dfx_define.h"
#include "dfx_errors.h"
#include "dfx_log.h"
#include "dfx_instr_statistic.h"
#include "dfx_regs_qut.h"
#include "dwarf_op.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxInstructions"
}

bool DfxInstructions::Flush(DfxRegs& regs, std::shared_ptr<DfxMemory> memory, uintptr_t cfa, RegLoc loc,
                            uintptr_t& val, bool& is_dex_pc)
{
    if (memory == nullptr) {
        return false;
    }
    is_dex_pc = false;
    uintptr_t location;
    switch (loc.type) {
        case REG_LOC_VAL_OFFSET:
            val = cfa + static_cast<uintptr_t>(loc.val);
            break;
        case REG_LOC_MEM_OFFSET:
            location = cfa + static_cast<uintptr_t>(loc.val);
            memory->Read<uintptr_t>(location, &val);
            break;
        case REG_LOC_REGISTER:
            location = static_cast<uintptr_t>(loc.val);
            if (location >= regs.RegsSize()) {
                DFXLOGE("Illegal register location");
                return false;
            }
            val = regs[location];
            break;
        case REG_LOC_MEM_EXPRESSION: {
            DwarfOp<uintptr_t> dwarfOp(memory);
            location = dwarfOp.Eval(regs, cfa, loc.val);
            memory->Read<uintptr_t>(location, &val);
            break;
        }
        case REG_LOC_VAL_EXPRESSION: {
            DwarfOp<uintptr_t> dwarfOp(memory);
            val = dwarfOp.Eval(regs, cfa, loc.val);
            // AOSP16:DWARF 表达式以 DEX1 魔数开头(DW_OP_const4u
            // 'D' 'E' 'X' '1' DW_OP_drop)时,求值结果是解释执行 Java
            // 方法的 dex_pc。存入伪寄存器,并告知调用方不要覆盖普通
            // 寄存器槽位。
            if (dwarfOp.DexPcSet()) {
                is_dex_pc = true;
                DFXLOGU("Flush: DEX1 dex_pc detected, val=0x%{public}" PRIx64 "", (uint64_t)val);
            }
            break;
        }
        default:
            DFXLOGE("Failed to save register.");
            return false;
    }
    return true;
}

bool DfxInstructions::GetCfa(DfxRegs& regs, std::shared_ptr<DfxMemory> memory, RegLocState& rsState,
    uintptr_t& cfa, uint16_t& errCode)
{
    RegLoc cfaLoc;
    if (rsState.cfaReg != 0) {
        if (rsState.cfaReg >= regs.RegsSize()) {
            DFXLOGE("Invalid cfa reg %{public}u, out of range [0, %{public}zu)",
                rsState.cfaReg, regs.RegsSize());
            INSTR_STATISTIC(UnsupportedDefCfa, rsState.cfaReg, UNW_ERROR_DWARF_INVALID_CFA);
            errCode = UNW_ERROR_DWARF_INVALID_CFA;
            return false;
        }
        cfa = regs[rsState.cfaReg] + static_cast<int64_t>(rsState.cfaRegOffset);
    } else if (rsState.cfaExprPtr != 0) {
        bool cfaIsDexPc = false;
        cfaLoc.type = REG_LOC_VAL_EXPRESSION;
        cfaLoc.val = static_cast<intptr_t>(rsState.cfaExprPtr);
        if (!Flush(regs, memory, 0, cfaLoc, cfa, cfaIsDexPc)) {
            DFXLOGE("Failed to update cfa.");
            return false;
        }
    } else {
        static std::atomic<uint64_t> noCfaCnt {0};
        if ((noCfaCnt.fetch_add(1) % 100) == 0) {
            DFXLOGE("no cfa info exist? total: %{public}" PRIx64 "", noCfaCnt.load());
        }
        INSTR_STATISTIC(UnsupportedDefCfa, rsState.cfaReg, UNW_ERROR_NOT_SUPPORT);
        return false;
    }
    DFXLOGU("Update cfa : %{public}" PRIx64 "", (uint64_t)cfa);
    return true;
}

bool DfxInstructions::Apply(std::shared_ptr<DfxMemory> memory, DfxRegs& regs, RegLocState& rsState, uint16_t& errCode)
{
    uintptr_t cfa = 0;
    if (!GetCfa(regs, memory, rsState, cfa, errCode)) {
        return false;
    }

    for (size_t i = 0; i < rsState.locs.size(); i++) {
        // REG_LOC_UNUSED:与上一帧同值(DW_CFA_same_value)。
        // REG_LOC_UNDEFINED:本帧恢复不出该值(DW_CFA_undefined,如 ART
        // 的 .oat CFI 常在 JNI trampoline 里把 x22/dex_pc 标为 undefined)。
        // 两种情况都保留寄存器现场值。
        RegLocEnum locType = rsState.locs[i].type;
        if (locType != REG_LOC_UNUSED && locType != REG_LOC_UNDEFINED) {
            size_t reg = DfxRegsQut::GetQutRegs()[i];
            bool isDexPc = false;
            uintptr_t val = 0;
            if (Flush(regs, memory, cfa, rsState.locs[i], val, isDexPc)) {
                if (isDexPc) {
                    // CFI 把该值标记为 dex_pc -> 存入伪寄存器。DEX1 魔数
                    // 只有 ART 为 nterp_helper 的 CFI 才会命中,所以同时无
                    // 视数值置起 seen 标志:当活 x22(val_expression 读的
                    // 那个)被改写为 0 时,值为 0,但 StepNterp 仍需要知道
                    // 这是 nterp 帧,才能执行被调用者保存帧恢复、读保存的
                    // x22。
                    regs.SetDexPc(val);
                    regs.SetDexPcSeen(true);
                    DFXLOGU("Apply: set dex_pc=0x%{public}" PRIx64 " (from reg slot %{public}zu)", (uint64_t)val, i);
                } else {
                    regs[reg] = val;
                }
            } else {
                DFXLOGU("Apply: Flush failed for reg slot %{public}zu, type=%{public}d", i, (int)rsState.locs[i].type);
             }
        }
    }

    regs.SetSp(cfa);
    DFXLOGU("Apply: cfa=0x%{public}" PRIx64 ", sp set, dex_pc now=0x%{public}" PRIx64 "", (uint64_t)cfa, (uint64_t)regs.DexPc());

    if (rsState.returnAddressUndefined) {
        regs.SetPc(0);
        errCode = UNW_ERROR_RETURN_ADDRESS_UNDEFINED;
        return false;
    }
    if (rsState.returnAddressRegister >= REG_EH && rsState.returnAddressRegister < REG_LAST) {
        DFXLOGU("returnAddressRegister: %{public}d", (int)rsState.returnAddressRegister);
        regs.SetPc(regs[rsState.returnAddressRegister]);
        if (regs.GetPc() == 0) {
            // 没有恢复出调用者:RA 槽的 CFA 相对读失败,活 RA 寄存器为 0。
            // 此处返回 true 会把 pc=0 的步进标记为成功,跳过 UpdateRegsState
            // 里的 LR/nterp/JIT/fp 兜底,随后死在 CheckFrameValid。改为失败,
            // 让兜底链(首帧 LR 兜底等)接管。这恢复了被删掉的 SP 可读性
            // 检查曾提供的行为,又不必重新引入它(nterp 的 CFA 可能合法地
            // 算出不可读的 CFA,而返回地址恢复得很好)。
            errCode = UNW_ERROR_INVALID_MEMORY;
            DFXLOGU("Apply: recovered return address is 0, treat as step failure");
            return false;
        }
    } else {
        DFXLOGE("returnAddressRegister: %{public}d error", (int)rsState.returnAddressRegister);
        errCode = UNW_ERROR_ILLEGAL_VALUE;
        return false;
    }
    if (rsState.returnAddressSame) {
        errCode = UNW_ERROR_RETURN_ADDRESS_SAME;
        DFXLOGU("Apply: returnAddressSame, return false, pc=0x%{public}" PRIx64 ", sp=0x%{public}" PRIx64 ", dexPc=0x%{public}" PRIx64 ", seen=%{public}d",
            (uint64_t)regs.GetPc(), (uint64_t)cfa, (uint64_t)regs.DexPc(), (int)regs.DexPcSeen());
        return false;
    }
    DFXLOGU("Apply: done, return true, pc=0x%{public}" PRIx64 ", sp=0x%{public}" PRIx64 ", dexPc=0x%{public}" PRIx64 ", seen=%{public}d, retAddrReg=%{public}d",
        (uint64_t)regs.GetPc(), (uint64_t)cfa, (uint64_t)regs.DexPc(), (int)regs.DexPcSeen(),
        (int)rsState.returnAddressRegister);
    return true;
}
} // namespace HiviewDFX
} // namespace OHOS
