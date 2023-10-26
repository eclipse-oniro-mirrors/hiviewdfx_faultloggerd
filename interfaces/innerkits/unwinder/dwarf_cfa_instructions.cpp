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

#include "dwarf_cfa_instructions.h"
#include <cstdio>
#include <cstring>
#include "dfx_log.h"
#include "dwarf_define.h"
#include "unwind_define.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxDwarfCfaInstructions"
}

bool DwarfCfaInstructions::Iterate(uintptr_t pc, FrameDescEntry fde,
    uintptr_t instStart, uintptr_t instEnd, RegLocState &rsState)
{
    uintptr_t instPtr = instStart;
    uintptr_t pcOffset = fde.pcStart;
    rsState.pcStart = pcOffset;
    RegLocState prevRs = rsState;
    const auto& cie = fde.cie;
    while (true) {
        if (pcOffset > pc) {
            rsState.pcEnd = pcOffset;
            break;
        }
        if (instPtr >= instEnd) {
            rsState.pcEnd = fde.pcEnd;
            break;
        }
        rsState.pcStart = pcOffset;
        uintptr_t value = 0;
        int64_t offset = 0;
        uint64_t reg = 0;
        uint64_t reg2 = 0;
        // Read the cfa information.
        uint8_t opCode;
        memory_->ReadU8(instPtr, &opCode, true);
        switch (opCode) {
            case DW_CFA_nop:
                LOGU("DW_CFA_nop");
                break;
            case DW_CFA_set_loc:
                value = memory_->ReadEncodedValue(instPtr, (DwarfEncoding)cie.pointerEncoding);
                pcOffset = value;
                LOGU("DW_CFA_set_loc: new offset=%" PRIu64 "", static_cast<uint64_t>(pcOffset));
                break;
            case DW_CFA_advance_loc1:
                value = memory_->ReadEncodedValue(instPtr, (DwarfEncoding)DW_EH_PE_udata1);
                pcOffset += (value * cie.codeAlignFactor);
                LOGU("DW_CFA_advance_loc1: new offset=%" PRIu64 "", static_cast<uint64_t>(pcOffset));
                break;
            case DW_CFA_advance_loc2:
                value = memory_->ReadEncodedValue(instPtr, (DwarfEncoding)DW_EH_PE_udata2);
                pcOffset += (value * cie.codeAlignFactor);
                LOGU("DW_CFA_advance_loc2: %" PRIu64 " to %llx",
                    static_cast<uint64_t>(value * cie.codeAlignFactor), pcOffset);
                break;
            case DW_CFA_advance_loc4:
                value = memory_->ReadEncodedValue(instPtr, (DwarfEncoding)DW_EH_PE_udata4);
                pcOffset += (value * cie.codeAlignFactor);
                LOGU("DW_CFA_advance_loc4: new offset=%" PRIu64 "", static_cast<uint64_t>(pcOffset));
                break;
            case DW_CFA_offset_extended:
                reg = memory_->ReadUleb128(instPtr);
                offset = (int64_t)memory_->ReadUleb128(instPtr) * cie.codeAlignFactor;
                if (reg > REGS_MAX_SIZE) {
                    LOGU("DW_CFA_offset_extended: reg=%d (Skipped)", (int)reg);
                    break;
                }
                rsState.locs[reg].type = REG_LOC_MEM_OFFSET;
                rsState.locs[reg].val = offset;
                LOGU("DW_CFA_offset_extended: reg=%d", (int)reg);
                break;
            case DW_CFA_restore_extended:
                reg = memory_->ReadUleb128(instPtr);
                if (reg > REGS_MAX_SIZE) {
                    LOGU("DW_CFA_restore_extended: reg=%d (Skipped)", (int)reg);
                    break;
                }
                rsState.locs[reg] = prevRs.locs[reg];
                LOGU("DW_CFA_restore_extended: reg=%d", (int)reg);
                break;
            case DW_CFA_undefined:
                reg = memory_->ReadUleb128(instPtr);
                rsState.locs[reg].type = REG_LOC_UNDEFINED;  // cfa offset
                LOGU("DW_CFA_undefined: reg=%d", (int)reg);
                break;
            case DW_CFA_same_value:
                reg = memory_->ReadUleb128(instPtr);
                rsState.locs[reg].type = REG_LOC_UNUSED;
                LOGU("DW_CFA_same_value: reg=%d", (int)reg);
                break;
            case DW_CFA_register:
                reg = memory_->ReadUleb128(instPtr);
                reg2 = memory_->ReadUleb128(instPtr);
                rsState.locs[reg].type = REG_LOC_REGISTER;  // register is saved in current register
                rsState.locs[reg].val = reg2;
                LOGU("DW_CFA_register: reg=%d, reg2=%d", (int)reg, (int)reg2);
                break;
            case DW_CFA_remember_state:
                saveRsStates_.push(rsState);
                LOGU("DW_CFA_remember_state");
                break;
            case DW_CFA_restore_state:
                if (saveRsStates_.size() == 0) {
                    LOGU("DW_CFA_restore_state: Attempt to restore without remember");
                } else {
                    rsState = saveRsStates_.top();
                    saveRsStates_.pop();
                    LOGU("DW_CFA_restore_state");
                }
                break;
            case DW_CFA_def_cfa:
                reg = memory_->ReadUleb128(instPtr);
                offset = (int64_t)memory_->ReadUleb128(instPtr);
                rsState.cfaReg = (uint32_t)reg;
                rsState.cfaRegOffset = (int32_t)offset;
                LOGU("DW_CFA_def_cfa: reg=%d, offset=%" PRIu64 "", (int)reg, offset);
                break;
            case DW_CFA_def_cfa_register:
                reg = memory_->ReadUleb128(instPtr);
                rsState.cfaReg = (uint32_t)reg;
                LOGU("DW_CFA_def_cfa_register: reg=%d", (int)reg);
                break;
            case DW_CFA_def_cfa_offset:
                rsState.cfaRegOffset = (int32_t)memory_->ReadUleb128(instPtr);
                LOGU("DW_CFA_def_cfa_offset: cfaRegOffset=%d", rsState.cfaRegOffset);
                break;
            case DW_CFA_offset_extended_sf:
                reg = memory_->ReadUleb128(instPtr);
                offset = (int64_t)(memory_->ReadSleb128(instPtr)) * cie.dataAlignFactor;
                rsState.locs[reg].type = REG_LOC_MEM_OFFSET;
                rsState.locs[reg].val = offset;
                break;
            case DW_CFA_def_cfa_sf:
                reg = memory_->ReadUleb128(instPtr);
                offset = (int64_t)(memory_->ReadSleb128(instPtr)) * cie.dataAlignFactor;
                rsState.cfaReg = (uint32_t)reg;
                rsState.cfaRegOffset = (int32_t)offset;
                LOGU("DW_CFA_def_cfa_sf: reg=%d, offset=%d", rsState.cfaReg, rsState.cfaRegOffset);
                break;
            case DW_CFA_def_cfa_offset_sf:
                offset = (int64_t)(memory_->ReadSleb128(instPtr)) * cie.dataAlignFactor;
                rsState.cfaRegOffset = (int32_t)offset;
                LOGU("DW_CFA_def_cfa_offset_sf: offset=%d", rsState.cfaRegOffset);
                break;
            case DW_CFA_val_offset:
                reg = memory_->ReadUleb128(instPtr);
                offset = (int64_t)memory_->ReadUleb128(instPtr) * cie.codeAlignFactor;
                rsState.locs[reg].type = REG_LOC_VAL_OFFSET;
                rsState.locs[reg].val = offset;
                LOGU("DW_CFA_val_offset: reg=%d, offset=%" PRIu64 "", (int)reg, offset);
                break;
            case DW_CFA_val_offset_sf:
                reg = memory_->ReadUleb128(instPtr);
                offset = (int64_t)memory_->ReadSleb128(instPtr) * cie.codeAlignFactor;
                rsState.locs[reg].type = REG_LOC_VAL_OFFSET;
                rsState.locs[reg].val = offset;
                LOGU("DW_CFA_val_offset_sf: reg=%d, offset=%" PRIu64 "", (int)reg, offset);
                break;
            case DW_CFA_def_cfa_expression:
                rsState.cfaReg = 0;
                rsState.cfaExprPtr = instPtr;
                instPtr += static_cast<uintptr_t>(memory_->ReadUleb128(instPtr));
                break;
            case DW_CFA_expression:
                reg = memory_->ReadUleb128(instPtr);
                rsState.locs[reg].type = REG_LOC_MEM_EXPRESSION;
                rsState.locs[reg].val = instPtr;
                instPtr += static_cast<uintptr_t>(memory_->ReadUleb128(instPtr));
                break;
            case DW_CFA_val_expression:
                reg = memory_->ReadUleb128(instPtr);
                rsState.locs[reg].type = REG_LOC_VAL_EXPRESSION;
                rsState.locs[reg].val = instPtr;
                instPtr += static_cast<uintptr_t>(memory_->ReadUleb128(instPtr));
                break;
            case DW_CFA_GNU_negative_offset_extended:
                reg = memory_->ReadUleb128(instPtr);
                offset = -(int64_t)memory_->ReadUleb128(instPtr);
                rsState.locs[reg].type = REG_LOC_MEM_OFFSET;
                rsState.locs[reg].val = offset;
                LOGU("DW_CFA_GNU_negative_offset_extended: reg=%d, offset=%" PRIu64 "", (int)reg, offset);
                break;

            default:
                uint8_t operand = opCode & 0x3F;
                // Check the 2 high bits.
                switch (opCode & 0xC0) {
                    case DW_CFA_advance_loc:
                        pcOffset += operand * cie.codeAlignFactor;
                        LOGU("DW_CFA_advance_loc: pcOffset=%" PRIu64 "", static_cast<uint64_t>(pcOffset));
                        break;
                    case DW_CFA_offset:
                        reg = operand;
                        offset = (int64_t)memory_->ReadUleb128(instPtr) * cie.dataAlignFactor;
                        rsState.locs[reg].type = REG_LOC_MEM_OFFSET;
                        rsState.locs[reg].val = offset;
                        LOGU("DW_CFA_offset: reg=%d, offset=%" PRId64 "", (int)reg, offset);
                        break;
                    case DW_CFA_restore:
                        reg = operand;
                        rsState.locs[reg] = prevRs.locs[reg];
                        LOGU("DW_CFA_restore: reg=%d", (int)reg);
                        break;
                    default:
                        LOGU("DW_CFA_unknown: opcode=0x%02x", opCode);
                        break;
                }
        }
    }
    LOGU("rsState pcStart=%llx, pcEnd=%llx", (uint64_t)rsState.pcStart, (uint64_t)rsState.pcEnd);
    return true;
}

bool DwarfCfaInstructions::Parse(uintptr_t pc, FrameDescEntry fde, RegLocState &rsState)
{
    LOGU("Iterate cie operations");
    if (!Iterate(pc, fde, fde.cie.instructionsOff, fde.cie.instructionsEnd, rsState)) {
        LOGE("Failed to run cie inst");
        return false;
    }

    LOGU("Iterate fde operations");
    if (!Iterate(pc, fde, fde.instructionsOff, fde.instructionsEnd, rsState)) {
        LOGE("Failed to run fde inst");
        return false;
    }
    return true;
}
}   // namespace HiviewDFX
}   // namespace OHOS
