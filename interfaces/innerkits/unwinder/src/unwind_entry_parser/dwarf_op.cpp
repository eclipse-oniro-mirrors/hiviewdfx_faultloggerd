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

#include "dwarf_op.h"
#include <cstring>
#include "dfx_log.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxDwarfOp"
}

template <typename AddressType>
AddressType DwarfOp<AddressType>::Eval(DfxRegs& regs, AddressType initStackValue, AddressType startPtr)
{
    DFXLOGU("Eval: initStackValue=%{public}" PRIuPTR ", startPtr=%{public}" PRIuPTR "", initStackValue, startPtr);
    StackReset(initStackValue);

    uintptr_t addr = startPtr;
    uintptr_t length = memory_->ReadUleb128(addr);
    uintptr_t end = addr + length;
    while (addr < end) {
        if (!Decode(regs, addr)) {
            break;
        }
    }

    if (stack_.empty()) {
        DFXLOGE("Eval: stack empty");
        return 0;
    }
    return static_cast<AddressType>(StackPop());
}

template <typename AddressType>
bool DwarfOp<AddressType>::Decode(DfxRegs& regs, uintptr_t& addr)
{
    uint8_t opcode;
    memory_->Read<uint8_t>(addr, &opcode, true);
    switch (opcode) {
        case DW_OP_addr: {
            DFXLOGU("DW_OP_addr");
            uintptr_t val;
            memory_->Read<uintptr_t>(addr, &val, true);
            OpPush(val);
        }
            break;
        case DW_OP_deref:
            DFXLOGU("DW_OP_deref");
            OpDeref();
            break;
        case DW_OP_const1u: {
            DFXLOGU("DW_OP_const1u");
            uint8_t val;
            memory_->Read<uint8_t>(addr, &val, true);
            OpPush(val);
        }
            break;
        case DW_OP_const1s: {
            DFXLOGU("DW_OP_const1s");
            int8_t val;
            memory_->Read<int8_t>(addr, &val, true);
            OpPush(val);
        }
            break;
        case DW_OP_const2u: {
            DFXLOGU("DW_OP_const2u");
            uint16_t val;
            memory_->Read<uint16_t>(addr, &val, true);
            OpPush(val);
        }
            break;
        case DW_OP_const2s: {
            DFXLOGU("DW_OP_const2s");
            int16_t val;
            memory_->Read<int16_t>(addr, &val, true);
            OpPush(val);
        }
            break;
        case DW_OP_const4u: {
            DFXLOGU("DW_OP_const4u");
            uint32_t val;
            memory_->Read<uint32_t>(addr, &val, true);
            OpPush(val);
        }
            break;
        case DW_OP_const4s: {
            DFXLOGU("DW_OP_const4s");
            int32_t val;
            memory_->Read<int32_t>(addr, &val, true);
            OpPush(val);
        }
            break;
        case DW_OP_const8u: {
            DFXLOGU("DW_OP_const8u");
            uint64_t val;
            memory_->Read<uint64_t>(addr, &val, true);
            OpPush(val);
        }
            break;
        case DW_OP_const8s: {
            DFXLOGU("DW_OP_const8s");
            int64_t val;
            memory_->Read<int64_t>(addr, &val, true);
            OpPush(val);
        }
            break;
        case DW_OP_constu:
            DFXLOGU("DW_OP_constu");
            OpPush(memory_->ReadUleb128(addr));
            break;
        case DW_OP_consts:
            DFXLOGU("DW_OP_consts");
            OpPush(memory_->ReadSleb128(addr));
            break;
        case DW_OP_dup:
            DFXLOGU("DW_OP_dup");
            OpDup();
            break;
        case DW_OP_drop:
            DFXLOGU("DW_OP_drop");
            OpDrop();
            break;
        case DW_OP_over:
            DFXLOGU("DW_OP_over");
            OpOver();
            break;
        case DW_OP_pick:
            DFXLOGU("DW_OP_pick");
            OpPick(addr);
            break;
        case DW_OP_swap:
            DFXLOGU("DW_OP_swap");
            OpSwap();
            break;
        case DW_OP_rot:
            DFXLOGU("DW_OP_rot");
            OpRot();
            break;
        case DW_OP_abs:
            DFXLOGU("DW_OP_abs");
            OpAbs();
            break;
        case DW_OP_and:
            DFXLOGU("DW_OP_and");
            OpAnd();
            break;
        case DW_OP_div:
            DFXLOGU("DW_OP_div");
            OpDiv();
            break;
        case DW_OP_minus:
            DFXLOGU("DW_OP_minus");
            OpMinus();
            break;
        case DW_OP_mod:
            DFXLOGU("DW_OP_mod");
            OpMod();
            break;
        case DW_OP_mul:
            DFXLOGU("DW_OP_mul");
            OpMul();
            break;
        case DW_OP_neg:
            DFXLOGU("DW_OP_neg");
            OpNeg();
            break;
        case DW_OP_not:
            DFXLOGU("DW_OP_not");
            OpNot();
            break;
        case DW_OP_or:
            DFXLOGU("DW_OP_or");
            OpOr();
            break;
        case DW_OP_plus:
            DFXLOGU("DW_OP_plus");
            OpPlus();
            break;
        case DW_OP_plus_uconst:
            DFXLOGU("DW_OP_plus_uconst");
            OpPlusULEBConst(addr);
            break;
        case DW_OP_shl:
            DFXLOGU("DW_OP_shl");
            OpShl();
            break;
        case DW_OP_shr:
            DFXLOGU("DW_OP_shr");
            OpShr();
            break;
        case DW_OP_shra:
            DFXLOGU("DW_OP_shra");
            OpShra();
            break;
        case DW_OP_xor:
            DFXLOGU("DW_OP_xor");
            OpXor();
            break;
        case DW_OP_skip:
            DFXLOGU("DW_OP_skip");
            OpSkip(addr);
            break;
        case DW_OP_bra:
            DFXLOGU("DW_OP_bra");
            OpBra(addr);
            break;
        case DW_OP_eq:
            DFXLOGU("DW_OP_eq");
            OpEQ();
            break;
        case DW_OP_ge:
            DFXLOGU("DW_OP_ge");
            OpGE();
            break;
        case DW_OP_gt:
            DFXLOGU("DW_OP_gt");
            OpGT();
            break;
        case DW_OP_le:
            DFXLOGU("DW_OP_le");
            OpLE();
            break;
        case DW_OP_lt:
            DFXLOGU("DW_OP_lt");
            OpLT();
            break;
        case DW_OP_ne:
            DFXLOGU("DW_OP_ne");
            OpNE();
            break;
        case DW_OP_lit0:
        case DW_OP_lit1:
        case DW_OP_lit2:
        case DW_OP_lit3:
        case DW_OP_lit4:
        case DW_OP_lit5:
        case DW_OP_lit6:
        case DW_OP_lit7:
        case DW_OP_lit8:
        case DW_OP_lit9:
        case DW_OP_lit10:
        case DW_OP_lit11:
        case DW_OP_lit12:
        case DW_OP_lit13:
        case DW_OP_lit14:
        case DW_OP_lit15:
        case DW_OP_lit16:
        case DW_OP_lit17:
        case DW_OP_lit18:
        case DW_OP_lit19:
        case DW_OP_lit20:
        case DW_OP_lit21:
        case DW_OP_lit22:
        case DW_OP_lit23:
        case DW_OP_lit24:
        case DW_OP_lit25:
        case DW_OP_lit26:
        case DW_OP_lit27:
        case DW_OP_lit28:
        case DW_OP_lit29:
        case DW_OP_lit30:
        case DW_OP_lit31:
            DFXLOGU("DW_OP_litXX");
            OpLit(opcode);
            break;
        case DW_OP_reg0:
        case DW_OP_reg1:
        case DW_OP_reg2:
        case DW_OP_reg3:
        case DW_OP_reg4:
        case DW_OP_reg5:
        case DW_OP_reg6:
        case DW_OP_reg7:
        case DW_OP_reg8:
        case DW_OP_reg9:
        case DW_OP_reg10:
        case DW_OP_reg11:
        case DW_OP_reg12:
        case DW_OP_reg13:
        case DW_OP_reg14:
        case DW_OP_reg15:
        case DW_OP_reg16:
        case DW_OP_reg17:
        case DW_OP_reg18:
        case DW_OP_reg19:
        case DW_OP_reg20:
        case DW_OP_reg21:
        case DW_OP_reg22:
        case DW_OP_reg23:
        case DW_OP_reg24:
        case DW_OP_reg25:
        case DW_OP_reg26:
        case DW_OP_reg27:
        case DW_OP_reg28:
        case DW_OP_reg29:
        case DW_OP_reg30:
        case DW_OP_reg31:
            DFXLOGU("DW_OP_regXX");
            OpReg(opcode, regs);
            break;
        case DW_OP_regx:
            DFXLOGU("DW_OP_regx");
            OpRegx(addr, regs);
            break;
        case DW_OP_breg0:
        case DW_OP_breg1:
        case DW_OP_breg2:
        case DW_OP_breg3:
        case DW_OP_breg4:
        case DW_OP_breg5:
        case DW_OP_breg6:
        case DW_OP_breg7:
        case DW_OP_breg8:
        case DW_OP_breg9:
        case DW_OP_breg10:
        case DW_OP_breg11:
        case DW_OP_breg12:
        case DW_OP_breg13:
        case DW_OP_breg14:
        case DW_OP_breg15:
        case DW_OP_breg16:
        case DW_OP_breg17:
        case DW_OP_breg18:
        case DW_OP_breg19:
        case DW_OP_breg20:
        case DW_OP_breg21:
        case DW_OP_breg22:
        case DW_OP_breg23:
        case DW_OP_breg24:
        case DW_OP_breg25:
        case DW_OP_breg26:
        case DW_OP_breg27:
        case DW_OP_breg28:
        case DW_OP_breg29:
        case DW_OP_breg30:
        case DW_OP_breg31:
            DFXLOGU("DW_OP_bregXX");
            OpBReg(opcode, addr, regs);
            break;
        case DW_OP_bregx:
            DFXLOGU("DW_OP_bregx");
            OpBRegx(addr, regs);
            break;
        case DW_OP_deref_size:
            DFXLOGU("DW_OP_deref_size");
            OpDerefSize(addr);
            break;
        case DW_OP_fbreg:
        case DW_OP_piece:
        case DW_OP_xderef:
        case DW_OP_xderef_size:
        case DW_OP_nop:
        case DW_OP_push_object_address:
        case DW_OP_call2:
        case DW_OP_call4:
        case DW_OP_call_ref:
            DFXLOGE("DWARF OpNop opcode: %{public}x", opcode);
            OpNop(opcode);
            break;
        default:
            DFXLOGE("DWARF Unexpected opcode: %{public}x", opcode);
            return false;
    }
    return true;
}

// offline unwind should support both dwarf32 and dwarf64 ?
template class DwarfOp<uintptr_t>;

}   // namespace HiviewDFX
}   // namespace OHOS
