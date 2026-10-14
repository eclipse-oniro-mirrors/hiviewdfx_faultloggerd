/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#if defined(__aarch64__)
#include "dfx_regs.h"

#include <securec.h>
#include <cstring>
#include "dfx_define.h"
#include "dfx_guest_state.h"
#include "dfx_log.h"
#include "string_printf.h"

#ifndef REGS_PRINT_LEN
#define REGS_PRINT_LEN 256
#endif

#define ARM_NR_sigreturn 119
#define ARM_NR_rt_sigreturn 173
#define ARM_NR_OABI_SYSCALL_BASE 0x900000

/* ARM EABI sigreturn (the syscall number is loaded into r7) */
#define MOV_R7_SIGRETURN (0xe3a07000UL | ARM_NR_sigreturn)
#define MOV_R7_RT_SIGRETURN (0xe3a07000UL | ARM_NR_rt_sigreturn)

/* ARM OABI sigreturn (using SWI) */
#define ARM_SIGRETURN (0xef000000UL | ARM_NR_sigreturn | ARM_NR_OABI_SYSCALL_BASE)
#define ARM_RT_SIGRETURN (0xef000000UL | ARM_NR_rt_sigreturn | ARM_NR_OABI_SYSCALL_BASE)

/* Thumb sigreturn (two insns, syscall number is loaded into r7) */
#define THUMB_SIGRETURN (0xdf00UL << 16 | 0x2700 | ARM_NR_sigreturn)
#define THUMB_RT_SIGRETURN (0xdf00UL << 16 | 0x2700 | ARM_NR_rt_sigreturn)

/* Thumb2 sigreturn (mov.w r7, $SYS_ify(rt_sigreturn/sigreturn)) */
#define THUMB2_SIGRETURN (((0x0700 | ARM_NR_sigreturn) << 16) | 0xf04f)
#define THUMB2_RT_SIGRETURN (((0x0700 | ARM_NR_rt_sigreturn) << 16) | 0xf04f)

namespace OHOS {
namespace HiviewDFX {
DfxRegsGuestArm32::DfxRegsGuestArm32()
{
    // Keep the build-arch size so index accesses with compile-time REG_*
    // constants stay in bounds; the guest itself only uses the flat slots.
    if (regsData_.size() < REG_LAST) {
        regsData_.resize(REG_LAST, 0);
    }
}

void DfxRegsGuestArm32::SetGuestRegs(const uint32_t regs[GUEST_ARM_LAST])
{
    for (size_t i = 0; i < GUEST_ARM_LAST && i < regsData_.size(); i++) {
        regsData_[i] = static_cast<uintptr_t>(regs[i]);
    }
}

uintptr_t DfxRegsGuestArm32::GetSp() const
{
    return regsData_[GUEST_ARM_SP];
}

void DfxRegsGuestArm32::SetSp(uintptr_t sp)
{
    regsData_[GUEST_ARM_SP] = sp;
}

uintptr_t DfxRegsGuestArm32::GetPc() const
{
    return regsData_[GUEST_ARM_PC];
}

void DfxRegsGuestArm32::SetPc(uintptr_t pc)
{
    regsData_[GUEST_ARM_PC] = pc;
}

uintptr_t DfxRegsGuestArm32::GetFp() const
{
    return regsData_[GUEST_ARM_FP];
}

void DfxRegsGuestArm32::SetFp(uintptr_t fp)
{
    regsData_[GUEST_ARM_FP] = fp;
}

void DfxRegsGuestArm32::GetSpecialRegs(uintptr_t& fp, uintptr_t& lr, uintptr_t& sp, uintptr_t& pc) const
{
    fp = regsData_[GUEST_ARM_FP];
    lr = regsData_[GUEST_ARM_LR];
    sp = regsData_[GUEST_ARM_SP];
    pc = regsData_[GUEST_ARM_PC];
}

void DfxRegsGuestArm32::SetSpecialRegs(uintptr_t fp, uintptr_t lr, uintptr_t sp, uintptr_t pc)
{
    regsData_[GUEST_ARM_FP] = fp;
    regsData_[GUEST_ARM_LR] = lr;
    regsData_[GUEST_ARM_SP] = sp;
    regsData_[GUEST_ARM_PC] = pc;
}

void DfxRegsGuestArm32::SetFromUcontext(const ucontext_t& context)
{
    // Guest regs always come from the guest state TLS protocol, never from a
    // local ucontext.
    MAYBE_UNUSED const ucontext_t& unused = context;
}

void DfxRegsGuestArm32::SetFromFpMiniRegs(const uintptr_t* regs, const size_t size)
{
    MAYBE_UNUSED const uintptr_t* unused = regs;
    MAYBE_UNUSED const size_t unusedSize = size;
}

void DfxRegsGuestArm32::SetFromQutMiniRegs(const uintptr_t* regs, const size_t size)
{
    MAYBE_UNUSED const uintptr_t* unused = regs;
    MAYBE_UNUSED const size_t unusedSize = size;
}

bool DfxRegsGuestArm32::SetPcFromReturnAddress(MAYBE_UNUSED std::shared_ptr<DfxMemory> memory)
{
    uintptr_t lr = regsData_[GUEST_ARM_LR];
    if (regsData_[GUEST_ARM_PC] == lr) {
        return false;
    }
    regsData_[GUEST_ARM_PC] = lr;
    return true;
}

std::string DfxRegsGuestArm32::PrintRegs() const
{
    char buf[REGS_PRINT_LEN] = {0};
    auto regs = GetRegsData();

    BufferPrintf(buf, sizeof(buf), "r0:%08x r1:%08x r2:%08x r3:%08x\n", \
        static_cast<uint32_t>(regs[GUEST_ARM_R0]), static_cast<uint32_t>(regs[GUEST_ARM_R1]), \
        static_cast<uint32_t>(regs[GUEST_ARM_R2]), static_cast<uint32_t>(regs[GUEST_ARM_R3]));

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "r4:%08x r5:%08x r6:%08x r7:%08x\n", \
        static_cast<uint32_t>(regs[GUEST_ARM_R4]), static_cast<uint32_t>(regs[GUEST_ARM_R5]), \
        static_cast<uint32_t>(regs[GUEST_ARM_R6]), static_cast<uint32_t>(regs[GUEST_ARM_R7]));

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "r8:%08x r9:%08x r10:%08x\n", \
        static_cast<uint32_t>(regs[GUEST_ARM_R8]), static_cast<uint32_t>(regs[GUEST_ARM_R9]), \
        static_cast<uint32_t>(regs[GUEST_ARM_R10]));

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "fp:%08x ip:%08x sp:%08x lr:%08x pc:%08x\n", \
        static_cast<uint32_t>(regs[GUEST_ARM_FP]), static_cast<uint32_t>(regs[GUEST_ARM_R12]), \
        static_cast<uint32_t>(regs[GUEST_ARM_SP]), static_cast<uint32_t>(regs[GUEST_ARM_LR]), \
        static_cast<uint32_t>(regs[GUEST_ARM_PC]));

    std::string regString = StringPrintf("Registers:\n%s", buf);
    return regString;
}

bool DfxRegsGuestArm32::StepIfSignalFrame(uintptr_t pc, std::shared_ptr<DfxMemory> memory)
{
    // Same sequence as the native arm32 path (dfx_regs_arm.cpp): recognize a
    // sigreturn trampoline at pc and reload the register set from the signal
    // frame on the guest stack.
    pc = pc & ~0x1;

    uint32_t data;
    if (!memory->Read<uint32_t>(pc, &data, false)) {
        return false;
    }
    DFXLOGU("data: %{public}x", data);

    uintptr_t scAddr = 0;
    if (data == MOV_R7_SIGRETURN || data == ARM_SIGRETURN
        || data == THUMB_SIGRETURN || data == THUMB2_SIGRETURN) {
        uintptr_t spAddr = regsData_[GUEST_ARM_SP];
        if (!memory->Read<uint32_t>(spAddr, &data, false)) {
            return false;
        }
        if (data == 0x5ac3c35a) {
            // SP + uc_mcontext offset + r0 offset.
            scAddr = spAddr + 0x14 + 0xc;
        } else {
            // SP + r0 offset
            scAddr = spAddr + 0xc;
        }
    } else if (data == MOV_R7_RT_SIGRETURN || data == ARM_RT_SIGRETURN
        || data == THUMB_RT_SIGRETURN || data == THUMB2_RT_SIGRETURN) {
        uintptr_t spAddr = regsData_[GUEST_ARM_SP];
        if (!memory->Read<uint32_t>(spAddr, &data, false)) {
            return false;
        }
        if (data == spAddr + 8) { // 8 : eight bytes offset
            // SP + 8 + sizeof(siginfo_t) + uc_mcontext_offset + r0 offset
            scAddr = spAddr + 8 + sizeof(siginfo_t) + 0x14 + 0xc; // 8 : eight bytes offset
        } else {
            // SP + sizeof(siginfo_t) + uc_mcontext_offset + r0 offset
            scAddr = spAddr + sizeof(siginfo_t) + 0x14 + 0xc;
        }
    }
    if (scAddr == 0) {
        return false;
    }
    DFXLOGU("scAddr: %{public}x", scAddr);
    memory->Read(scAddr, regsData_.data(), sizeof(uint32_t) * GUEST_ARM_R15, false);
    return true;
}
} // namespace HiviewDFX
} // namespace OHOS
#endif
