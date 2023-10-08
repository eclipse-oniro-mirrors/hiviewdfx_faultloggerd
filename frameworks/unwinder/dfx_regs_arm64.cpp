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

#if defined(__aarch64__)
#include "dfx_regs.h"

#include <securec.h>
#include "dfx_define.h"
#include "dfx_log.h"
#include "string_printf.h"

namespace OHOS {
namespace HiviewDFX {
DfxRegsArm64::DfxRegsArm64(const ucontext_t &context)
{
    std::vector<uintptr_t> regs {};
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X0]));   // 0:x0
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X1]));   // 1:x1
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X2]));   // 2:x2
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X3]));   // 3:x3
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X4]));   // 4:x4
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X5]));   // 5:x5
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X6]));   // 6:x6
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X7]));   // 7:x7
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X8]));   // 8:x8
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X9]));   // 9:x9
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X10])); // 10:x10
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X11])); // 11:x11
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X12])); // 12:x12
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X13])); // 13:x13
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X14])); // 14:x14
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X15])); // 15:x15
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X16])); // 16:x16
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X17])); // 17:x17
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X18])); // 18:x18
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X19])); // 19:x19
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X20])); // 20:x20
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X21])); // 21:x21
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X22])); // 22:x22
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X23])); // 23:x23
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X24])); // 24:x24
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X25])); // 25:x25
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X26])); // 26:x26
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X27])); // 27:x27
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X28])); // 28:x28
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X29])); // 29:x29
    regs.push_back(uintptr_t(context.uc_mcontext.regs[REG_AARCH64_X30])); // 30:lr
    regs.push_back(uintptr_t(context.uc_mcontext.sp));       // 31:sp
    regs.push_back(uintptr_t(context.uc_mcontext.pc));       // 32:pc

    SetRegsData(regs);
}

std::string DfxRegsArm64::PrintRegs() const
{
    char buf[REGS_PRINT_LEN] = {0};
    std::vector<uintptr_t> regs = GetRegsData();

    BufferPrintf(buf, sizeof(buf), "x0:%016lx x1:%016lx x2:%016lx x3:%016lx\n", \
        regs[REG_AARCH64_X0], regs[REG_AARCH64_X1], regs[REG_AARCH64_X2], regs[REG_AARCH64_X3]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "x4:%016lx x5:%016lx x6:%016lx x7:%016lx\n", \
        regs[REG_AARCH64_X4], regs[REG_AARCH64_X5], regs[REG_AARCH64_X6], regs[REG_AARCH64_X7]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "x8:%016lx x9:%016lx x10:%016lx x11:%016lx\n", \
        regs[REG_AARCH64_X8], regs[REG_AARCH64_X9], regs[REG_AARCH64_X10], regs[REG_AARCH64_X11]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "x12:%016lx x13:%016lx x14:%016lx x15:%016lx\n", \
        regs[REG_AARCH64_X12], regs[REG_AARCH64_X13], regs[REG_AARCH64_X14], regs[REG_AARCH64_X15]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "x16:%016lx x17:%016lx x18:%016lx x19:%016lx\n", \
        regs[REG_AARCH64_X16], regs[REG_AARCH64_X17], regs[REG_AARCH64_X18], regs[REG_AARCH64_X19]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "x20:%016lx x21:%016lx x22:%016lx x23:%016lx\n", \
        regs[REG_AARCH64_X20], regs[REG_AARCH64_X21], regs[REG_AARCH64_X22], regs[REG_AARCH64_X23]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "x24:%016lx x25:%016lx x26:%016lx x27:%016lx\n", \
        regs[REG_AARCH64_X24], regs[REG_AARCH64_X25], regs[REG_AARCH64_X26], regs[REG_AARCH64_X27]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "x28:%016lx x29:%016lx\n", \
        regs[REG_AARCH64_X28], regs[REG_AARCH64_X29]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "lr:%016lx sp:%016lx pc:%016lx\n", \
        regs[REG_LR], regs[REG_SP], regs[REG_PC]);

    std::string regString = StringPrintf("Registers:\n%s", buf);
    return regString;
}

// Get 4 registers from x29 to x32.
inline AT_ALWAYS_INLINE void DfxRegsArm64::GetFramePointerMiniRegs(void *regs)
{
    asm volatile(
    "1:\n"
    "stp x29, x30, [%[base], #0]\n"
    "mov x12, sp\n"
    "adr x13, 1b\n"
    "stp x12, x13, [%[base], #16]\n"
    : [base] "+r"(regs)
    :
    : "x12", "x13", "memory");
}

// Get 7 registers with [unuse, unset, x28, x29, sp, pc, unset].
inline AT_ALWAYS_INLINE void DfxRegsArm64::GetQuickenMiniRegs(void *regs)
{
    asm volatile(
    "1:\n"
    "stp x28, x29, [%[base], #16]\n"
    "mov x12, sp\n"
    "adr x13, 1b\n"
    "stp x12, x13, [%[base], #32]\n"
    : [base] "+r"(regs)
    :
    : "x12", "x13", "memory");
}
} // namespace HiviewDFX
} // namespace OHOS
#endif
