/*
 * Copyright 2024 Institute of Software, Chinese Academy of Sciences.
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

#if defined(__riscv) && defined(__riscv_xlen) && __riscv_xlen == 64
#include "dfx_regs.h"

#include <elf.h>
#include <securec.h>
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include "dfx_define.h"
#include "dfx_log.h"
#include "dfx_elf.h"
#include "string_printf.h"

namespace OHOS {
namespace HiviewDFX {
void DfxRegsRiscv64::SetFromUcontext(const ucontext_t &context)
{
    std::vector<uintptr_t> regs;
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X0]));   // 0:x0
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X1]));   // 1:x1
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X2]));   // 2:x2
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X3]));   // 3:x3
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X4]));   // 4:x4
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X5]));   // 5:x5
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X6]));   // 6:x6
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X7]));   // 7:x7
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X8]));   // 8:x8
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X9]));   // 9:x9
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X10])); // 10:x10
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X11])); // 11:x11
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X12])); // 12:x12
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X13])); // 13:x13
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X14])); // 14:x14
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X15])); // 15:x15
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X16])); // 16:x16
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X17])); // 17:x17
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X18])); // 18:x18
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X19])); // 19:x19
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X20])); // 20:x20
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X21])); // 21:x21
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X22])); // 22:x22
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X23])); // 23:x23
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X24])); // 24:x24
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X25])); // 25:x25
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X26])); // 26:x26
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X27])); // 27:x27
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X28])); // 28:x28
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X29])); // 29:x29
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X30])); // 30:30
    regs.emplace_back(uintptr_t(context.uc_mcontext.__gregs[REG_RISCV64_X31])); // 31:31

    SetRegsData(regs);
}

void DfxRegsRiscv64::SetFromFpMiniRegs(const uintptr_t* regs, const size_t size)
{
    if (size < FP_MINI_REGS_SIZE) {
        return;
    }
    regsData_[REG_FP] = regs[0]; // 0 : fp offset
    regsData_[REG_LR] = regs[1]; // 1 : lr offset
    regsData_[REG_SP] = regs[2]; // 2 : sp offset
    regsData_[REG_PC] = regs[3]; // 3 : pc offset
}

void DfxRegsRiscv64::SetFromQutMiniRegs(const uintptr_t* regs, const size_t size)
{
    if (size < QUT_MINI_REGS_SIZE) {
        return;
    }
    regsData_[REG_RISCV64_X20] = regs[1]; // 1 : X20 offset
    regsData_[REG_RISCV64_X28] = regs[2]; // 2 : X28 offset
    regsData_[REG_FP] = regs[3]; // 3 : fp offset
    regsData_[REG_SP] = regs[4];  // 4 : sp offset
    regsData_[REG_PC] = regs[5];  // 5 : pc offset
    regsData_[REG_LR] = regs[6];  // 6 : lr offset
}

bool DfxRegsRiscv64::SetPcFromReturnAddress(MAYBE_UNUSED std::shared_ptr<DfxMemory> memory)
{
    uintptr_t lr = regsData_[REG_LR];
    if (regsData_[REG_PC] == lr) {
        return false;
    }
    regsData_[REG_PC] = lr;
    return true;
}

std::string DfxRegsRiscv64::PrintRegs() const
{
    char buf[REGS_PRINT_LEN] = {0};
    auto regs = GetRegsData();

    BufferPrintf(buf, sizeof(buf), "x0:%016lx x1:%016lx x2:%016lx x3:%016lx\n", \
        regs[REG_RISCV64_X0], regs[REG_RISCV64_X1], regs[REG_RISCV64_X2], regs[REG_RISCV64_X3]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "x4:%016lx x5:%016lx x6:%016lx x7:%016lx\n", \
        regs[REG_RISCV64_X4], regs[REG_RISCV64_X5], regs[REG_RISCV64_X6], regs[REG_RISCV64_X7]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "x8:%016lx x9:%016lx x10:%016lx x11:%016lx\n", \
        regs[REG_RISCV64_X8], regs[REG_RISCV64_X9], regs[REG_RISCV64_X10], regs[REG_RISCV64_X11]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "x12:%016lx x13:%016lx x14:%016lx x15:%016lx\n", \
        regs[REG_RISCV64_X12], regs[REG_RISCV64_X13], regs[REG_RISCV64_X14], regs[REG_RISCV64_X15]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "x16:%016lx x17:%016lx x18:%016lx x19:%016lx\n", \
        regs[REG_RISCV64_X16], regs[REG_RISCV64_X17], regs[REG_RISCV64_X18], regs[REG_RISCV64_X19]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "x20:%016lx x21:%016lx x22:%016lx x23:%016lx\n", \
        regs[REG_RISCV64_X20], regs[REG_RISCV64_X21], regs[REG_RISCV64_X22], regs[REG_RISCV64_X23]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "x24:%016lx x25:%016lx x26:%016lx x27:%016lx\n", \
        regs[REG_RISCV64_X24], regs[REG_RISCV64_X25], regs[REG_RISCV64_X26], regs[REG_RISCV64_X27]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "x28:%016lx x29:%016lx\n", \
        regs[REG_RISCV64_X28], regs[REG_RISCV64_X29]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "lr:%016lx sp:%016lx pc:%016lx\n", \
        regs[REG_RISCV64_X30], regs[REG_SP], regs[REG_PC]);

    std::string regString = StringPrintf("Registers:\n%s", buf);
    return regString;
}

bool DfxRegsRiscv64::StepIfSignalFrame(uintptr_t pc, std::shared_ptr<DfxMemory> memory)
{
    uint64_t data;
    if (!memory->ReadU64(pc, &data, false)) {
        return false;
    }
    LOGU("data: %llx", data);
    //future work
    // SP + sizeof(siginfo_t) + uc_mcontext offset + X0 offset.
    uintptr_t scAddr = regsData_[REG_SP] + sizeof(siginfo_t) + 0xb0 + 0x08;
    LOGU("scAddr: %llx", scAddr);
    memory->Read(scAddr, regsData_.data(), sizeof(uint64_t) * REG_LAST, false);
    return true;
}
} // namespace HiviewDFX
} // namespace OHOS
#endif
