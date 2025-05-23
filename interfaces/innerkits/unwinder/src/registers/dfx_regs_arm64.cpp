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
#include <stdint.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include "dfx_define.h"
#include "dfx_log.h"
#include "string_printf.h"

namespace OHOS {
namespace HiviewDFX {

constexpr int VREGS_ARRAY_LEN = 32;

struct Aarch64CtxHead {
    uint32_t magic;
    uint32_t size;
};

struct Aarch64FpsimdContext {
    struct Aarch64CtxHead head;
    uint32_t fpsr;
    uint32_t fpcr;
    __uint128_t vregs[VREGS_ARRAY_LEN];
};

void DfxRegsArm64::SetFromUcontext(const ucontext_t &context)
{
    if (regsData_.size() < REG_LAST) {
        return;
    }
    for (uint16_t index = REG_AARCH64_X0; index <= REG_AARCH64_X30; index++) {
        regsData_[index] = static_cast<uintptr_t>(context.uc_mcontext.regs[index]);
    }
    regsData_[REG_AARCH64_X31] = static_cast<uintptr_t>(context.uc_mcontext.sp); // sp register
    regsData_[REG_AARCH64_PC] = static_cast<uintptr_t>(context.uc_mcontext.pc); // pc register
    regsData_[REG_AARCH64_PSTATE] = static_cast<uintptr_t>(context.uc_mcontext.pstate);
    uint8_t* pMctxRes = reinterpret_cast<uint8_t*>(const_cast<long double*>(&context.uc_mcontext.__reserved[0]));
    regsData_[REG_AARCH64_ESR] = *reinterpret_cast<uintptr_t*>(pMctxRes + sizeof(Aarch64FpsimdContext) +
        sizeof(Aarch64CtxHead));
}

void DfxRegsArm64::SetFromFpMiniRegs(const uintptr_t* regs, const size_t size)
{
    if (regs == nullptr || size < FP_MINI_REGS_SIZE) {
        return;
    }
    regsData_[REG_FP] = regs[0]; // 0 : fp offset
    regsData_[REG_LR] = regs[1]; // 1 : lr offset
    regsData_[REG_SP] = regs[2]; // 2 : sp offset
    regsData_[REG_PC] = regs[3]; // 3 : pc offset
}

void DfxRegsArm64::SetFromQutMiniRegs(const uintptr_t* regs, const size_t size)
{
    if (regs == nullptr || size < QUT_MINI_REGS_SIZE) {
        return;
    }
    regsData_[REG_AARCH64_X20] = regs[1]; // 1 : X20 offset
    regsData_[REG_AARCH64_X28] = regs[2]; // 2 : X28 offset
    regsData_[REG_FP] = regs[3]; // 3 : fp offset
    regsData_[REG_SP] = regs[4];  // 4 : sp offset
    regsData_[REG_PC] = regs[5];  // 5 : pc offset
    regsData_[REG_LR] = regs[6];  // 6 : lr offset
}

bool DfxRegsArm64::SetPcFromReturnAddress(MAYBE_UNUSED std::shared_ptr<DfxMemory> memory)
{
    uintptr_t lr = regsData_[REG_LR];
    if (regsData_[REG_PC] == lr) {
        return false;
    }
    regsData_[REG_PC] = lr;
    return true;
}

std::string DfxRegsArm64::PrintRegs() const
{
    char buf[REGS_PRINT_LEN] = {0};
    auto regs = GetRegsData();

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
        regs[REG_AARCH64_X30], regs[REG_SP], regs[REG_PC]);

    BufferPrintf(buf + strlen(buf), sizeof(buf) - strlen(buf), "pstate:%016lx esr:%016lx\n", \
        regs[REG_AARCH64_PSTATE], regs[REG_AARCH64_ESR]);
    std::string regString = StringPrintf("Registers:\n%s", buf);
    return regString;
}

bool DfxRegsArm64::StepIfSignalFrame(uintptr_t pc, std::shared_ptr<DfxMemory> memory)
{
    if (memory == nullptr) {
        return false;
    }
    uint64_t data;
    if (!memory->Read<uint64_t>(pc, &data, false)) {
        return false;
    }
    DFXLOGU("data: %{public}lx", data);

    // Look for the kernel sigreturn function.
    // __kernel_rt_sigreturn:
    // 0xd2801168     mov x8, #0x8b
    // 0xd4000001     svc #0x0
    if (data != 0xd4000001d2801168ULL) {
        return false;
    }

    // SP + sizeof(siginfo_t) + uc_mcontext offset + X0 offset.
    uintptr_t scAddr = regsData_[REG_SP] + sizeof(siginfo_t) + 0xb0 + 0x08;
    DFXLOGU("scAddr: %{public}lx", scAddr);
    memory->Read(scAddr, regsData_.data(), sizeof(uint64_t) * REG_LAST, false);
    return true;
}
} // namespace HiviewDFX
} // namespace OHOS
#endif
