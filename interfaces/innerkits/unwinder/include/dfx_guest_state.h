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
#ifndef DFX_GUEST_STATE_H
#define DFX_GUEST_STATE_H

#include <cstdint>
#include <vector>
#include "unwind_define.h"

namespace OHOS {
namespace HiviewDFX {
// Register indices of the arm32 guest world. The values match the DWARF
// register numbering of ARM32 (r0-r15), so the flat slots of the guest regs
// object are addressed directly by CFI/exidx register numbers.
enum GuestArm32Reg : uint16_t {
    GUEST_ARM_R0 = 0,
    GUEST_ARM_R1,
    GUEST_ARM_R2,
    GUEST_ARM_R3,
    GUEST_ARM_R4,
    GUEST_ARM_R5,
    GUEST_ARM_R6,
    GUEST_ARM_R7,
    GUEST_ARM_R8,
    GUEST_ARM_R9,
    GUEST_ARM_R10,
    GUEST_ARM_R11,
    GUEST_ARM_R12,
    GUEST_ARM_R13,
    GUEST_ARM_R14,
    GUEST_ARM_R15,
    GUEST_ARM_CPSR,
    GUEST_ARM_LAST,
    GUEST_ARM_FP = GUEST_ARM_R11,
    GUEST_ARM_SP = GUEST_ARM_R13,
    GUEST_ARM_LR = GUEST_ARM_R14,
    GUEST_ARM_PC = GUEST_ARM_R15,
};

// QUT register list of the arm32 guest world, same layout as the arm32
// native build (unwind_arm_define.h) so exidx locs keep their meaning.
static const std::vector<uint16_t> GUEST_ARM_QUT_REGS {
    GUEST_ARM_R7,
    GUEST_ARM_FP,
    GUEST_ARM_SP,
    GUEST_ARM_PC,
    GUEST_ARM_LR,
};

struct GuestArm32Regs {
    uint32_t r[GUEST_ARM_LAST] = {0};
};

// Reader of the native bridge guest state protocol (AOSP16
// frameworks/libs/native_bridge_support guest_state_accessor):
//   tpidr = PTRACE_GETREGSET(NT_ARM_TLS)
//   headerPtr = *(u64 *)(tpidr + TLS_SLOT_NATIVE_BRIDGE_GUEST_STATE * 8)
//   NativeBridgeGuestStateHeader { signature, hostArch, guestArch, dataPtr, dataSize }
// The guest_state_data blob layout is translator specific (ExaGear ubt_*);
// the arm32 register set is located by a validated scan (see .cpp).
class DfxGuestState {
public:
    // True when the thread's executable belongs to a binary translator
    // (e.g. ubt_a32a64). Cheap pre-check before touching TLS.
    static bool IsTranslatedThread(pid_t tid);

    // Read the arm32 guest registers of an attached thread.
    // Returns false for native threads or unreadable guest state.
    static bool ReadGuestArm32Regs(pid_t tid, GuestArm32Regs& regs);
};
} // namespace HiviewDFX
} // namespace OHOS
#endif
