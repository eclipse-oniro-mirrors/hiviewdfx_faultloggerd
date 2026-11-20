/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef DFX_ART_H
#define DFX_ART_H

#include <cstdint>
#include <memory>
#include <string>

#include "dfx_elf.h"
#include "dfx_frame.h"
#include "dfx_jit_debug.h"
#include "dfx_map.h"
#include "dfx_maps.h"
#include "dfx_memory.h"
#include "dfx_regs.h"
#include "unwind_context.h"
#include "unwind_entry_parser.h"

namespace OHOS {
namespace HiviewDFX {
// ART adapter (JIT / nterp / dex frame resolution).
// State references bind to the owning Unwinder::Impl members so they stay
// current across SetRegs / SetMaps. The step-machine side effects
// (Apply / AddFrame / register write-back) remain in Unwinder::Impl; the
// resolution results are handed back via RegLocState / NterpStepResult.
class DfxArt {
public:
    struct NterpStepResult {
        uintptr_t dexPc = 0;
        std::shared_ptr<DfxMap> dexMap;
        uintptr_t nativeSp = 0;
        uintptr_t nativeLr = 0;
        bool dexPcValid = false;
    };

    DfxArt(int32_t& pid, std::shared_ptr<DfxMemory>& memory, std::shared_ptr<DfxRegs>& regs,
        std::shared_ptr<DfxMaps>& maps, std::shared_ptr<UnwindEntryParser>& unwindEntryParser);

    bool TryJitStep(uintptr_t pc, std::shared_ptr<RegLocState>& rs);
    bool StepNterp(uintptr_t pc, uintptr_t origDexPc, uintptr_t origXRefs, NterpStepResult& result);
    bool FindJitElf(uintptr_t pc, std::shared_ptr<DfxElf>& jitElf, uint64_t& loadBias);
    void TryJitSymbolLookup(DfxFrame& frame);
    uintptr_t ResolveDexPcAnchor(uintptr_t origDexPc, std::shared_ptr<DfxMap>& dexMap, bool& dexPcValid);
    bool ReadNterpFrameLayout(uintptr_t xRefs, uintptr_t& savedSp, uintptr_t& nativeLr, uintptr_t& nativeSp);
    void FallbackToSavedDexPc(uintptr_t savedSp, uintptr_t& dexPc, std::shared_ptr<DfxMap>& dexMap,
        bool& dexPcValid);

    static bool BuildJitUnwindTable(uintptr_t pc, const std::shared_ptr<DfxElf>& jitElf, uint64_t loadBias,
        UnwindTableInfo& uti);
    static bool IsArtInterpMap(const std::shared_ptr<DfxMap>& map);
    static bool IsDexPcMapName(const std::string& name, bool isMapExec);
    static void FillDexFrame(DfxFrame& frame);
    static bool IsFileBackedMapName(std::string name);

private:
    int32_t& pid_;
    std::shared_ptr<DfxMemory>& memory_;
    std::shared_ptr<DfxRegs>& regs_;
    std::shared_ptr<DfxMaps>& maps_;
    std::shared_ptr<UnwindEntryParser>& unwindEntryParser_;
    DfxJitDebug jitDebug_;
};
} // namespace HiviewDFX
} // namespace OHOS

#endif // DFX_ART_H
