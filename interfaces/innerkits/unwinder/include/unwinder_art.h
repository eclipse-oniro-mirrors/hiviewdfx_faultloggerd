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

#ifndef UNWINDER_ART_H
#define UNWINDER_ART_H

#include <cstdint>
#include <memory>
#include <string>

#include "dfx_elf.h"
#include "dfx_jit_debug.h"
#include "dfx_map.h"
#include "dfx_maps.h"
#include "dfx_memory.h"
#include "dfx_regs.h"
#include "unwind_context.h"
#include "unwinder.h"

namespace OHOS {
namespace HiviewDFX {
namespace ArtUnwind {

void TryJitSymbolLookup(DfxJitDebug& jitDebug, const std::shared_ptr<DfxMemory>& memory,
    const std::shared_ptr<DfxMaps>& maps, int32_t pid, DfxFrame& frame);
bool BuildJitUnwindTable(uintptr_t pc, const std::shared_ptr<DfxElf>& jitElf, uint64_t loadBias,
    UnwindTableInfo& uti);
bool IsArtInterpMap(const std::shared_ptr<DfxMap>& map);
bool IsDexPcMapName(const std::string& name, bool isMapExec);
uintptr_t ResolveDexPcAnchor(const std::shared_ptr<DfxRegs>& regs,
    const std::shared_ptr<DfxMaps>& maps, uintptr_t origDexPc, std::shared_ptr<DfxMap>& dexMap,
    bool& dexPcValid);
bool ReadNterpFrameLayout(const std::shared_ptr<DfxMemory>& memory, uintptr_t xRefs, uintptr_t& savedSp,
    uintptr_t& nativeLr, uintptr_t& nativeSp);
void FallbackToSavedDexPc(const std::shared_ptr<DfxMemory>& memory,
    const std::shared_ptr<DfxMaps>& maps, uintptr_t savedSp, uintptr_t& dexPc,
    std::shared_ptr<DfxMap>& dexMap, bool& dexPcValid);
void FillDexFrame(DfxFrame& frame);
bool IsFileBackedMapName(std::string name);

} // namespace ArtUnwind
} // namespace HiviewDFX
} // namespace OHOS

#endif // UNWINDER_ART_H
