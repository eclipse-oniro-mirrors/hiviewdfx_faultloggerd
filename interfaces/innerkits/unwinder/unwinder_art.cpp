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

#include "unwinder_art.h"

#include "dfx_errors.h"
#include "dfx_log.h"
#include "dfx_symbols.h"
#include "string_util.h"
#include "unwind_define.h"

namespace OHOS {
namespace HiviewDFX {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxUnwinder"

namespace ArtUnwind {

bool IsFileBackedMapName(std::string name)
{
    if (name.rfind("/proc/", 0) == 0) {
        size_t pos = name.find("/root");
        if (pos != std::string::npos) {
            name = name.substr(pos + static_cast<size_t>(sizeof("/root")) - 1);
        }
    }
    return !name.empty() && name[0] == '/' && name.find("/memfd:") == std::string::npos;
}

void TryJitSymbolLookup(DfxJitDebug& jitDebug, const std::shared_ptr<DfxMemory>& memory,
    const std::shared_ptr<DfxMaps>& maps, int32_t pid, DfxFrame& frame)
{
    if (frame.map != nullptr && IsFileBackedMapName(frame.map->name)) {
        return;
    }
    jitDebug.SetMemory(memory);
    jitDebug.SetMaps(maps);
    jitDebug.SetPid(pid);
#if defined(__aarch64__)
    jitDebug.SetArch(ARCH_ARM64);
#else
    return;
#endif

    JitSymbolInfo info;
    if (!jitDebug.GetJitSymbolInfo(frame.pc, info)) {
        return;
    }

    if (info.elf == nullptr || !info.elf->IsValid()) {
        return;
    }

    uint64_t relPc = frame.pc;
    if (info.loadBias != 0 && info.loadBias != static_cast<uint64_t>(-1)) {
        relPc = frame.pc - info.loadBias;
    } else {
        relPc = frame.pc - info.startPc;
    }

    if (!DfxSymbols::GetFuncNameAndOffsetByPc(relPc, info.elf, frame.funcName, frame.funcOffset)) {
        return;
    }

    frame.parseSymbolState.SetParseSymbolState(true);
}

bool BuildJitUnwindTable(uintptr_t pc, const std::shared_ptr<DfxElf>& jitElf,
    uint64_t loadBias, UnwindTableInfo& uti)
{
    std::shared_ptr<DfxMap> tmpMap = std::make_shared<DfxMap>();
    if (jitElf->HasRuntimeRange()) {
        tmpMap->begin = 0;
        tmpMap->end = 0;
    } else {
        tmpMap->begin = jitElf->GetStartVaddr() + loadBias;
        tmpMap->end = jitElf->GetEndVaddr() + loadBias;
    }
    tmpMap->offset = 0;
    tmpMap->name = "[jit]";

    int utiRet = jitElf->FindUnwindTableInfo(pc, tmpMap, uti);
    if (utiRet != UNW_ERROR_NONE) {
        DFXLOGU("TryJitStep: Failed to find unwind table in JIT ELF, ret: %{public}d, pc: 0x%{public}" PRIx64 "",
            utiRet, (uint64_t)pc);
        return false;
    }
    return true;
}

bool IsArtInterpMap(const std::shared_ptr<DfxMap>& map)
{
    auto pos = map->name.rfind('/');
    std::string baseName = (pos == std::string::npos) ? map->name : map->name.substr(pos + 1);

    std::string libArtName = std::string("lib") + "art" + ".so";
    std::string libArtdName = std::string("lib") + "artd" + ".so";
    return baseName == libArtName || baseName == libArtdName;
}

bool IsDexPcMapName(const std::string& name, bool isMapExec)
{
    return name.find(".vdex") != std::string::npos ||
        EndsWith(name, ".dex") || EndsWith(name, ".apk") ||
        StartsWith(name, "[anon:dalvik") ||
        (name.empty() && isMapExec);
}

uintptr_t ResolveDexPcAnchor(const std::shared_ptr<DfxRegs>& regs,
    const std::shared_ptr<DfxMaps>& maps, uintptr_t origDexPc, std::shared_ptr<DfxMap>& dexMap,
    bool& dexPcValid)
{
    uintptr_t effectiveDexPc = regs->DexPc();
    if (effectiveDexPc == 0) {
        effectiveDexPc = origDexPc;
    }
    if (effectiveDexPc != 0) {
        if (maps->FindMapByAddr(static_cast<uintptr_t>(effectiveDexPc), dexMap) && dexMap != nullptr) {
            dexPcValid = IsDexPcMapName(dexMap->name, dexMap->IsMapExec());
        }
    }
    return effectiveDexPc;
}

bool ReadNterpFrameLayout(const std::shared_ptr<DfxMemory>& memory, uintptr_t xRefs, uintptr_t& savedSp,
    uintptr_t& nativeLr, uintptr_t& nativeSp)
{
    savedSp = 0;
    if (xRefs != 0) {
        uintptr_t refsAddr = xRefs - 8; // 8 : saved_sp offset
        if (!memory->Read<uintptr_t>(refsAddr, &savedSp, false)) {
            DFXLOGU("StepNterp: failed to read saved_sp at [xREFS-8]=0x%{public}" PRIx64 "", (uint64_t)refsAddr);
            return false;
        }
    }
    if (savedSp == 0) {
        DFXLOGU("StepNterp: saved_sp is 0, cannot locate callee-saves frame");
        return false;
    }

    nativeLr = 0;
    uintptr_t lrAddr = savedSp + 152; // 152 : callee-saves frame offset
    if (!memory->Read<uintptr_t>(lrAddr, &nativeLr, false)) {
        DFXLOGU("StepNterp: failed to read native lr at saved_sp+152=0x%{public}" PRIx64 "", (uint64_t)lrAddr);
        return false;
    }
    nativeSp = savedSp + 176; // 176 : callee-saves frame size
    return true;
}

void FallbackToSavedDexPc(const std::shared_ptr<DfxMemory>& memory,
    const std::shared_ptr<DfxMaps>& maps, uintptr_t savedSp, uintptr_t& dexPc,
    std::shared_ptr<DfxMap>& dexMap, bool& dexPcValid)
{
    uintptr_t savedDexPc = 0;
    uintptr_t savedDexPcAddr = savedSp + 88;
    if (memory->Read<uintptr_t>(savedDexPcAddr, &savedDexPc, false) && savedDexPc != 0) {
        std::shared_ptr<DfxMap> savedDexMap;
        if (maps->FindMapByAddr(static_cast<uintptr_t>(savedDexPc), savedDexMap) && savedDexMap != nullptr) {
            const std::string& sn = savedDexMap->name;
            bool savedDexPcValid = IsDexPcMapName(sn, savedDexMap->IsMapExec());
            if (savedDexPcValid) {
                dexPc = savedDexPc;
                dexMap = savedDexMap;
                dexPcValid = true;
            }
        }
    }
}

void FillDexFrame(DfxFrame& frame)
{
    if (frame.map == nullptr) {
        frame.relPc = frame.pc;
        frame.mapName = "Not mapped";
        return;
    }
    frame.mapName = frame.map->GetElfName();
    frame.relPc = frame.pc - frame.map->begin;
    frame.mapOffset = frame.map->offset;
}
} // namespace ArtUnwind
} // namespace HiviewDFX
} // namespace OHOS
