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

#include "dfx_art.h"

#include "dfx_errors.h"
#include "dfx_log.h"
#include "dfx_symbols.h"
#include "dfx_trace_dlsym.h"
#include "string_util.h"
#include "unwind_define.h"

namespace OHOS {
namespace HiviewDFX {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxArt"

DfxArt::DfxArt(int32_t& pid, std::shared_ptr<DfxMemory>& memory, std::shared_ptr<DfxRegs>& regs,
    std::shared_ptr<DfxMaps>& maps, std::shared_ptr<UnwindEntryParser>& unwindEntryParser)
    : pid_(pid), memory_(memory), regs_(regs), maps_(maps), unwindEntryParser_(unwindEntryParser)
{
}

bool DfxArt::TryJitStep(uintptr_t pc, std::shared_ptr<RegLocState>& rs)
{
    DFX_TRACE_SCOPED_DLSYM("TryJitStep:%p", reinterpret_cast<void *>(pc));
    if (maps_ != nullptr) {
        std::shared_ptr<DfxMap> map;
        if (memory_->GetMapByPc(pc, map) == UNW_ERROR_NONE && map != nullptr &&
            IsFileBackedMapName(map->name)) {
            return false;
        }
    }

    std::shared_ptr<DfxElf> jitElf;
    uint64_t loadBias = 0;
    if (!FindJitElf(pc, jitElf, loadBias)) {
        DFXLOGU("TryJitStep: No JIT ELF found for pc: 0x%{public}" PRIx64 "", (uint64_t)pc);
        return false;
    }

    if (jitElf == nullptr || !jitElf->IsValid()) {
        DFXLOGU("TryJitStep: JIT ELF invalid for pc: 0x%{public}" PRIx64 "", (uint64_t)pc);
        return false;
    }

    UnwindTableInfo uti;
    if (!BuildJitUnwindTable(pc, jitElf, loadBias, uti)) {
        return false;
    }

    rs = std::make_shared<RegLocState>();
    if (!unwindEntryParser_->Step(pc, uti, rs)) {
        DFXLOGU("TryJitStep: Failed to step JIT unwind entry, pc: 0x%{public}" PRIx64 "", (uint64_t)pc);
        return false;
    }
    return true;
}

bool DfxArt::StepNterp(uintptr_t pc, uintptr_t origDexPc, uintptr_t origXRefs, NterpStepResult& result)
{
    DFX_TRACE_SCOPED_DLSYM("StepNterp:%p", reinterpret_cast<void *>(pc));
#if defined(__aarch64__)
    if (maps_ == nullptr || memory_ == nullptr || regs_ == nullptr) {
        return false;
    }

    std::shared_ptr<DfxMap> map;
    if (memory_->GetMapByPc(pc, map) != UNW_ERROR_NONE || map == nullptr) {
        return false;
    }

    if (!IsArtInterpMap(map)) {
        return false;
    }

    bool dexPcValid = false;
    std::shared_ptr<DfxMap> dexMap;
    uintptr_t effectiveDexPc = ResolveDexPcAnchor(origDexPc, dexMap, dexPcValid);
    bool isNterp = regs_->DexPcSeen() || dexPcValid;
    if (!isNterp) {
        return false;
    }
    regs_->ClearDexPc();

    uintptr_t savedSp = 0;
    uintptr_t nativeLr = 0;
    uintptr_t nativeSp = 0;
    if (!ReadNterpFrameLayout(origXRefs, savedSp, nativeLr, nativeSp)) {
        return false;
    }

    uintptr_t dexPc = effectiveDexPc;
    if (!dexPcValid) {
        FallbackToSavedDexPc(savedSp, dexPc, dexMap, dexPcValid);
    }

    result.dexPc = dexPc;
    result.dexMap = dexMap;
    result.nativeSp = nativeSp;
    result.nativeLr = nativeLr;
    result.dexPcValid = dexPcValid;
    return true;
#else
    return false;
#endif
}

bool DfxArt::FindJitElf(uintptr_t pc, std::shared_ptr<DfxElf>& jitElf, uint64_t& loadBias)
{
    jitDebug_.SetMemory(memory_);
    jitDebug_.SetMaps(maps_);
    jitDebug_.SetPid(pid_);
#if defined(__aarch64__)
    jitDebug_.SetArch(ARCH_ARM64);
#else
    return false;
#endif
    return jitDebug_.FindJitElf(pc, jitElf, loadBias);
}

void DfxArt::TryJitSymbolLookup(DfxFrame& frame)
{
    if (frame.map != nullptr && IsFileBackedMapName(frame.map->name)) {
        return;
    }
    jitDebug_.SetMemory(memory_);
    jitDebug_.SetMaps(maps_);
    jitDebug_.SetPid(pid_);
#if defined(__aarch64__)
    jitDebug_.SetArch(ARCH_ARM64);
#else
    return;
#endif

    JitSymbolInfo info;
    if (!jitDebug_.GetJitSymbolInfo(frame.pc, info)) {
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

bool DfxArt::BuildJitUnwindTable(uintptr_t pc, const std::shared_ptr<DfxElf>& jitElf,
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

bool DfxArt::IsArtInterpMap(const std::shared_ptr<DfxMap>& map)
{
    auto pos = map->name.rfind('/');
    std::string baseName = (pos == std::string::npos) ? map->name : map->name.substr(pos + 1);

    std::string libArtName = std::string("lib") + "art" + ".so";
    std::string libArtdName = std::string("lib") + "artd" + ".so";
    return baseName == libArtName || baseName == libArtdName;
}

bool DfxArt::IsDexPcMapName(const std::string& name, bool isMapExec)
{
    return name.find(".vdex") != std::string::npos ||
        EndsWith(name, ".dex") || EndsWith(name, ".apk") ||
        StartsWith(name, "[anon:dalvik") ||
        (name.empty() && isMapExec);
}

uintptr_t DfxArt::ResolveDexPcAnchor(uintptr_t origDexPc, std::shared_ptr<DfxMap>& dexMap, bool& dexPcValid)
{
    uintptr_t effectiveDexPc = regs_->DexPc();
    if (effectiveDexPc == 0) {
        effectiveDexPc = origDexPc;
    }
    if (effectiveDexPc != 0) {
        if (maps_->FindMapByAddr(static_cast<uintptr_t>(effectiveDexPc), dexMap) && dexMap != nullptr) {
            dexPcValid = IsDexPcMapName(dexMap->name, dexMap->IsMapExec());
        }
    }
    return effectiveDexPc;
}

bool DfxArt::ReadNterpFrameLayout(uintptr_t xRefs, uintptr_t& savedSp, uintptr_t& nativeLr, uintptr_t& nativeSp)
{
    savedSp = 0;
    if (xRefs != 0) {
        uintptr_t refsAddr = xRefs - 8; // 8 : saved_sp offset
        if (!memory_->Read<uintptr_t>(refsAddr, &savedSp, false)) {
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
    if (!memory_->Read<uintptr_t>(lrAddr, &nativeLr, false)) {
        DFXLOGU("StepNterp: failed to read native lr at saved_sp+152=0x%{public}" PRIx64 "", (uint64_t)lrAddr);
        return false;
    }
    nativeSp = savedSp + 176; // 176 : callee-saves frame size
    return true;
}

void DfxArt::FallbackToSavedDexPc(uintptr_t savedSp, uintptr_t& dexPc, std::shared_ptr<DfxMap>& dexMap,
    bool& dexPcValid)
{
    uintptr_t savedDexPc = 0;
    uintptr_t savedDexPcAddr = savedSp + 88;
    if (memory_->Read<uintptr_t>(savedDexPcAddr, &savedDexPc, false) && savedDexPc != 0) {
        std::shared_ptr<DfxMap> savedDexMap;
        if (maps_->FindMapByAddr(static_cast<uintptr_t>(savedDexPc), savedDexMap) && savedDexMap != nullptr) {
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

void DfxArt::FillDexFrame(DfxFrame& frame)
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

bool DfxArt::IsFileBackedMapName(std::string name)
{
    if (name.rfind("/proc/", 0) == 0) {
        size_t pos = name.find("/root");
        if (pos != std::string::npos) {
            name = name.substr(pos + static_cast<size_t>(sizeof("/root")) - 1);
        }
    }
    return !name.empty() && name[0] == '/' && name.find("/memfd:") == std::string::npos;
}
} // namespace HiviewDFX
} // namespace OHOS
