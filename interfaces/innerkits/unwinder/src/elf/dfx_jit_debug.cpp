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

#include <unordered_map>
#include <unordered_set>
#include <mutex>
#include "dfx_jit_debug.h"
#include <algorithm>
#include <cstring>
#include <dlfcn.h>
#include "dfx_log.h"
#include "dfx_maps.h"
#include "dfx_util.h"
#include "elf_factory.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxJitDebug"

constexpr const char* JIT_DEBUG_DESCRIPTOR = "__jit_debug_descriptor";
// V1 layout (no Android-specific fields) covers up to (but excluding) `timestamp`:
//   next + prev + symfileAddr + symfileSize = 4 * sizeof(uint64_t) = 32 bytes on 64-bit.
// V2 layout (Android "Android2" magic) adds timestamp + seqlock + padding = sizeof(JitCodeEntry).
// Using offsetof/sizeof keeps the constants correct for the host pointer size.
constexpr size_t DESCRIPTOR_SIZE_V1 = 24;  // version + action_flag + relevant_entry + first_entry
constexpr size_t DESCRIPTOR_SIZE_V2 = 56;  // V1 + Android-specific magic/flags/sizes/seqlock/timestamp
constexpr size_t CODE_ENTRY_SIZE_V1 = offsetof(JitCodeEntry, timestamp);
constexpr size_t CODE_ENTRY_SIZE_V2 = sizeof(JitCodeEntry);

// JIT descriptor is registered in ART runtime, only search these libs.
const std::vector<std::string>& GetSearchLibs()
{
    static const std::vector<std::string> searchLibs = {"libart.so", "libartd.so"};
    return searchLibs;
}

std::string GetBaseName(const std::string& path)
{
    size_t pos = path.find_last_of('/');
    if (pos == std::string::npos) {
        return path;
    }
    return path.substr(pos + 1);
}

bool Searchable(const std::string& name)
{
    if (name.empty()) {
        return false;
    }
    std::string baseName = GetBaseName(name);
    for (const auto& lib : GetSearchLibs()) {
        if (baseName == lib) {
            return true;
        }
    }
    return false;
}

bool IsBlankMap(const std::shared_ptr<DfxMap>& map)
{
    return map->offset == 0 && map->prots == 0 &&
           (map->name.empty() || map->name == "[page size compat]");
}
} // anonymous namespace

void DfxJitDebug::SetMemory(const std::shared_ptr<DfxMemory>& memory)
{
    memory_ = memory;
}

void DfxJitDebug::SetMaps(const std::shared_ptr<DfxMaps>& maps)
{
    maps_ = maps;
}

void DfxJitDebug::SetPid(pid_t pid)
{
    pid_ = pid;
}

void DfxJitDebug::SetArch(ArchType arch)
{
    arch_ = arch;
}

void DfxJitDebug::Clear()
{
    std::lock_guard<std::mutex> guard(lock_);
    descriptorAddr_ = 0;
    entries_.clear();
    descriptorCheckedPid_ = -1;
}

bool DfxJitDebug::ReadMemory(uint64_t addr, void* buf, size_t size)
{
    if (buf == nullptr || size == 0) {
        return false;
    }
    // For remote processes, use ReadProcMemByPid which reads /proc/pid/mem directly.
    // This is necessary because DfxMemory::Read may try to read from ELF mmap first,
    // which fails for .bss sections (not in the ELF file).
    if (pid_ > 0 && pid_ != getpid()) {
        size_t read = ReadProcMemByPid(pid_, addr, buf, size);
        if (read == size) {
            return true;
        }
        DFXLOGE("ReadMemory: ReadProcMemByPid failed, pid=%{public}d, addr=0x%{public}" PRIx64 ", read=%{public}zu, expected=%{public}zu",
            pid_, addr, read, size);
        return false;
    }
    // For local process, use DfxMemory::Read
    if (memory_ == nullptr) {
        return false;
    }
    uintptr_t readAddr = static_cast<uintptr_t>(addr);
    return memory_->Read(readAddr, buf, size, true) == size;
}

bool DfxJitDebug::ReadU64(uint64_t addr, uint64_t* val)
{
    return ReadMemory(addr, val, sizeof(*val));
}

bool DfxJitDebug::ReadU32(uint64_t addr, uint32_t* val)
{
    return ReadMemory(addr, val, sizeof(*val));
}

uint64_t DfxJitDebug::StripAddressTag(uint64_t addr)
{
    if (arch_ == ARCH_ARM64) {
        return static_cast<uint64_t>((static_cast<int64_t>(addr) << 8) >> 8);
    }
    return addr;
}

bool DfxJitDebug::FindJitDescriptorLocal()
{
    void* addr = dlsym(RTLD_DEFAULT, JIT_DEBUG_DESCRIPTOR);
    if (addr == nullptr) {
        DFXLOGU("dlsym failed for __jit_debug_descriptor: %{public}s", dlerror());
        return false;
    }
    descriptorAddr_ = reinterpret_cast<uint64_t>(addr);
    DFXLOGU("Found jit_debug_descriptor via dlsym at 0x%{public}" PRIx64 "", descriptorAddr_);
    return ReadDescriptor();
}

DfxJitDebug::JitDescriptorStatus DfxJitDebug::FindJitDescriptor()
{
    if (pid_ <= 0 || pid_ == getpid()) {
        if (FindJitDescriptorLocal()) {
            return JitDescriptorStatus::FOUND;
        }
    }

    if (maps_ == nullptr) {
        DFXLOGE("FindJitDescriptor: maps is null");
        return JitDescriptorStatus::RETRY_LATER;
    }

    DFXLOGU("FindJitDescriptor: searching in libart.so/libartd.so, pid=%{public}d", pid_);
    std::shared_ptr<DfxMap> mapZero = nullptr;
    const auto& maps = maps_->GetMaps();

    for (const auto& map : maps) {
        if (map == nullptr) {
            continue;
        }

        // The ELF header map (read-only, offset 0) of libart.so/libartd.so:
        // its begin is the runtime address of vaddr 0, so a symbol with vaddr
        // V lives at mapZero->begin + V. The descriptor may sit in any
        // following mapping of the image (relro page or the anonymous .bss
        // tail with an empty name), so resolve the containing map by address.
        if (map->prots == PROT_READ && map->offset == 0 && !IsBlankMap(map) &&
            !map->name.empty() && Searchable(map->name)) {
            mapZero = map;
            auto elf = mapZero->GetElf(pid_);
            if (elf == nullptr || !elf->IsValid()) {
                DFXLOGE("FindJitDescriptor: elf invalid for %{public}s", GetBaseName(mapZero->name).c_str());
                continue;
            }
            ElfSymbol symbol;
            if (!elf->FindGlobalVariableByName(JIT_DEBUG_DESCRIPTOR, symbol)) {
                DFXLOGU("FindJitDescriptor: symbol not found in %{public}s", GetBaseName(mapZero->name).c_str());
                continue;
            }
            uint64_t symAddr = symbol.value;
            if (elf->IsAdlt()) {
                symAddr += mapZero->GetAdltLoadBase();
            }
            uint64_t runtimeAddr = mapZero->begin + symAddr;
            std::shared_ptr<DfxMap> containing = nullptr;
            if (!maps_->FindMapByAddr(static_cast<uintptr_t>(runtimeAddr), containing) || containing == nullptr) {
                DFXLOGE("FindJitDescriptor: runtimeAddr 0x%{public}" PRIx64 " not mapped", runtimeAddr);
                continue;
            }
            DFXLOGU("FindJitDescriptor: symAddr=0x%{public}" PRIx64 ", runtimeAddr=0x%{public}" PRIx64
                ", in %{public}s [0x%{public}" PRIx64 ", 0x%{public}" PRIx64 ")",
                symAddr, runtimeAddr, GetBaseName(containing->name).c_str(), containing->begin, containing->end);
            descriptorAddr_ = runtimeAddr;
            if (ReadDescriptor()) {
                DFXLOGU("Found jit_debug_descriptor at 0x%{public}" PRIx64 " in %{public}s",
                    runtimeAddr, GetBaseName(mapZero->name).c_str());
                return JitDescriptorStatus::FOUND;
            }
            DFXLOGE("FindJitDescriptor: ReadDescriptor failed at 0x%{public}" PRIx64 "", runtimeAddr);
        }
    }

    DFXLOGE("FindJitDescriptor: not found in any libart.so/libartd.so map");
    return JitDescriptorStatus::NOT_PRESENT;
}

bool DfxJitDebug::EnsureJitDescriptorLocked()
{
    if (descriptorAddr_ != 0) {
        return true;
    }
    if (descriptorCheckedPid_ == pid_) {
        return false;
    }
    JitDescriptorStatus status = FindJitDescriptor();
    if (status == JitDescriptorStatus::FOUND) {
        return true;
    }
    if (status == JitDescriptorStatus::NOT_PRESENT) {
        descriptorCheckedPid_ = pid_;
    }
    return false;
}

bool DfxJitDebug::ReadDescriptor()
{
    JitDescriptor desc{};
    DFXLOGU("ReadDescriptor: reading from 0x%{public}" PRIx64 ", sizeV2=%{public}zu, sizeV1=%{public}zu",
        descriptorAddr_, DESCRIPTOR_SIZE_V2, DESCRIPTOR_SIZE_V1);
    bool readV2 = ReadMemory(descriptorAddr_, &desc, DESCRIPTOR_SIZE_V2);
    DFXLOGU("ReadDescriptor: ReadMemory V2 result: %{public}d", readV2);
    if (!readV2) {
        bool readV1 = ReadMemory(descriptorAddr_, &desc, DESCRIPTOR_SIZE_V1);
        DFXLOGU("ReadDescriptor: ReadMemory V1 result: %{public}d", readV1);
        if (!readV1) {
            DFXLOGE("ReadDescriptor: failed to read from 0x%{public}" PRIx64 "", descriptorAddr_);
            return false;
        }
    }

    if (desc.version != 1 || desc.firstEntry == 0) {
        return false;
    }

    if (memcmp(desc.magic, JIT_MAGIC, sizeof(JIT_MAGIC)) == 0) {
        jitEntrySize_ = CODE_ENTRY_SIZE_V2;
        seqlockOffset_ = offsetof(JitCodeEntry, seqlock);
    } else {
        jitEntrySize_ = CODE_ENTRY_SIZE_V1;
        seqlockOffset_ = 0;
    }

    return true;
}

bool DfxJitDebug::ReadNextField(uint64_t fieldAddr, JitUID* uid, bool* race)
{
    uint64_t address[2] = {0, 0};
    uint32_t seqlock[2] = {0, 0};

    for (int i = 0; i < 2; i++) {
        if (!ReadU64(fieldAddr, &address[i])) {
            return false;
        }
        address[i] = StripAddressTag(address[i]);

        if (seqlockOffset_ == 0) {
            *uid = JitUID{.address = address[0], .seqlock = 0};
            return true;
        }

        if (address[i] != 0) {
            if (!ReadU32(address[i] + seqlockOffset_, &seqlock[i])) {
                return false;
            }
        }
    }

    if (address[0] != address[1] || seqlock[0] != seqlock[1] || (seqlock[0] & 1) == 1) {
        if (race != nullptr) {
            *race = true;
        }
        return false;
    }

    *uid = JitUID{.address = address[1], .seqlock = seqlock[1]};
    return true;
}

bool DfxJitDebug::CheckSeqlock(const JitUID& uid, bool* race)
{
    if (seqlockOffset_ == 0) {
        return true;
    }

    uint32_t seenSeqlock = 0;
    if (!ReadU32(uid.address + seqlockOffset_, &seenSeqlock)) {
        return false;
    }

    if (seenSeqlock != uid.seqlock) {
        if (race != nullptr) {
            *race = true;
        }
        return false;
    }
    return true;
}

bool DfxJitDebug::LoadJitElf(uint64_t addr, uint64_t size, std::shared_ptr<DfxElf>& elf, const JitUID& uid)
{
    if (addr == 0 || size == 0) {
        return false;
    }

    std::vector<uint8_t> data(static_cast<size_t>(size));
    uint8_t* dstPtr = data.data();
    if (dstPtr == nullptr) {
        return false;
    }

    uint64_t readAddr = addr;
    if (!ReadMemory(readAddr, dstPtr, static_cast<size_t>(size))) {
        return false;
    }

    if (!CheckSeqlock(uid)) {
        return false;
    }

    auto mmap = std::make_shared<DfxMmap>();
    if (!mmap->Init(std::move(data))) {
        DFXLOGU("Failed to init mmap for JIT ELF");
        return false;
    }

    elf = std::make_shared<DfxElf>(mmap);
    if (!elf->IsValid()) {
        DFXLOGE("JIT ELF is not valid");
        elf = nullptr;
        return false;
    }

    ShdrInfo textShdr;
    if (elf->GetSectionInfo(textShdr, ".text") && textShdr.size != 0) {
        // ART/ets_runtime JIT ELFs store the absolute runtime address of the .text bytes
        // in sh_addr (e.g. for ART it is the address inside the JIT code cache, and for
        // ets_runtime it is `symfile_addr + sh_offset`). Either way sh_addr is already
        // the runtime PC, so we must NOT add `addr` (symfile_addr) again. Setting
        // loadBase to 0 keeps IsValidPc/FindUnwindTableInfo consistent with this layout
        // (matches the libunwindstack reference, which never adds symfile_addr).
        uint64_t runtimeStart = textShdr.addr;
        uint64_t runtimeEnd = runtimeStart + textShdr.size;
        elf->SetRuntimeRange(runtimeStart, runtimeEnd);
        elf->SetLoadBase(0);
        DFXLOGU("Loaded JIT ELF: addr=0x%{public}" PRIx64 ", size=%{public}" PRIu64 ", .text=[0x%{public}" PRIx64 ", 0x%{public}" PRIx64 "), runtime=[0x%{public}" PRIx64 ", 0x%{public}" PRIx64 ")",
            addr, size, textShdr.addr, textShdr.addr + textShdr.size, runtimeStart, runtimeEnd);
    } else {
        const auto& symbols = elf->GetFuncSymbols();
        uint64_t minAddr = static_cast<uint64_t>(-1);
        uint64_t maxAddr = 0;
        for (const auto& sym : symbols) {
            if (sym.value != 0 && sym.size != 0) {
                minAddr = std::min(minAddr, sym.value);
                maxAddr = std::max(maxAddr, sym.value + sym.size);
            }
        }
        if (minAddr != static_cast<uint64_t>(-1) && maxAddr != 0) {
            // Symbol values in JIT ELFs are also absolute runtime addresses (verified
            // against ART JIT samples), so no need to add `addr`.
            uint64_t runtimeStart = minAddr;
            uint64_t runtimeEnd = maxAddr;
            elf->SetRuntimeRange(runtimeStart, runtimeEnd);
            elf->SetLoadBase(0);
            DFXLOGU("Loaded JIT ELF: addr=0x%{public}" PRIx64 ", size=%{public}" PRIu64 ", symRange=[0x%{public}" PRIx64 ", 0x%{public}" PRIx64 "), runtime=[0x%{public}" PRIx64 ", 0x%{public}" PRIx64 ")",
                addr, size, minAddr, maxAddr, runtimeStart, runtimeEnd);
        } else {
            // Fallback: use PT_LOAD segments to derive the runtime range.
            // ART JIT ELFs typically carry .text with sh_size=0 (the code lives in the
            // JIT code cache, not inside the ELF file) and symbols with st_size=0, so
            // the .text/symbol approaches above do not yield a range. However the
            // PT_LOAD segments have p_vaddr set to the absolute runtime address of the
            // JIT code (see libunwindstack ElfInterface::IsValidPc, which matches the
            // PC against [p_vaddr, p_vaddr + p_memsz)). Use that range here so that
            // IsValidPc/FindUnwindTableInfo can match the PC without relying on
            // section headers or symbols.
            const auto& ptLoads = elf->GetPtLoads();
            uint64_t ptStart = static_cast<uint64_t>(-1);
            uint64_t ptEnd = 0;
            for (const auto& entry : ptLoads) {
                if (entry.second.tableSize == 0) {
                    continue;
                }
                ptStart = std::min(ptStart, entry.second.tableVaddr);
                ptEnd = std::max(ptEnd, entry.second.tableVaddr + entry.second.tableSize);
            }
            elf->SetLoadBase(0);
            if (ptStart != static_cast<uint64_t>(-1) && ptEnd != 0) {
                elf->SetRuntimeRange(ptStart, ptEnd);
                DFXLOGU("Loaded JIT ELF: addr=0x%{public}" PRIx64 ", size=%{public}" PRIu64 ", ptLoadRange=[0x%{public}" PRIx64 ", 0x%{public}" PRIx64 ")",
                    addr, size, ptStart, ptEnd);
            } else {
                DFXLOGU("Loaded JIT ELF: addr=0x%{public}" PRIx64 ", size=%{public}" PRIu64 ", loadBias=0x%{public}" PRIx64 " (no runtime range)",
                    addr, size, static_cast<uint64_t>(elf->GetLoadBias()));
            }
        }
    }

    return true;
}

bool DfxJitDebug::ReadNewEntries(std::map<JitUID, std::shared_ptr<DfxElf>>* entries, bool* race)
{
    JitUID uid;
    if (!ReadNextField(descriptorAddr_ + offsetof(JitDescriptor, firstEntry), &uid, race)) {
        return false;
    }

    while (uid.address != 0) {
        if (entries->find(uid) != entries->end()) {
            return true;
        }

        JitCodeEntry data{};
        if (!ReadMemory(uid.address, &data, jitEntrySize_)) {
            return false;
        }
        data.symfileAddr = StripAddressTag(data.symfileAddr);

        DFXLOGU("ReadNewEntries: uid=0x%{public}" PRIx64 ", symfileAddr=0x%{public}" PRIx64 ", symfileSize=%{public}" PRIu64 "",
            uid.address, data.symfileAddr, data.symfileSize);

        if (!CheckSeqlock(uid, race)) {
            return false;
        }

        auto it = entries_.find(uid);
        if (it != entries_.end()) {
            entries->emplace(uid, it->second);
        } else if (data.symfileAddr != 0) {
            std::shared_ptr<DfxElf> elf;
            bool ok = LoadJitElf(data.symfileAddr, data.symfileSize, elf, uid);
            if (!CheckSeqlock(uid, race)) {
                return false;
            }
            if (ok) {
                entries->emplace(uid, elf);
            }
        }

        JitUID nextUid;
        if (!ReadNextField(uid.address + offsetof(JitCodeEntry, next), &nextUid, race)) {
            return false;
        }
        if (!CheckSeqlock(uid, race)) {
            return false;
        }
        uid = nextUid;
    }

    return true;
}

bool DfxJitDebug::ReadAllEntries(std::map<JitUID, std::shared_ptr<DfxElf>>* entries, bool* race)
{
    for (size_t i = 0; i < MAX_HEAD_RETRIES; i++) {
        size_t oldSize = entries->size();
        if (!ReadNewEntries(entries, race)) {
            return false;
        }
        if (entries->size() == oldSize) {
            entries_.swap(*entries);
            return true;
        }
    }
    return false;
}

bool DfxJitDebug::FindJitElf(uint64_t pc, std::shared_ptr<DfxElf>& elf, uint64_t& loadBias)
{
    std::lock_guard<std::mutex> guard(lock_);
    // miss cache: collapse repeated lookups of the same unmatched pc, so we skip
    // the O(entries) walk and the repeated error log. invalidated when the entry
    // count changes, because jit code cache ranges can be reused after gc.
    static std::mutex s_missMutex;
    static std::unordered_set<uint64_t> s_missedPcs;
    // hit cache: freeze the jit elf of the FIRST successful lookup per pc.
    // the jit code cache may reclaim entries while a caller (e.g. hiperf
    // delayed unwind) keeps unwinding samples of the same pc; the first
    // result is the closest to sampling time, so reuse it for consistency.
    static std::unordered_map<uint64_t, std::pair<std::shared_ptr<DfxElf>, uint64_t>> s_hitPcs;
    static size_t s_entriesSizeWhenCached = 0;
    {
        std::lock_guard<std::mutex> missLock(s_missMutex);
        size_t cached = s_entriesSizeWhenCached;
        size_t nowSz = entries_.size();
        size_t threshold = cached / 8;  // 12.5%
        if (threshold < 4) { threshold = 4; }  // min guard
        if ((nowSz > cached && nowSz - cached > threshold) ||
            (cached > nowSz && cached - nowSz > threshold)) {
            s_missedPcs.clear();
            s_entriesSizeWhenCached = nowSz;
        }
        if (s_missedPcs.find(pc) != s_missedPcs.end()) {
            return false;
        }
        auto hit = s_hitPcs.find(pc);
        if (hit != s_hitPcs.end()) {
            elf = hit->second.first;
            loadBias = hit->second.second;
            return true;
        }
    }

    if (descriptorAddr_ == 0) {
        // See EnsureJitDescriptorLocked: only conclusive per-pid failures are
        // cached; transient ones (maps not set yet) stay retryable.
        if (!EnsureJitDescriptorLocked()) {
            DFXLOGE("FindJitElf: FindJitDescriptor failed for pc=0x%{public}" PRIx64 "", pc);
            return false;
        }
    } else {
        DFXLOGU("FindJitElf: using cached descriptor at 0x%{public}" PRIx64 "", descriptorAddr_);
    }

    for (const auto& it : entries_) {
        const auto& jitElf = it.second;
        if (jitElf != nullptr && jitElf->IsValid()) {
            if (jitElf->IsValidPc(pc)) {
                if (CheckSeqlock(it.first)) {
                    DFXLOGU("FindJitElf: found in cache, pc=0x%{public}" PRIx64 "", pc);
                    elf = jitElf;
                    loadBias = jitElf->GetLoadBias();
                    return true;
                }
            }
        }
    }

    std::map<JitUID, std::shared_ptr<DfxElf>> entries;
    bool race = false;
    ReadAllEntries(&entries, &race);

    // ReadAllEntries swaps data into entries_, so search entries_ not local entries
    DFXLOGU("FindJitElf: checking %{public}zu JIT entries for pc=0x%{public}" PRIx64 "", entries_.size(), pc);
    for (const auto& it : entries_) {
        const auto& jitElf = it.second;
        if (jitElf == nullptr || !jitElf->IsValid()) {
            continue;
        }
        if (jitElf->IsValidPc(pc)) {
            DFXLOGU("FindJitElf: MATCH! pc=0x%{public}" PRIx64 ", range=[0x%{public}" PRIx64 ", 0x%{public}" PRIx64 ")",
                pc, jitElf->GetRuntimeStart(), jitElf->GetRuntimeEnd());
            elf = jitElf;
            loadBias = jitElf->GetLoadBias();
            {
                std::lock_guard<std::mutex> missLock(s_missMutex);
                if (s_hitPcs.size() < 8192) {
                    s_hitPcs[pc] = std::make_pair(jitElf, loadBias);
                }
            }
            return true;
        }
        DFXLOGU("FindJitElf: no match, pc=0x%{public}" PRIx64 ", range=[0x%{public}" PRIx64 ", 0x%{public}" PRIx64 ")",
            pc, jitElf->GetRuntimeStart(), jitElf->GetRuntimeEnd());
    }

    {
        std::lock_guard<std::mutex> missLock(s_missMutex);
        constexpr size_t maxMissCacheSize = 8192;
        if (s_missedPcs.size() < maxMissCacheSize) {
            s_missedPcs.insert(pc);
        }
    }
    DFXLOGE("FindJitElf: no JIT ELF found for pc=0x%{public}" PRIx64 ", entries=%{public}zu", pc, entries_.size());
    return false;
}

bool DfxJitDebug::GetJitSymbolInfo(uint64_t pc, JitSymbolInfo& info)
{
    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;

    if (!FindJitElf(pc, elf, loadBias)) {
        return false;
    }

    info.elf = elf;
    info.loadBias = static_cast<uint64_t>(loadBias);
    if (elf->HasRuntimeRange()) {
        // JIT ELF symbol values are absolute runtime addresses (verified against
        // ART JIT samples, where st_value equals the address inside the JIT code
        // cache). TryJitSymbolLookup computes relPc = pc - startPc, so to keep relPc
        // equal to the absolute runtime pc (and match the absolute symbol values),
        // startPc must be 0. endPc is kept as the runtime range end for callers that
        // use it for boundary checks.
        info.startPc = 0;
        info.endPc = elf->GetRuntimeEnd();
    } else {
        info.startPc = elf->GetStartPc();
        info.endPc = elf->GetEndPc();
    }

    return true;
}

bool DfxJitDebug::ForEachJitElf(uint64_t pc, std::function<bool(const JitSymbolInfo&)> callback)
{
    if (!callback) {
        return false;
    }
    std::lock_guard<std::mutex> guard(lock_);

    if (!EnsureJitDescriptorLocked()) {
        return false;
    }

    auto fillInfo = [](const std::shared_ptr<DfxElf>& jitElf, JitSymbolInfo& info) {
        info.elf = jitElf;
        uint64_t loadBias = jitElf->GetLoadBias();
        info.loadBias = loadBias;
        if (jitElf->HasRuntimeRange()) {
            // See GetJitSymbolInfo: JIT ELF symbols use absolute runtime addresses,
            // so startPc must be 0 to keep relPc = pc in TryJitSymbolLookup.
            info.startPc = 0;
            info.endPc = jitElf->GetRuntimeEnd();
        } else {
            info.startPc = jitElf->GetStartVaddr() + loadBias;
            info.endPc = jitElf->GetEndVaddr() + loadBias;
        }
    };

    for (const auto& it : entries_) {
        const auto& jitElf = it.second;
        if (jitElf != nullptr && jitElf->IsValid()) {
            if (jitElf->IsValidPc(pc)) {
                if (CheckSeqlock(it.first)) {
                    JitSymbolInfo info;
                    fillInfo(jitElf, info);
                    if (callback(info)) {
                        return true;
                    }
                }
            }
        }
    }

    std::map<JitUID, std::shared_ptr<DfxElf>> entries;
    bool race = false;
    ReadAllEntries(&entries, &race);

    for (const auto& it : entries) {
        const auto& jitElf = it.second;
        if (jitElf != nullptr && jitElf->IsValid()) {
            if (jitElf->IsValidPc(pc)) {
                JitSymbolInfo info;
                fillInfo(jitElf, info);
                if (callback(info)) {
                    return true;
                }
            }
        }
    }

    return false;
}

} // namespace HiviewDFX
} // namespace OHOS