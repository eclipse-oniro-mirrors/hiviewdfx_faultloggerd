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
#include <deque>
#include <algorithm>
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
constexpr size_t DESCRIPTOR_SIZE_V1 = 24;
constexpr size_t DESCRIPTOR_SIZE_V2 = 56;
constexpr size_t MAX_JIT_WALK_ENTRIES = 1024 * 1024;
constexpr size_t MAX_JIT_VISITED_ENTRIES = 8192;
constexpr size_t CODE_ENTRY_SIZE_V1 = offsetof(JitCodeEntry, timestamp);
constexpr size_t CODE_ENTRY_SIZE_V2 = sizeof(JitCodeEntry);

const std::vector<std::string>& GetSearchLibs()
{
    std::string libArtName = std::string("lib") + "art" + ".so";
    std::string libArtdName = std::string("lib") + "artd" + ".so";
    static const std::vector<std::string> searchLibs = {libArtName, libArtdName};
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

bool DfxJitDebug::ReadMemory(uint64_t addr, void* buf, size_t size)
{
    if (buf == nullptr || size == 0) {
        return false;
    }
    if (pid_ > 0 && pid_ != getpid()) {
        size_t read = ReadProcMemByPid(pid_, addr, buf, size);
        if (read == size) {
            return true;
        }
        DFXLOGE("ReadMemory: ReadProcMemByPid failed, pid=%{public}d, "
            "addr=0x%{public}" PRIx64 ", read=%{public}zu, expected=%{public}zu",
            pid_, addr, read, size);
        return false;
    }
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
        constexpr uint64_t arm64TagBits = 8;
        return (addr << arm64TagBits) >> arm64TagBits;
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
    if (!ReadDescriptor()) {
        descriptorAddr_ = 0;
        return false;
    }
    return true;
}

DfxJitDebug::JitDescriptorStatus DfxJitDebug::FindJitDescriptor()
{
    if (pid_ <= 0 || pid_ == getpid()) {
        if (FindJitDescriptorLocal()) {
            return JitDescriptorStatus::FOUND;
        }
    }

    if (maps_ == nullptr) {
        DFXLOGU("FindJitDescriptor: maps is null");
        return JitDescriptorStatus::RETRY_LATER;
    }

    std::shared_ptr<DfxMap> mapZero = nullptr;
    const auto& maps = maps_->GetMaps();

    for (const auto& map : maps) {
        if (map == nullptr) {
            continue;
        }

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
            descriptorAddr_ = runtimeAddr;
            if (ReadDescriptor()) {
                return JitDescriptorStatus::FOUND;
            }
            descriptorAddr_ = 0;
            DFXLOGE("FindJitDescriptor: ReadDescriptor failed at 0x%{public}" PRIx64 "", runtimeAddr);
        }
    }

    DFXLOGE("FindJitDescriptor: not found in any art.so/artd so map");
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
    bool readV2 = ReadMemory(descriptorAddr_, &desc, DESCRIPTOR_SIZE_V2);
    if (!readV2) {
        bool readV1 = ReadMemory(descriptorAddr_, &desc, DESCRIPTOR_SIZE_V1);
        if (!readV1) {
            DFXLOGE("ReadDescriptor: failed to read from 0x%{public}" PRIx64 "", descriptorAddr_);
            return false;
        }
    }

    if (desc.version != 1) {
        return false;
    }

    static constexpr uint8_t jitMagic[] = {'A', 'n', 'd', 'r', 'o', 'i', 'd', '2'};
    if (memcmp(desc.magic, jitMagic, sizeof(jitMagic)) == 0) {
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
    constexpr int seqlockReadCount = 2;
    uint64_t address[seqlockReadCount] = {0, 0};
    uint32_t seqlock[seqlockReadCount] = {0, 0};

    for (int i = 0; i < seqlockReadCount; i++) {
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
    constexpr uint64_t kMaxSymfileSize = 64ULL << 20;
    if (size > kMaxSymfileSize) {
        DFXLOGE("LoadJitElf: symfileSize %{public}" PRIu64 " too large, skip entry at 0x%{public}" PRIx64,
            size, addr);
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
        DFXLOGU("JIT ELF is not valid");
        elf = nullptr;
        return false;
    }

    if (!TrySetJitRangeFromTextSection(elf)) {
        if (!TrySetJitRangeFromSymbols(elf)) {
            SetJitRangeFromPtLoads(elf);
        }
    }

    return true;
}

bool DfxJitDebug::TrySetJitRangeFromTextSection(const std::shared_ptr<DfxElf>& elf)
{
    ShdrInfo textShdr;
    if (elf->GetSectionInfo(textShdr, ".text") && textShdr.size != 0) {
        uint64_t runtimeStart = textShdr.addr;
        uint64_t runtimeEnd = runtimeStart + textShdr.size;
        elf->SetRuntimeRange(runtimeStart, runtimeEnd);
        elf->SetLoadBase(0);
        return true;
    }
    return false;
}

bool DfxJitDebug::TrySetJitRangeFromSymbols(const std::shared_ptr<DfxElf>& elf)
{
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
        uint64_t runtimeStart = minAddr;
        uint64_t runtimeEnd = maxAddr;
        elf->SetRuntimeRange(runtimeStart, runtimeEnd);
        elf->SetLoadBase(0);
        return true;
    }
    return false;
}

void DfxJitDebug::SetJitRangeFromPtLoads(const std::shared_ptr<DfxElf>& elf)
{
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
    }
}

bool DfxJitDebug::ResolveEntryElf(const JitUID& uid, const JitCodeEntry& data,
    std::map<JitUID, std::shared_ptr<DfxElf>>* entries, bool* race)
{
    auto it = entries_.find(uid);
    if (it != entries_.end()) {
        entries->emplace(uid, it->second);
    } else if (data.symfileAddr != 0) {
        std::shared_ptr<DfxElf> elf;
        bool isElfLoaded = LoadJitElf(data.symfileAddr, data.symfileSize, elf, uid);
        if (!CheckSeqlock(uid, race)) {
            return false;
        }
        if (isElfLoaded) {
            entries->emplace(uid, elf);
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

    std::unordered_set<uint64_t> visited;
    size_t steps = 0;
    while (uid.address != 0) {
        if (++steps > MAX_JIT_WALK_ENTRIES) {
            DFXLOGU("ReadNewEntries: entry budget %{public}zu exhausted", MAX_JIT_WALK_ENTRIES);
            return false;
        }
        if (visited.size() < MAX_JIT_VISITED_ENTRIES &&
            !visited.insert(StripAddressTag(uid.address)).second) {
            return false;
        }
        if (entries->find(uid) != entries->end()) {
            return true;
        }

        JitCodeEntry data{};
        if (!ReadMemory(uid.address, &data, jitEntrySize_)) {
            return false;
        }
        data.symfileAddr = StripAddressTag(data.symfileAddr);

        if (!CheckSeqlock(uid, race)) {
            return false;
        }

        if (!ResolveEntryElf(uid, data, entries, race)) {
            return false;
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

bool DfxJitDebug::ReadAllEntriesRaceRetry()
{
    for (int i = 0; i < MAX_RACE_RETRIES; i++) {
        std::map<JitUID, std::shared_ptr<DfxElf>> entries;
        bool race = false;
        if (!ReadAllEntries(&entries, &race)) {
            if (race) {
                continue;
            }
            return false;
        }
        return true;
    }
    return false;
}

namespace {
struct JitPcHit {
    JitUID uid;
    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias;
};

struct PerPidJitCache {
    std::unordered_map<uint64_t, JitPcHit> hitPcs;
    std::unordered_set<uint64_t> missedPcs;
    size_t entriesSizeWhenCached = 0;
};
} // namespace

static std::mutex g_missMutex;
static std::unordered_map<uint32_t, PerPidJitCache> g_jitPerPid;
static std::deque<uint32_t> g_pidLru;

constexpr size_t MAX_JIT_CACHE_PER_PID_ENTRIES = 8192;
constexpr size_t MAX_JIT_CACHE_PIDS = 4;

static PerPidJitCache& AcquireJitBucketLocked(uint32_t pid)
{
    auto lruIt = std::find(g_pidLru.begin(), g_pidLru.end(), pid);
    if (lruIt != g_pidLru.end()) {
        g_pidLru.erase(lruIt);
    }
    g_pidLru.push_back(pid);
    while (g_pidLru.size() > MAX_JIT_CACHE_PIDS) {
        g_jitPerPid.erase(g_pidLru.front());
        g_pidLru.pop_front();
    }
    return g_jitPerPid[pid];
}

DfxJitDebug::JitCacheResult DfxJitDebug::LookupJitCache(uint64_t pc, std::shared_ptr<DfxElf>& elf,
    uint64_t& loadBias)
{
    bool hitCached = false;
    JitUID hitUid {};
    std::shared_ptr<DfxElf> hitElf;
    uint64_t hitLoadBias = 0;
    {
        std::lock_guard<std::mutex> missLock(g_missMutex);
        PerPidJitCache& bucket = AcquireJitBucketLocked(static_cast<uint32_t>(pid_));
        if (entries_.size() != bucket.entriesSizeWhenCached) {
            bucket.missedPcs.clear();
            bucket.hitPcs.clear();
            bucket.entriesSizeWhenCached = entries_.size();
        }
        if (bucket.missedPcs.find(pc) != bucket.missedPcs.end()) {
            return JitCacheResult::KNOWN_MISS;
        }
        auto hit = bucket.hitPcs.find(pc);
        if (hit != bucket.hitPcs.end()) {
            hitUid = hit->second.uid;
            hitElf = hit->second.elf;
            hitLoadBias = hit->second.loadBias;
            hitCached = true;
        }
    }
    if (hitCached) {
        if (CheckSeqlock(hitUid)) {
            elf = hitElf;
            loadBias = hitLoadBias;
            return JitCacheResult::HIT;
        }
        std::lock_guard<std::mutex> missLock(g_missMutex);
        AcquireJitBucketLocked(static_cast<uint32_t>(pid_)).hitPcs.erase(pc);
    }
    return JitCacheResult::MISS;
}

bool DfxJitDebug::ScanEntriesForPc(uint64_t pc, std::shared_ptr<DfxElf>& elf, uint64_t& loadBias)
{
    for (const auto& it : entries_) {
        const auto& jitElf = it.second;
        if (jitElf == nullptr || !jitElf->IsValid()) {
            continue;
        }
        if (jitElf->IsValidPc(pc)) {
            if (!CheckSeqlock(it.first)) {
                continue;
            }
            elf = jitElf;
            loadBias = static_cast<uint64_t>(jitElf->GetLoadBias());
            return true;
        }
    }
    return false;
}

bool DfxJitDebug::ScanEntriesForPcAndCacheHit(uint64_t pc, std::shared_ptr<DfxElf>& elf, uint64_t& loadBias)
{
    for (const auto& it : entries_) {
        const auto& jitElf = it.second;
        if (jitElf == nullptr || !jitElf->IsValid()) {
            continue;
        }
        if (jitElf->IsValidPc(pc)) {
            if (!CheckSeqlock(it.first)) {
                continue;
            }
            elf = jitElf;
            loadBias = static_cast<uint64_t>(jitElf->GetLoadBias());
            {
                std::lock_guard<std::mutex> missLock(g_missMutex);
                PerPidJitCache& bucket = AcquireJitBucketLocked(static_cast<uint32_t>(pid_));
                if (bucket.hitPcs.size() < MAX_JIT_CACHE_PER_PID_ENTRIES) {
                    bucket.hitPcs[pc] = {it.first, jitElf, loadBias};
                }
            }
            return true;
        }
    }
    return false;
}

void DfxJitDebug::RecordJitMiss(uint64_t pc)
{
    std::lock_guard<std::mutex> missLock(g_missMutex);
    PerPidJitCache& bucket = AcquireJitBucketLocked(static_cast<uint32_t>(pid_));
    if (bucket.missedPcs.size() < MAX_JIT_CACHE_PER_PID_ENTRIES) {
        bucket.missedPcs.insert(pc);
    }
}

bool DfxJitDebug::FindJitElf(uint64_t pc, std::shared_ptr<DfxElf>& elf, uint64_t& loadBias)
{
    std::lock_guard<std::mutex> guard(lock_);
    if (descriptorPid_ != pid_) {
        descriptorAddr_ = 0;
        entries_.clear();
        descriptorPid_ = pid_;
    }

    JitCacheResult cached = LookupJitCache(pc, elf, loadBias);
    if (cached == JitCacheResult::HIT) {
        return true;
    }
    if (cached == JitCacheResult::KNOWN_MISS) {
        return false;
    }

    if (descriptorAddr_ == 0) {
        if (!EnsureJitDescriptorLocked()) {
            DFXLOGE("FindJitElf: FindJitDescriptor failed for pc=0x%{public}" PRIx64 "", pc);
            return false;
        }
    }

    if (ScanEntriesForPc(pc, elf, loadBias)) {
        return true;
    }

    bool readOk = ReadAllEntriesRaceRetry();

    if (ScanEntriesForPcAndCacheHit(pc, elf, loadBias)) {
        return true;
    }

    if (readOk) {
        RecordJitMiss(pc);
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
        info.startPc = 0;
        info.endPc = elf->GetRuntimeEnd();
    } else {
        info.startPc = elf->GetStartPc();
        info.endPc = elf->GetEndPc();
    }

    return true;
}

} // namespace HiviewDFX
} // namespace OHOS