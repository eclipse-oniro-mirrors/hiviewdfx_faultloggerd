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
#ifndef DFX_JIT_DEBUG_H
#define DFX_JIT_DEBUG_H

#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include "dfx_define.h"
#include "dfx_elf.h"
#include "dfx_map.h"
#include "dfx_memory.h"
#include "dfx_mmap.h"
#include "unwind_define.h"

namespace OHOS {
namespace HiviewDFX {

struct JitCodeEntry {
    uint64_t next;
    uint64_t prev;
    uint64_t symfileAddr;
    uint64_t symfileSize;
    uint64_t timestamp;
    uint32_t seqlock;
};
// Layout must match libunwindstack GlobalDebugImpl<Elf, uint64_t, Uint64_A> for ARM64.
static_assert(offsetof(JitCodeEntry, symfileSize) == 24, "JIT code entry layout mismatch");
static_assert(offsetof(JitCodeEntry, seqlock) == 40, "JIT code entry layout mismatch");
static_assert(sizeof(JitCodeEntry) == 48, "JIT code entry layout mismatch");

struct JitDescriptor {
    uint32_t version;
    uint32_t actionFlag;
    uint64_t relevantEntry;
    uint64_t firstEntry;
    uint8_t magic[8];
    uint32_t flags;
    uint32_t sizeofDescriptor;
    uint32_t sizeofEntry;
    uint32_t seqlock;
    uint64_t timestamp;
};
static_assert(offsetof(JitDescriptor, magic) == 24, "JIT descriptor layout mismatch");
static_assert(sizeof(JitDescriptor) == 56, "JIT descriptor layout mismatch");

struct JitUID {
    uint64_t address;
    uint32_t seqlock;

    bool operator<(const JitUID& other) const
    {
        return address < other.address || (address == other.address && seqlock < other.seqlock);
    }
};

struct JitSymbolInfo {
    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias;
    uint64_t startPc;
    uint64_t endPc;
};

class DfxJitDebug {
public:
    // Owned per Unwinder (one DfxJitDebug per unwind session): the cached
    // descriptor and elf entries are bound to that session's target pid, so a
    // process-global instance would leak state across pids.
    DfxJitDebug() = default;
    ~DfxJitDebug() = default;
    void SetMemory(const std::shared_ptr<DfxMemory>& memory);
    void SetMaps(const std::shared_ptr<DfxMaps>& maps);
    void SetPid(pid_t pid);
    void SetArch(ArchType arch);

    bool FindJitElf(uint64_t pc, std::shared_ptr<DfxElf>& elf, uint64_t& loadBias);
    bool GetJitSymbolInfo(uint64_t pc, JitSymbolInfo& info);
    bool ForEachJitElf(uint64_t pc, std::function<bool(const JitSymbolInfo&)> callback);
    bool HasJitDebugInfo() const { return descriptorAddr_ != 0; }
    void Clear();

private:
    DfxJitDebug(const DfxJitDebug&) = delete;
    DfxJitDebug& operator=(const DfxJitDebug&) = delete;

    // Outcome of a descriptor search, used to decide whether the per-pid failure
    // cache may be updated (see EnsureJitDescriptorLocked).
    enum class JitDescriptorStatus {
        FOUND,        // descriptor located, descriptorAddr_ is valid
        RETRY_LATER,  // transient condition (maps not set yet): not conclusive for this pid
        NOT_PRESENT,  // searched with valid maps: conclusively absent for this pid
    };

    // Caller must hold lock_. Locates the descriptor if not yet known. Only
    // conclusive failures (NOT_PRESENT) update descriptorCheckedPid_: libart is
    // loaded at process start and never unloads, so a completed search is final,
    // while transient conditions such as maps being null must stay retryable —
    // caching one would blind every later JIT lookup for this pid for the rest
    // of the session.
    bool EnsureJitDescriptorLocked();

    JitDescriptorStatus FindJitDescriptor();
    bool FindJitDescriptorLocal();
    bool ReadDescriptor();
    bool ReadAllEntries(std::map<JitUID, std::shared_ptr<DfxElf>>* entries, bool* race);
    bool ReadNewEntries(std::map<JitUID, std::shared_ptr<DfxElf>>* entries, bool* race);
    bool ReadNextField(uint64_t fieldAddr, JitUID* uid, bool* race);
    bool CheckSeqlock(const JitUID& uid, bool* race = nullptr);
    bool LoadJitElf(uint64_t addr, uint64_t size, std::shared_ptr<DfxElf>& elf, const JitUID& uid);
    uint64_t StripAddressTag(uint64_t addr);

    bool ReadMemory(uint64_t addr, void* buf, size_t size);
    bool ReadU64(uint64_t addr, uint64_t* val);
    bool ReadU32(uint64_t addr, uint32_t* val);

    static constexpr int MAX_HEAD_RETRIES = 16;
    static constexpr uint8_t JIT_MAGIC[] = {'A', 'n', 'd', 'r', 'o', 'i', 'd', '2'};

    std::shared_ptr<DfxMemory> memory_;
    std::shared_ptr<DfxMaps> maps_;
    pid_t pid_ = 0;
    ArchType arch_ = ARCH_ARM64;

    std::mutex lock_;
    uint64_t descriptorAddr_ = 0;
    // pid for which FindJitDescriptor has conclusively failed (NOT_PRESENT).
    // Without this, every FindJitElf call on a non-ART process rescans all maps
    // and retries opening libart.so, flooding logs and wasting time on the
    // DWARF-failure fallback path. Transient failures are never cached here.
    pid_t descriptorCheckedPid_ = -1;
    uint32_t jitEntrySize_ = 0;
    uint32_t seqlockOffset_ = 0;
    std::map<JitUID, std::shared_ptr<DfxElf>> entries_;
};

} // namespace HiviewDFX
} // namespace OHOS
#endif // DFX_JIT_DEBUG_H