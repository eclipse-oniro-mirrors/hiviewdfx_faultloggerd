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
// V1 布局(无 Android 扩展字段)截止到 timestamp 之前:
//   next + prev + symfileAddr + symfileSize = 4 * sizeof(uint64_t),64 位下 32 字节。
// V2 布局(Android "Android2" 魔数)增加 timestamp + seqlock + 填充 = sizeof(JitCodeEntry)。
// 用 offsetof/sizeof 定义常量,保证在宿主机任意指针宽度下都正确。
constexpr size_t DESCRIPTOR_SIZE_V1 = 24;  // version + action_flag + relevant_entry + first_entry
constexpr size_t DESCRIPTOR_SIZE_V2 = 56;  // V1 + Android 扩展的 magic/flags/sizes/seqlock/timestamp
constexpr size_t CODE_ENTRY_SIZE_V1 = offsetof(JitCodeEntry, timestamp);
constexpr size_t CODE_ENTRY_SIZE_V2 = sizeof(JitCodeEntry);

// JIT 描述符注册在 ART 运行时里,只在下面这些库中搜索。
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
    // 远程进程直接用 ReadProcMemByPid 读 /proc/pid/mem。必须如此:
    // DfxMemory::Read 会先尝试从 ELF mmap 读,而 .bss 段不在 ELF 文件里,
    // 那样读会失败。
    if (pid_ > 0 && pid_ != getpid()) {
        size_t read = ReadProcMemByPid(pid_, addr, buf, size);
        if (read == size) {
            return true;
        }
        DFXLOGE("ReadMemory: ReadProcMemByPid failed, pid=%{public}d, addr=0x%{public}" PRIx64 ", read=%{public}zu, expected=%{public}zu",
            pid_, addr, read, size);
        return false;
    }
    // 本进程则用 DfxMemory::Read。
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

// 去掉 ARM64 MTE/TBI 的高位地址标签(保留低 56 位)。
uint64_t DfxJitDebug::StripAddressTag(uint64_t addr)
{
    if (arch_ == ARCH_ARM64) {
        return static_cast<uint64_t>((static_cast<int64_t>(addr) << 8) >> 8);
    }
    return addr;
}

// 本进程:dlsym 直接取 __jit_debug_descriptor 地址。
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

// 定位 __jit_debug_descriptor 并读出描述符。本进程先走 dlsym;远程则
// 扫描 maps 找 libart.so/libartd.so 的 ELF 头映射(只读、offset 0 行),
// 用 FindGlobalVariableByName 按名查符号,vaddr + 映射基址得运行时
// 地址,再按地址反查所属 map 后经 ReadDescriptor 验证版本与魔数。
// 三种结果:FOUND / RETRY_LATER(maps 未设,可重试)/ NOT_PRESENT
// (搜遍无果,对本 pid 终局)。
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

        // libart.so/libartd.so 的 ELF 头映射(只读、offset 0):其 begin 即
        // vaddr 0 的运行时地址,故 vaddr 为 V 的符号位于 mapZero->begin + V。
        // 描述符可能落在该映像随后的任意映射里(relro 页或无名的匿名 .bss
        // 尾部),所以要按地址反查所属 map。
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

// 读取并识别描述符版本:magic 为 "Android2" 走 V2 表项(含 seqlock),
// 否则按 V1(无 seqlock)处理。
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

// 双读 + seqlock 校验读取链表指针字段:读两次目标字段并核对所指表项的
// seqlock,两次不一致或 seqlock 为奇数(写入进行中)即判定发生竞争。
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

// 复核表项 seqlock 未变:读取 ELF 期间目标可能已被 ART 回收重写。
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
        // ART/ets_runtime 的 JIT ELF 把 .text 字节的绝对运行时地址存在
        // sh_addr(ART 里是 JIT 代码缓存内的地址,ets_runtime 里是
        // symfile_addr + sh_offset)。无论哪种,sh_addr 已是运行时 PC,
        // 绝不能再加 addr(symfile_addr)。loadBase 置 0 使
        // IsValidPc/FindUnwindTableInfo 与该布局保持一致(对齐
        // libunwindstack 参考实现,从不加 symfile_addr)。
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
            // JIT ELF 的符号值同样是绝对运行时地址(经 ART JIT 样本实证),
            // 无需再加 addr。
            uint64_t runtimeStart = minAddr;
            uint64_t runtimeEnd = maxAddr;
            elf->SetRuntimeRange(runtimeStart, runtimeEnd);
            elf->SetLoadBase(0);
            DFXLOGU("Loaded JIT ELF: addr=0x%{public}" PRIx64 ", size=%{public}" PRIu64 ", symRange=[0x%{public}" PRIx64 ", 0x%{public}" PRIx64 "), runtime=[0x%{public}" PRIx64 ", 0x%{public}" PRIx64 ")",
                addr, size, minAddr, maxAddr, runtimeStart, runtimeEnd);
        } else {
            // 兜底:用 PT_LOAD 段推算运行时区间。ART JIT ELF 常见 .text 的
            // sh_size=0(代码在 JIT 代码缓存里,不在 ELF 文件内)、符号
            // st_size=0,上面两条路都得不到区间;但 PT_LOAD 的 p_vaddr 存的
            // 是 JIT 代码的绝对运行时地址(参见 libunwindstack
            // ElfInterface::IsValidPc,用 [p_vaddr, p_vaddr + p_memsz) 匹配
            // PC)。取该区间后,IsValidPc/FindUnwindTableInfo 匹配 PC 便
            // 无需依赖节头或符号。
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

// 沿链表读取新表项:从描述符 firstEntry 出发逐项走 next 指针,
// 逐项 seqlock 校验,已缓存的 ELF 直接复用,新表项现场加载。
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

// 重试到一轮读取不再新增表项为止:链表头在读取期间被并发修改会引入新项,
// 连续两轮数量不变才说明快照稳定,方可换入 entries_;超过 MAX_HEAD_RETRIES
// 轮仍不稳定则放弃。
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
    // miss 缓存:把同一未命中 pc 的重复查找折叠掉,省去 O(entries) 遍历和
    // 重复报错日志。表项数量变化时整体失效——GC 后 JIT 代码缓存区间可能复用。
    // F16-0:键带上 pid。缓存是进程级 static,而 DfxJitDebug 实例按 pid 独立
    // (每个 Unwinder 一个),裸 pc 键会让一个进程命中另一进程同数值地址上的
    // jit elf。按 pid 分桶:若用扁平 (pid,pc) 键配一个全局 8192 上限,首个
    // pid 会塞满整表饿死后续 pid(其每次查找都退化成 O(entries) 遍历+远程
    // 读),且已死 pid 的 elf 被永久钉住。分桶后各 pid 有独立上限,整桶按
    // LRU 淘汰,不会被无限期钉住。
    struct PerPidJitCache {
        std::unordered_map<uint64_t, std::pair<std::shared_ptr<DfxElf>, uint64_t>> hitPcs;
        std::unordered_set<uint64_t> missedPcs;
        size_t entriesSizeWhenCached = 0;
    };
    static std::mutex s_missMutex;
    static std::unordered_map<uint32_t, PerPidJitCache> s_jitPerPid;
    static std::deque<uint32_t> s_pidLru; // 队首=最久未使用
    constexpr size_t kMaxPerPidEntries = 8192;
    constexpr size_t kMaxPids = 4;
    const uint32_t keyPid = static_cast<uint32_t>(pid_);
    {
        std::lock_guard<std::mutex> missLock(s_missMutex);
        auto lruIt = std::find(s_pidLru.begin(), s_pidLru.end(), keyPid);
        if (lruIt != s_pidLru.end()) {
            s_pidLru.erase(lruIt);
        }
        s_pidLru.push_back(keyPid);
        while (s_pidLru.size() > kMaxPids) {
            s_jitPerPid.erase(s_pidLru.front());
            s_pidLru.pop_front();
        }
        PerPidJitCache& bucket = s_jitPerPid[keyPid];
        if (entries_.size() != bucket.entriesSizeWhenCached) {
            bucket.missedPcs.clear(); // 只清本 pid 的 miss,其他 pid 不受影响
            bucket.entriesSizeWhenCached = entries_.size();
        }
        if (bucket.missedPcs.find(pc) != bucket.missedPcs.end()) {
            return false;
        }
        auto hit = bucket.hitPcs.find(pc);
        if (hit != bucket.hitPcs.end()) {
            elf = hit->second.first;
            loadBias = hit->second.second;
            return true;
        }
    }

    if (descriptorAddr_ == 0) {
        // 见 EnsureJitDescriptorLocked:只缓存确定性的按 pid 失败;
        // 暂态失败(maps 尚未设置)保持可重试。
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

    // ReadAllEntries 已把数据换入 entries_,这里搜 entries_ 而非局部 entries
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
                auto& bucket = s_jitPerPid[keyPid];
                if (bucket.hitPcs.size() < kMaxPerPidEntries) {
                    bucket.hitPcs[pc] = std::make_pair(jitElf, loadBias);
                }
            }
            return true;
        }
        DFXLOGU("FindJitElf: no match, pc=0x%{public}" PRIx64 ", range=[0x%{public}" PRIx64 ", 0x%{public}" PRIx64 ")",
            pc, jitElf->GetRuntimeStart(), jitElf->GetRuntimeEnd());
    }

    {
        std::lock_guard<std::mutex> missLock(s_missMutex);
        auto& bucket = s_jitPerPid[keyPid];
        if (bucket.missedPcs.size() < kMaxPerPidEntries) {
            bucket.missedPcs.insert(pc);
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
        // JIT ELF 符号值是绝对运行时地址(经 ART JIT 样本实证,st_value 即
        // JIT 代码缓存内的地址)。TryJitSymbolLookup 计算 relPc = pc - startPc,
        // 要让 relPc 等于绝对运行时 pc(与绝对符号值匹配),startPc 必须为 0。
        // endPc 保留运行时区间终点,供调用方做边界判断。
        info.startPc = 0;
        info.endPc = elf->GetRuntimeEnd();
    } else {
        info.startPc = elf->GetStartPc();
        info.endPc = elf->GetEndPc();
    }

    return true;
}

// 枚举覆盖 pc 的全部 JIT ELF(接口说明见头文件):先扫缓存表项
// (IsValidPc 命中后 seqlock 复核),再增量重读链表(ReadAllEntries)
// 扫新表项;每命中一个构造 JitSymbolInfo 回调一次。
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
            // 同 GetJitSymbolInfo:JIT ELF 符号是绝对运行时地址,
            // startPc 必须为 0,TryJitSymbolLookup 里才有 relPc = pc。
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