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
// JIT 代码链表节点(存在于目标进程内存中,须远程逐字段读取)。
// 布局必须与 libunwindstack ARM64 的 GlobalDebugImpl<Elf, uint64_t, Uint64_A> 一致。
static_assert(offsetof(JitCodeEntry, symfileSize) == 24, "JIT code entry layout mismatch");
static_assert(offsetof(JitCodeEntry, seqlock) == 40, "JIT code entry layout mismatch");
static_assert(sizeof(JitCodeEntry) == 48, "JIT code entry layout mismatch");

// JIT 描述符(libart 发布的全局变量 __jit_debug_descriptor):JIT 代码链表头,
// firstEntry 指向首个 JitCodeEntry;magic 为 "Android2" 表示启用
// 时间戳+seqlock 防竞争扩展。
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

// 表项身份标识:地址+读取时的 seqlock。GC 后 JIT 代码缓存地址可能复用,
// 仅凭地址会把新 ELF 误当旧缓存,seqlock 用于区分同一地址的新旧版本。
struct JitUID {
    uint64_t address;
    uint32_t seqlock;

    bool operator<(const JitUID& other) const
    {
        return address < other.address || (address == other.address && seqlock < other.seqlock);
    }
};

// 命中后返回给调用方的 JIT 符号信息(ELF+loadBias+PC 区间)。
struct JitSymbolInfo {
    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias;
    uint64_t startPc;
    uint64_t endPc;
};

class DfxJitDebug {
public:
    // 归属单个 Unwinder(每次回溯会话一个 DfxJitDebug 实例):缓存的描述符
    // 与 elf 表项都绑定该会话的目标 pid,做成进程级单例会跨 pid 泄漏状态。
    DfxJitDebug() = default;
    ~DfxJitDebug() = default;
    void SetMemory(const std::shared_ptr<DfxMemory>& memory);
    void SetMaps(const std::shared_ptr<DfxMaps>& maps);
    void SetPid(pid_t pid);
    void SetArch(ArchType arch);

    // 判定 pc 是否属于某个 JIT 代码块,命中返回该块的内存 ELF 与
    // loadBias。流程:查进程级 hit/miss 缓存(按 pid 分桶,miss 缓存在
    // 表项数变化时整体失效)→ 未命中先确保描述符已定位
    // (EnsureJitDescriptorLocked)→ 遍历已缓存表项(IsValidPc 比对 +
    // seqlock 复核)→ 仍未中则增量重读链表(ReadAllEntries)再比对。
    // TryJitStep(JIT 帧步进)与 TryJitSymbolLookup(JIT 符号化)的
    // 共同入口。
    bool FindJitElf(uint64_t pc, std::shared_ptr<DfxElf>& elf, uint64_t& loadBias);
    // FindJitElf 的符号化包装:命中时额外给出 startPc/endPc/loadBias。
    // 带运行时区间的 JIT ELF 符号值是绝对运行时地址,故 startPc 置 0,
    // 使调用方 relPc = pc - startPc 等于绝对 pc,与符号值同量纲。
    bool GetJitSymbolInfo(uint64_t pc, JitSymbolInfo& info);
    // 枚举所有覆盖 pc 的 JIT ELF:先扫缓存表项(seqlock 复核),再增量
    // 重读链表扫新表项;每命中一个回调一次,回调返回 true 即停止。
    // 与 FindJitElf 的区别:不写 hit/miss 缓存,适合一次性枚举场景。
    bool ForEachJitElf(uint64_t pc, std::function<bool(const JitSymbolInfo&)> callback);
    // 描述符是否已定位(__jit_debug_descriptor 地址非 0)。
    bool HasJitDebugInfo() const { return descriptorAddr_ != 0; }
    // 清空描述符地址、表项缓存与失败缓存(Unwinder 换目标 pid 时调用)。
    void Clear();

private:
    DfxJitDebug(const DfxJitDebug&) = delete;
    DfxJitDebug& operator=(const DfxJitDebug&) = delete;

    // 描述符查找结果,用于决定是否更新按 pid 记录的失败缓存
    // (见 EnsureJitDescriptorLocked)。
    enum class JitDescriptorStatus {
        FOUND,        // 已找到描述符,descriptorAddr_ 有效
        RETRY_LATER,  // 暂态条件(maps 尚未设置):对本 pid 无结论
        NOT_PRESENT,  // 已在有效 maps 下搜索:本 pid 确定不存在
    };

    // 调用方须持有 lock_。描述符未知时执行定位。只有确定性失败(NOT_PRESENT)
    // 才写入 descriptorCheckedPid_:libart 随进程启动加载且永不卸载,搜索完成
    // 即是终局;而 maps 为空之类的暂态条件必须保持可重试——若把暂态失败也
    // 缓存,本 pid 在会话剩余时间内的所有 JIT 查找都会被"致盲"。
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
    // FindJitDescriptor 已确定性失败(NOT_PRESENT)的 pid。没有它,非 ART
    // 进程每次 FindJitElf 都要重扫全部 maps 并重试打开 libart.so,在
    // DWARF 失败兜底路径上刷爆日志、白白耗时。暂态失败从不写入此缓存。
    pid_t descriptorCheckedPid_ = -1;
    uint32_t jitEntrySize_ = 0;
    uint32_t seqlockOffset_ = 0;
    std::map<JitUID, std::shared_ptr<DfxElf>> entries_;
};

} // namespace HiviewDFX
} // namespace OHOS
#endif // DFX_JIT_DEBUG_H