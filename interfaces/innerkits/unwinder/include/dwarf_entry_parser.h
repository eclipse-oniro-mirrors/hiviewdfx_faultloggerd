/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef DWARF_ENTRY_PARSER_H
#define DWARF_ENTRY_PARSER_H

#include <cinttypes>
#include <memory>
#include <list>
#include <vector>
#include <unordered_map>
#include "dwarf_define.h"
#include "dfx_errors.h"
#include "dfx_memory.h"
#include "dfx_regs.h"
#include "unwind_context.h"
#include "unwind_entry_parser.h"

namespace OHOS {
namespace HiviewDFX {
class DwarfEntryParser : public UnwindEntryParser {
public:
    explicit DwarfEntryParser(const std::shared_ptr<DfxMemory>& memory) : UnwindEntryParser(memory) {}
    ~DwarfEntryParser() override = default;
    // 进入/退出 .debug_frame 解析模式。两种格式的 entry 头约定不同,
    // 三处随之切换:①CIE 哨兵值——eh_frame 为 0,debug_frame 为全 1
    // (0xffffffff/0xffffffffffffffff);②CIE 指针语义——eh_frame 是
    // 相对回退量(cieAddr = ptr - ciePtr),debug_frame 是 section 起始
    // 处的绝对偏移(cieAddr = entriesOffset + ciePtr);③指针初始编码
    // ——debug_frame 用 absptr,eh_frame 用 sdata4/sdata8。
    // entriesOffset 记录 section 起始(tableData),兼作失败缓存
    // (s_failedFdes)的键,区分不同 section 中的同地址 fde。每次
    // Step 开始按 uti 重设。
    void SetDebugFrameMode(bool isDebugFrame, uintptr_t entriesOffset)
    {
        isDebugFrame_ = isDebugFrame;
        entriesOffset_ = entriesOffset;
        cie32Value_ = isDebugFrame ? static_cast<uint32_t>(-1) : 0;
        cie64Value_ = isDebugFrame ? static_cast<uint64_t>(-1) : 0;
    }
    bool Step(uintptr_t pc, const UnwindTableInfo& uti, std::shared_ptr<RegLocState> rs) override;
protected:
    bool SearchEntry(uintptr_t pc, const UnwindTableInfo& uti, UnwindEntryInfo& uei) override;
    bool ParseFde(uintptr_t fdeAddr, uintptr_t fdePtr, FrameDescEntry& fdeInfo);
    bool ParseCie(uintptr_t cieAddr, uintptr_t ciePtr, CommonInfoEntry& cieInfo);
private:
    bool LinearSearchEntry(uintptr_t pc, const UnwindTableInfo& uti, UnwindEntryInfo& uei,
        const FrameDescEntry** cachedFde);
    // 按 pcEnd 排序的 fde 索引,取代无表 section 每步 O(N) 的线性扫描
    // (对齐 libunwindstack DwarfSection 二分查找表设计)。
    // 为何需要索引:eh_frame 有 .eh_frame_hdr 自带的编码查找表可直接
    // 二分(SearchEntry);.debug_frame(JIT ELF、odex miniDebugInfo)
    // 没有对应表,旧路径只能从表头逐条解析比对——每帧每样本各查一次,
    // 大 section 上实测占 hiperf 后处理约 14%。
    // 为何不用已有的 fdeEntries_ 哈希:它按 fde 地址缓存"该地址的 FDE
    // 内容",而这里的查询是"pc 落在哪个 FDE 区间"——范围查询,哈希
    // 结构做不了,必须有序结构二分。索引项携带 fdeEntries_ 节点指针,
    // 二分命中后连 ParseFde 都一并跳过(其缓存查找曾是头号热点,见
    // Step 内 F6 注释)。实测本索引将该项开销 14%→≈0,连同 F6 等
    // 优化 dwarf 路径提速 4-5 倍。
    // 按 section 维护小型 LRU 索引缓存,栈回溯在多个模块间交替时不必
    // 反复重建索引。
    struct FdeIndexEntry {
        uintptr_t pcStart;
        uintptr_t pcEnd;
        uintptr_t fdeAddr;
        // 指向 fdeEntries_ 中的表项(unordered_map 节点地址稳定;被索引的
        // 表项永不删除——命中缓存的 ParseFde 直接返回,走不到失败删除路径)
        const FrameDescEntry* entry;
    };
    struct SectionIndex {
        uintptr_t tableData;
        // F19: .debug_frame 的 tableData 是文件偏移(shdr.offset),不同 DSO
        // 可能取到同值(miniDebugInfo 缓冲布局高度相似);混入底层 mmap 的
        // 身份标识,避免不同 section 的索引互相误命中。
        uintptr_t mmapId;
        std::vector<FdeIndexEntry> entries;
    };
    std::list<SectionIndex> fdeIndexCache_; // 头部为最近使用(MRU)
    // 一次性线性收集 section 内全部 FDE 区间(内联走表项,坏表项跳过),
    // 按 pcEnd 排序建二分索引并存入 fdeIndexCache_;缓存有界(32 个
    // section/共 100 万项),超出从队尾淘汰。返回索引供
    // LinearSearchEntry 二分定位覆盖 pc 的 FDE。
    const std::vector<FdeIndexEntry>* BuildFdeIndex(const UnwindTableInfo& uti);
    bool GetCieOrFde(uintptr_t& addr, FrameDescEntry& fdeInfo);
    void ParseCieOrFdeHeader(uintptr_t& ptr, FrameDescEntry& fdeInfo, bool& isCieEntry);
    bool FillInFde(uintptr_t ptr, FrameDescEntry& fdeInfo);
    bool FillInCie(uintptr_t ptr, CommonInfoEntry& cieInfo);
    void ParseAugData(uintptr_t& ptr, CommonInfoEntry& cieInfo, const std::vector<char>& augStr);
    bool isDebugFrame_ = false;
    uintptr_t entriesOffset_ = 0;
    uint32_t cie32Value_ = 0;
    uint64_t cie64Value_ = 0;
    std::unordered_map<uintptr_t, FrameDescEntry> fdeEntries_;
    std::unordered_map<uintptr_t, CommonInfoEntry> cieEntries_;
};
} // nameapace HiviewDFX
} // nameapace OHOS
#endif
