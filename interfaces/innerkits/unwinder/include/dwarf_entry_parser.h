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
    // sorted fde index (by pcEnd) to replace per-step O(N) scan, following
    // libunwindstack DwarfSection binary search table design. a small LRU of
    // per-section indexes avoids rebuilding when stack walks alternate modules.
    struct FdeIndexEntry {
        uintptr_t pcStart;
        uintptr_t pcEnd;
        uintptr_t fdeAddr;
        // points into fdeEntries_ (unordered_map node addresses are
        // stable; indexed entries are never erased because a cached
        // ParseFde always hits and cannot reach the erase-on-fail path)
        const FrameDescEntry* entry;
    };
    struct SectionIndex {
        uintptr_t tableData;
        // F19: .debug_frame sections key tableData by file offset (shdr.offset),
        // which can be identical across different DSOs (miniDebugInfo buffers
        // share similar layouts); mix in the backing mmap identity so such
        // sections cannot false-hit each other's index.
        uintptr_t mmapId;
        std::vector<FdeIndexEntry> entries;
    };
    std::list<SectionIndex> fdeIndexCache_; // MRU at front
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
