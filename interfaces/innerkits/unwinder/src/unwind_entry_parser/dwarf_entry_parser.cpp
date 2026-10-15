/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include <algorithm>
#include <atomic>
#include <mutex>
#include <unordered_map>
#include "dwarf_entry_parser.h"
#include <securec.h>
#include "dfx_log.h"
#include "dfx_trace_dlsym.h"
#include "dwarf_cfa_instructions.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxDwarfEntryParser"
}
bool DwarfEntryParser::LinearSearchEntry(uintptr_t pc, const UnwindTableInfo& uti, UnwindEntryInfo& uei,
    const FrameDescEntry** cachedFde)
{
    DFX_TRACE_SCOPED_DLSYM("DwarfEntryParserLinearSearchEntry");
    uintptr_t tableData = uti.tableData;
    *cachedFde = nullptr;
    // F19: disambiguate sections whose tableData is a bare file offset
    // (.debug_frame); eh_frame tableData is an address and needs no id.
    const uintptr_t mmapId = uti.isDebugFrame
        ? reinterpret_cast<uintptr_t>(uti.debugFrameMmap.get()) : 0;

    pc = pc - uti.segbase;
    if (uti.isDebugFrame) {
        pc -= uti.oatExecutableOffset;
    }

    // F8(.1): small sections (per-method JIT ELFs are the common case) are
    // cheaper to scan directly than to index; indexing thousands of one-shot
    // sections also thrashed the cache and evicted hot DSO indexes.
    // tableLen is an FDE count only on the known-count eh_frame_hdr path;
    // .debug_frame sections (JIT ELFs, odex miniDebugInfo) carry ~0UL, so the
    // small test must also accept the section byte span.
    constexpr uintptr_t kSmallSectionFdeCount = 64;
    constexpr uintptr_t kSmallSectionBytes = 8 * 1024;
    uintptr_t endBoundary = uti.isDebugFrame ? uti.debugFrameEnd : uti.endPc;
    // byte-span test is only sound for .debug_frame sections, where tableData
    // and debugFrameEnd are offsets in the same mmap; endPc is a pc-range
    // value unrelated to tableData, so never span-test the eh_frame path.
    bool smallSection = (uti.tableLen < kSmallSectionFdeCount);
    if (!smallSection && uti.isDebugFrame && uti.debugFrameEnd > tableData &&
        (uti.debugFrameEnd - tableData) < kSmallSectionBytes) {
        smallSection = true;
    }
    if (smallSection) {
        uintptr_t fdeCount = uti.tableLen;
        uintptr_t i = 0;
        uintptr_t ptr = tableData;
        FrameDescEntry fdeInfo;
        uintptr_t consecutiveSkips = 0;
        while (i++ < fdeCount && ptr < endBoundary) {
            uintptr_t fdeAddr = ptr;
            if (GetCieOrFde(ptr, fdeInfo)) {
                consecutiveSkips = 0;
                if (pc >= fdeInfo.pcStart && pc < fdeInfo.pcEnd) {
                    DFXLOGU("Fde entry addr: %{public}" PRIx64 "", (uint64_t)fdeAddr);
                    uei.unwindInfo = (void *)(fdeAddr);
                    uei.format = UNW_INFO_FORMAT_REMOTE_TABLE;
                    return true;
                }
            } else {
                // tolerate bad entry: GetCieOrFde advanced ptr to entry end.
                // guard against no-progress/backward move and runaway skipping.
                if (ptr <= fdeAddr) {
                    break;
                }
                if (++consecutiveSkips > 32) {
                    break;
                }
                continue;
            }
        }
        return false;
    }

    // section indexes are cached (true LRU, F8: hit promotes to front):
    // stack walks alternate modules, so a FIFO cache thrashed on >8 hot
    // sections and rebuilt indexes repeatedly.
    const std::vector<FdeIndexEntry>* index = nullptr;
    for (auto it = fdeIndexCache_.begin(); it != fdeIndexCache_.end(); ++it) {
        if (it->tableData == tableData && it->mmapId == mmapId) {
            if (it != fdeIndexCache_.begin()) {
                fdeIndexCache_.splice(fdeIndexCache_.begin(), fdeIndexCache_, it);
            }
            index = &(fdeIndexCache_.front().entries);
            break;
        }
    }
    if (index == nullptr) {
        index = BuildFdeIndex(uti);
    }
    if (index == nullptr || index->empty()) {
        return false;
    }
    // sorted by pcEnd: first candidate whose pcEnd > pc, then scan forward
    // for a covering range (pcStart <= pc < pcEnd). scan is bounded so a
    // pathological section cannot stall the unwind.
    auto it = std::upper_bound(index->begin(), index->end(), pc,
        [](uintptr_t value, const FdeIndexEntry& entry) { return value < entry.pcEnd; });
    size_t scanned = 0;
    for (; it != index->end() && scanned < 256; ++it, ++scanned) {
        if (pc >= it->pcStart && pc < it->pcEnd) {
            DFXLOGU("Fde entry addr by index: %{public}" PRIx64 "", (uint64_t)it->fdeAddr);
            uei.unwindInfo = (void *)(it->fdeAddr);
            *cachedFde = it->entry; // F6: null falls back to ParseFde in Step
            uei.format = UNW_INFO_FORMAT_REMOTE_TABLE;
            return true;
        }
    }
    return false;
}

const std::vector<DwarfEntryParser::FdeIndexEntry>* DwarfEntryParser::BuildFdeIndex(const UnwindTableInfo& uti)
{
    DFX_TRACE_SCOPED_DLSYM("DwarfEntryParserBuildFdeIndex");
    uintptr_t fdeCount = uti.tableLen;
    uintptr_t tableData = uti.tableData;
    uintptr_t endBoundary = uti.isDebugFrame ? uti.debugFrameEnd : uti.endPc;
    const uintptr_t mmapId = uti.isDebugFrame
        ? reinterpret_cast<uintptr_t>(uti.debugFrameMmap.get()) : 0;
    constexpr size_t maxSectionEntries = 512 * 1024; // guard against bogus fdeCount
    constexpr size_t maxCachedSections = 32;
    constexpr size_t maxTotalEntries = 1024 * 1024;  // bound cache memory (~24MB)

    std::vector<FdeIndexEntry> entries;
    uintptr_t i = 0;
    uintptr_t ptr = tableData;
    uintptr_t consecutiveSkips = 0;
    FrameDescEntry fdeInfo;
    while (i++ < fdeCount && ptr < endBoundary && entries.size() < maxSectionEntries) {
        uintptr_t fdeAddr = ptr;
        // inline entry walk (same semantics as GetCieOrFde, but collects fde
        // ranges instead of querying one pc; bad entries are skipped, not fatal)
        uintptr_t entryPtr = ptr;
        bool isCieEntry = false;
        ParseCieOrFdeHeader(entryPtr, fdeInfo, isCieEntry);
        uintptr_t entryEnd = isCieEntry ? fdeInfo.cie.instructionsEnd : fdeInfo.instructionsEnd;
        bool ok;
        if (isCieEntry) {
            ok = ParseCie(fdeAddr, entryPtr, fdeInfo.cie);
        } else {
            ok = ParseFde(fdeAddr, entryPtr, fdeInfo);
        }
        if (ok) {
            consecutiveSkips = 0;
            if (!isCieEntry && fdeInfo.pcEnd > fdeInfo.pcStart) {
                // F6: ParseFde just cached this fde; unordered_map nodes are
                // address-stable and indexed entries are never erased (a
                // cached ParseFde returns before the erase-on-fail path).
                const FrameDescEntry* parsed = nullptr;
                auto cached = fdeEntries_.find(fdeAddr);
                if (cached != fdeEntries_.end()) {
                    parsed = &cached->second;
                }
                entries.push_back({fdeInfo.pcStart, fdeInfo.pcEnd, fdeAddr, parsed});
            }
        } else {
            // tolerate: advance to entry end so collection can continue
            if (entryEnd <= fdeAddr) {
                break;
            }
            if (++consecutiveSkips > 32) {
                break;
            }
        }
        ptr = (ok && !isCieEntry) ? fdeInfo.instructionsEnd : ((ok && isCieEntry) ? fdeInfo.cie.instructionsEnd : entryEnd);
    }
    std::sort(entries.begin(), entries.end(),
        [](const FdeIndexEntry& a, const FdeIndexEntry& b) { return a.pcEnd < b.pcEnd; });
    fdeIndexCache_.push_front({tableData, mmapId, std::move(entries)});
    size_t total = fdeIndexCache_.front().entries.size();
    for (auto& section : fdeIndexCache_) {
        if (&section != &fdeIndexCache_.front()) {
            total += section.entries.size();
        }
    }
    while (fdeIndexCache_.size() > 1 &&
           (fdeIndexCache_.size() > maxCachedSections || total > maxTotalEntries)) {
        total -= fdeIndexCache_.back().entries.size();
        fdeIndexCache_.pop_back();
    }
    DFXLOGU("FdeIndex built: %{public}zu entries, tableData: %{public}p, cached sections: %{public}zu",
        fdeIndexCache_.front().entries.size(), (void*)tableData, fdeIndexCache_.size());
    return &fdeIndexCache_.front().entries;
}

bool DwarfEntryParser::SearchEntry(uintptr_t pc, const UnwindTableInfo& uti, UnwindEntryInfo& uei)
{
    DFX_TRACE_SCOPED_DLSYM("DwarfEntryParserSearchEntry");
    MAYBE_UNUSED auto segbase = uti.segbase;
    uintptr_t fdeCount = uti.tableLen;
    uintptr_t tableData = uti.tableData;
    DFXLOGU("SearchEntry pc: %{public}p segbase:%{public}p, tableData:%{public}p, tableLen: %{public}u",
        (void*)pc, (void*)segbase, (void*)tableData, (uint32_t)fdeCount);

    // do binary search, encode is stored in symbol file, we have no means to find?
    // hard code for 1b DwarfEncoding
    uintptr_t ptr = 0;
    uintptr_t entry = 0;
    uintptr_t low = 0;
    uintptr_t high = fdeCount;
    DwarfTableEntry dwarfTableEntry;
    while (low < high) {
        uintptr_t cur = (low + high) / 2; // 2 : binary search divided parameter
        ptr = (uintptr_t) tableData + cur * sizeof(DwarfTableEntry);
        if (!memory_->Read<int32_t>(ptr, &dwarfTableEntry.startPc, true)) {
            lastErrorData_.SetAddrAndCode(ptr, UNW_ERROR_INVALID_MEMORY);
            return false;
        }
        uintptr_t startPc = static_cast<uintptr_t>(dwarfTableEntry.startPc) + segbase;
        if (startPc == pc) {
            if (!memory_->Read<int32_t>(ptr, &dwarfTableEntry.fdeOffset, true)) {
                lastErrorData_.SetAddrAndCode(ptr, UNW_ERROR_INVALID_MEMORY);
                return false;
            }
            entry = static_cast<uintptr_t>(dwarfTableEntry.fdeOffset) + segbase;
            break;
        } else if (pc < startPc) {
            high = cur;
        } else {
            low = cur + 1;
        }
    }

    if (entry == 0) {
        if (high != 0) {
            ptr = static_cast<uintptr_t>(tableData) + (high - 1) * sizeof(DwarfTableEntry) + 4; // 4 : four bytes
            if (!memory_->Read<int32_t>(ptr, &dwarfTableEntry.fdeOffset, true)) {
                lastErrorData_.SetAddrAndCode(ptr, UNW_ERROR_INVALID_MEMORY);
                return false;
            }
            entry = static_cast<uintptr_t>(dwarfTableEntry.fdeOffset) + segbase;
        } else {
            return false;
        }
    }

    DFXLOGU("Fde entry addr: %{public}" PRIx64 "", (uint64_t)entry);
    uei.unwindInfo = (void *)(entry);
    uei.format = UNW_INFO_FORMAT_REMOTE_TABLE;
    return true;
}

bool DwarfEntryParser::Step(uintptr_t pc, const UnwindTableInfo& uti, std::shared_ptr<RegLocState> rs)
{
    DFX_TRACE_SCOPED_DLSYM("DwarfEntryParserStep");
    if (memory_ == nullptr || rs == nullptr) {
        DFXLOGE("memory or rs is nullptr!");
        return false;
    }
    SetDebugFrameMode(uti.isDebugFrame, uti.tableData);

    std::shared_ptr<DfxMemory> originalMemory = memory_;
    if (uti.isDebugFrame && uti.debugFrameMmap != nullptr) {
        memory_ = uti.debugFrameMmap;
    }

    struct UnwindEntryInfo uei;
    const FrameDescEntry* cachedFde = nullptr;
    if ((!uti.isLinear && !SearchEntry(pc, uti, uei)) ||
        (uti.isLinear && !LinearSearchEntry(pc, uti, uei, &cachedFde))) {
        DFXLOGU("Failed to search unwind entry");
        memory_ = originalMemory;
        return false;
    }
    memory_->SetDataOffset(uti.segbase);

    // F6: index hit carries the parsed entry; skip ParseFde entirely (its
    // cache find was the top self-time hotspot: hash mod + bucket walk +
    // deep copy, ~41% of post-pass under heavy app load).
    FrameDescEntry localFdeInfo;
    const FrameDescEntry* fdePtr = cachedFde;
    if (fdePtr == nullptr) {
        if (!ParseFde((uintptr_t)uei.unwindInfo, (uintptr_t)uei.unwindInfo, localFdeInfo)) {
            DFXLOGE("Failed to parse fde? addr: 0x%{public}" PRIx64 ", isLinear: %{public}d, isDebugFrame: %{public}d",
                (uint64_t)(uintptr_t)uei.unwindInfo, (int)uti.isLinear, (int)uti.isDebugFrame);
            lastErrorData_.SetAddrAndCode((uintptr_t)uei.unwindInfo, UNW_ERROR_DWARF_INVALID_FDE);
            memory_ = originalMemory;
            return false;
        }
        fdePtr = &localFdeInfo;
    }
    const FrameDescEntry& fdeInfo = *fdePtr;

    uintptr_t checkPc = pc;
    if (uti.isDebugFrame) {
        checkPc = pc - uti.segbase - uti.oatExecutableOffset;
    }

    if (checkPc < fdeInfo.pcStart || checkPc >= fdeInfo.pcEnd) {
        DFXLOGU("pc: %{public}p, checkPc: %{public}p, FDE start: %{public}p, end: %{public}p",
            (void*)pc, (void*)checkPc, (void*)fdeInfo.pcStart, (void*)fdeInfo.pcEnd);
        memory_ = originalMemory;
        return false;
    }

    // Epilogue ret handling: when the pc is at the function's ret
    // instruction (last 4 bytes of the FDE range), the epilogue has
    // already restored x29(fp) and x30(lr) to the caller's values.
    // CFA rules that reference fp now compute a wrong CFA from the
    // restored (caller's) fp, causing register saves to be read from
    // wrong stack addresses. Instead of trying to correct the CFA,
    // return false here so UpdateRegsState takes the fallback path:
    //   - LR fallback: x30 already holds the correct return address
    //     (loaded by the epilogue's ldp), giving the right next pc.
    //   - FpStep: fp already holds the caller's fp, giving the correct
    //     frame chain for subsequent unwinding.
    // Both fallbacks use register values that are valid precisely
    // because the epilogue has completed its restores.
    if (checkPc + 4 >= fdeInfo.pcEnd) {
        DFXLOGU("Epilogue ret: deferring to LR/FP fallback, pc: 0x%{public}" PRIx64, (uint64_t)pc);
        memory_ = originalMemory;
        return false;
    }
    DwarfCfaInstructions dwarfInstructions(memory_);
    if (!dwarfInstructions.Parse(checkPc, fdeInfo, *(rs.get()))) {
        DFXLOGE("Failed to parse dwarf instructions?");
        lastErrorData_.SetAddrAndCode(checkPc, UNW_ERROR_DWARF_INVALID_INSTR);
        memory_ = originalMemory;
        return false;
    }

    memory_ = originalMemory;
    return true;
}

bool DwarfEntryParser::GetCieOrFde(uintptr_t& addr, FrameDescEntry& fdeInfo)
{
    uintptr_t ptr = addr;
    bool isCieEntry = false;
    ParseCieOrFdeHeader(ptr, fdeInfo, isCieEntry);
    uintptr_t entryEnd = isCieEntry ? fdeInfo.cie.instructionsEnd : fdeInfo.instructionsEnd;

    if (isCieEntry) {
        if (!ParseCie(addr, ptr, fdeInfo.cie)) {
            DFXLOGE("Failed to Parse CIE?");
            // tolerate: advance to entry end so linear scan can skip this entry
            addr = entryEnd;
            return false;
        }
        addr = fdeInfo.cie.instructionsEnd;
    } else {
        if (!ParseFde(addr, ptr, fdeInfo)) {
            static std::atomic<uint64_t> failCnt {0};
            if ((failCnt.fetch_add(1) % 100) == 0) {
                DFXLOGE("Failed to Parse FDE? addr: 0x%{public}" PRIx64 ", total: %{public}" PRIx64 "",
                    (uint64_t)addr, failCnt.load());
            }
            // tolerate: advance to entry end so linear scan can skip this entry
            addr = entryEnd;
            return false;
        }
        addr = fdeInfo.instructionsEnd;
    }
    return true;
}

void DwarfEntryParser::ParseCieOrFdeHeader(uintptr_t& ptr, FrameDescEntry& fdeInfo, bool& isCieEntry)
{
    uint32_t value32 = 0;
    memory_->Read<uint32_t>(ptr, &value32, true);
    uintptr_t ciePtr = 0;
    uintptr_t instructionsEnd = 0;
    if (value32 == static_cast<uint32_t>(-1)) {
        uint64_t value64;
        memory_->Read<uint64_t>(ptr, &value64, true);
        instructionsEnd = ptr + value64;

        memory_->Read<uint64_t>(ptr, &value64, true);
        ciePtr = static_cast<uintptr_t>(value64);
        if (ciePtr == cie64Value_) {
            isCieEntry = true;
            fdeInfo.cie.instructionsEnd = instructionsEnd;
            fdeInfo.cie.pointerEncoding = isDebugFrame_
                ? DW_EH_PE_absptr
                : DW_EH_PE_sdata8;
        } else {
            fdeInfo.instructionsEnd = instructionsEnd;
            fdeInfo.ciePtrValue = ciePtr;
            fdeInfo.cieAddr = isDebugFrame_ ? (entriesOffset_ + ciePtr) : static_cast<uintptr_t>(ptr - ciePtr);
        }
        ptr += sizeof(uint64_t);
    } else {
        instructionsEnd = ptr + value32;
        memory_->Read<uint32_t>(ptr, &value32, false);
        ciePtr = static_cast<uintptr_t>(value32);
        if (ciePtr == cie32Value_) {
            isCieEntry = true;
            fdeInfo.cie.instructionsEnd = instructionsEnd;
            fdeInfo.cie.pointerEncoding = isDebugFrame_
                ? DW_EH_PE_absptr
                : DW_EH_PE_sdata4;
        } else {
            fdeInfo.instructionsEnd = instructionsEnd;
            fdeInfo.ciePtrValue = ciePtr;
            fdeInfo.cieAddr = isDebugFrame_ ? (entriesOffset_ + ciePtr) : static_cast<uintptr_t>(ptr - ciePtr);
        }
        ptr += sizeof(uint32_t);
    }
}

bool DwarfEntryParser::ParseFde(uintptr_t fdeAddr, uintptr_t fdePtr, FrameDescEntry& fdeInfo)
{
    if (!fdeEntries_.empty()) {
        auto iter = fdeEntries_.find(fdeAddr);
        if (iter != fdeEntries_.end()) {
            fdeInfo = iter->second;
            return true;
        }
    }
    // R4 (F7: checked after the success cache so hot steps take no lock):
    // remember conclusively failed fdes (keyed with section base at failure
    // time) so repeated lookups skip the full parse; bounded to avoid growth.
    // s_failedFdes and fdeEntries_ are disjoint: the fail path erases the
    // success entry before recording the failure.
    static std::mutex s_failMutex;
    static std::unordered_map<uintptr_t, uintptr_t> s_failedFdes;
    {
        std::lock_guard<std::mutex> lock(s_failMutex);
        auto it = s_failedFdes.find(fdeAddr);
        if (it != s_failedFdes.end() && it->second == entriesOffset_) {
            return false;
        }
    }

    if (fdeAddr == fdePtr) {
        bool isCieEntry = false;
        ParseCieOrFdeHeader(fdePtr, fdeInfo, isCieEntry);
        if (isCieEntry) {
            DFXLOGE("ParseFde error, is Cie Entry?");
            return false;
        }
    }
    if (!FillInFde(fdePtr, fdeInfo)) {
        static std::atomic<uint64_t> failCnt {0};
        if ((failCnt.fetch_add(1) % 100) == 0) {
            DFXLOGE("ParseFde error, failed to fill FDE? fdeAddr: 0x%{public}" PRIx64 ", total: %{public}" PRIx64 "",
                (uint64_t)fdeAddr, failCnt.load());
        }
        {
            std::lock_guard<std::mutex> lock(s_failMutex);
            if (s_failedFdes.size() < 8192) {
                s_failedFdes[fdeAddr] = entriesOffset_;
            }
        }
        fdeEntries_.erase(fdeAddr);
        return false;
    }
    fdeEntries_[fdeAddr] = fdeInfo;
    return true;
}

bool DwarfEntryParser::FillInFde(uintptr_t ptr, FrameDescEntry& fdeInfo)
{
    if (!ParseCie(fdeInfo.cieAddr, fdeInfo.cieAddr, fdeInfo.cie)) {
        // R2: some producers emit debug_frame style absolute cie pointer inside
        // an eh_frame section; retry with absolute convention before giving up.
        uintptr_t altCieAddr = entriesOffset_ + fdeInfo.ciePtrValue;
        if (!isDebugFrame_ && altCieAddr != fdeInfo.cieAddr &&
            altCieAddr >= entriesOffset_ && altCieAddr < ptr &&
            ParseCie(altCieAddr, altCieAddr, fdeInfo.cie)) {
            static std::atomic<uint64_t> altCnt {0};
            if ((altCnt.fetch_add(1) % 100) == 0) {
                DFXLOGI("cie addr fixed by absolute convention: 0x%{public}" PRIx64
                    ", total: %{public}" PRIx64 "", (uint64_t)altCieAddr, altCnt.load());
            }
            fdeInfo.cieAddr = altCieAddr;
        } else {
            static std::atomic<uint64_t> failCnt {0};
            if ((failCnt.fetch_add(1) % 100) == 0) {
                DFXLOGE("Failed to parse CIE? cieAddr: 0x%{public}" PRIx64 ", total: %{public}" PRIx64 "",
                    (uint64_t)fdeInfo.cieAddr, failCnt.load());
            }
            return false;
        }
    }

    if (fdeInfo.cie.segmentSize != 0) {
        // Skip over the segment selector for now.
        ptr += fdeInfo.cie.segmentSize;
    }
    // Parse pc begin and range.
    DFXLOGU("pointerEncoding: %{public}02x", fdeInfo.cie.pointerEncoding);
    uintptr_t pcStart = memory_->ReadEncodedValue(ptr, fdeInfo.cie.pointerEncoding);
    uintptr_t pcRange = memory_->ReadEncodedValue(ptr, (fdeInfo.cie.pointerEncoding & 0x0F));

    fdeInfo.lsda = 0;
    // Check for augmentation length.
    if (fdeInfo.cie.hasAugmentationData) {
        uintptr_t augLen = static_cast<uintptr_t>(memory_->ReadUleb128(ptr));
        uintptr_t instructionsPtr;
        if (__builtin_add_overflow(ptr, augLen, &instructionsPtr) ||
            (fdeInfo.instructionsEnd != 0 && instructionsPtr > fdeInfo.instructionsEnd)) {
            DFXLOGE("Invalid augmentation length in fde.");
            lastErrorData_.SetAddrAndCode(ptr, UNW_ERROR_INVALID_MEMORY);
            return false;
        }
        if (fdeInfo.cie.lsdaEncoding != DW_EH_PE_omit) {
            uintptr_t lsdaPtr = ptr;
            if (memory_->ReadEncodedValue(ptr, (fdeInfo.cie.lsdaEncoding & 0x0F)) != 0) {
                fdeInfo.lsda = memory_->ReadEncodedValue(lsdaPtr, fdeInfo.cie.lsdaEncoding);
            }
        }
        ptr = instructionsPtr;
    }

    fdeInfo.instructionsOff = ptr;
    fdeInfo.pcStart = pcStart;
    fdeInfo.pcEnd = pcStart + pcRange;
    DFXLOGU("FDE pcStart: %{public}p, pcEnd: %{public}p", (void*)(fdeInfo.pcStart), (void*)(fdeInfo.pcEnd));
    return true;
}

bool DwarfEntryParser::ParseCie(uintptr_t cieAddr, uintptr_t ciePtr, CommonInfoEntry& cieInfo)
{
    DFXLOGU("cieAddr: %{public}" PRIx64 "", (uint64_t)cieAddr);
    if (!cieEntries_.empty()) {
        auto iter = cieEntries_.find(cieAddr);
        if (iter != cieEntries_.end()) {
            cieInfo = iter->second;
            return true;
        }
    }
    if (cieAddr == ciePtr) {
        cieInfo.lsdaEncoding = DW_EH_PE_omit;
        bool isCieEntry = false;
        FrameDescEntry fdeInfo;
        ParseCieOrFdeHeader(ciePtr, fdeInfo, isCieEntry);
        if (!isCieEntry) {
            static std::atomic<uint64_t> failCnt {0};
            if ((failCnt.fetch_add(1) % 100) == 0) {
                DFXLOGE("ParseCie error, is not Cie Entry? cieAddr: 0x%{public}" PRIx64 ", total: %{public}" PRIx64 "",
                    (uint64_t)cieAddr, failCnt.load());
            }
            return false;
        }
        cieInfo = fdeInfo.cie;
    }
    if (!FillInCie(ciePtr, cieInfo)) {
        DFXLOGE("ParseCie error, failed to fill Cie?");
        cieEntries_.erase(cieAddr);
        return false;
    }
    cieEntries_[cieAddr] = cieInfo;
    return true;
}

void DwarfEntryParser::ParseAugData(uintptr_t& ptr, CommonInfoEntry& cieInfo, const std::vector<char>& augStr)
{
    MAYBE_UNUSED uintptr_t augSize = memory_->ReadUleb128(ptr);
    DFXLOGU("augSize: %{public}" PRIxPTR "", augSize);
    cieInfo.instructionsOff = ptr + augSize;

    for (size_t i = 1; i < augStr.size(); ++i) {
        switch (augStr[i]) {
            case 'P':
                uint8_t personalityEncoding;
                memory_->Read<uint8_t>(ptr, &personalityEncoding, true);
                cieInfo.personality = memory_->ReadEncodedValue(ptr, personalityEncoding);
                break;
            case 'L':
                memory_->Read<uint8_t>(ptr, &cieInfo.lsdaEncoding, true);
                DFXLOGU("cieInfo.lsdaEncoding: %{public}x", cieInfo.lsdaEncoding);
                break;
            case 'R':
                memory_->Read<uint8_t>(ptr, &cieInfo.pointerEncoding, true);
                DFXLOGU("cieInfo.pointerEncoding: %{public}x", cieInfo.pointerEncoding);
                break;
            case 'S':
                cieInfo.isSignalFrame = true;
                break;
            default:
                break;
        }
    }
}

bool DwarfEntryParser::FillInCie(uintptr_t ptr, CommonInfoEntry& cieInfo)
{
    uint8_t version;
    memory_->Read<uint8_t>(ptr, &version, true);
    DFXLOGU("Cie version: %{public}d", version);
    if (version != DW_EH_VERSION && version != 3 && version != 4 && version != 5) { // 3 4 5 : cie version
        DFXLOGE("Invalid cie version: %{public}d", version);
        lastErrorData_.SetAddrAndCode(ptr, UNW_ERROR_UNSUPPORTED_VERSION);
        return false;
    }

    // save augmentation string
    std::vector<char> augStr;
    augStr.clear();
    uint8_t ch;
    constexpr size_t maxAugStrLen = 64;
    size_t augStrLen = 0;
    while (augStrLen < maxAugStrLen && cieInfo.instructionsEnd != 0 && ptr < cieInfo.instructionsEnd &&
           memory_->Read<uint8_t>(ptr, &ch, true) && ch != '\0') {
        augStr.push_back(ch);
        augStrLen++;
    }

    // Segment Size
    if (version == 4 || version == 5) { // 4 5 : cie version
        // Skip the Address Size field since we only use it for validation.
        ptr += 1;
        memory_->Read<uint8_t>(ptr, &cieInfo.segmentSize, true);
    } else {
        cieInfo.segmentSize = 0;
    }

    // parse code alignment factor
    cieInfo.codeAlignFactor = static_cast<uint32_t>(memory_->ReadUleb128(ptr));
    DFXLOGU("codeAlignFactor: %{public}d", cieInfo.codeAlignFactor);

    // parse data alignment factor
    cieInfo.dataAlignFactor = static_cast<int32_t>(memory_->ReadSleb128(ptr));
    DFXLOGU("dataAlignFactor: %{public}d", cieInfo.dataAlignFactor);

    // parse return address register
    if (version == DW_EH_VERSION) {
        uint8_t val;
        memory_->Read<uint8_t>(ptr, &val, true);
        cieInfo.returnAddressRegister = static_cast<uintptr_t>(val);
    } else {
        cieInfo.returnAddressRegister = static_cast<uintptr_t>(memory_->ReadUleb128(ptr));
    }
    DFXLOGU("returnAddressRegister: %{public}d", static_cast<int>(cieInfo.returnAddressRegister));

    // parse augmentation data based on augmentation string
    if (augStr.empty()) {
        cieInfo.instructionsOff = ptr;
        return true;
    }
    if (augStr[0] == 'z') {
        cieInfo.hasAugmentationData = true;
        ParseAugData(ptr, cieInfo, augStr);
        return true;
    }
    // legacy augmentation without length prefix: parse known chars inline,
    // stop at unknown char (instructions offset then stays at current ptr).
    for (size_t i = 0; i < augStr.size(); ++i) {
        switch (augStr[i]) {
            case 'P': {
                uint8_t personalityEncoding = 0;
                memory_->Read<uint8_t>(ptr, &personalityEncoding, true);
                cieInfo.personality = memory_->ReadEncodedValue(ptr, personalityEncoding);
                break;
            }
            case 'L':
                memory_->Read<uint8_t>(ptr, &cieInfo.lsdaEncoding, true);
                break;
            case 'R':
                memory_->Read<uint8_t>(ptr, &cieInfo.pointerEncoding, true);
                break;
            case 'S':
                cieInfo.isSignalFrame = true;
                break;
            default:
                i = augStr.size(); // stop scanning
                break;
        }
    }
    cieInfo.instructionsOff = ptr;
    return true;
}
}   // namespace HiviewDFX
}   // namespace OHOS