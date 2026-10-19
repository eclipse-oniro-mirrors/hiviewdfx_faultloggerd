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
    // F19:区分 tableData 只是裸文件偏移的 section(.debug_frame);
    // eh_frame 的 tableData 是地址,无需附加标识。
    const uintptr_t mmapId = uti.isDebugFrame
        ? reinterpret_cast<uintptr_t>(uti.debugFrameMmap.get()) : 0;

    pc = pc - uti.segbase;
    if (uti.isDebugFrame) {
        pc -= uti.oatExecutableOffset;
    }

    // F8(.1):小 section(按方法生成的 JIT ELF 是常态)直接扫比建索引
    // 更便宜;给成千上万一次性 section 建索引还会抖掉缓存里热的 DSO
    // 索引。tableLen 仅在已知 FDE 数的 eh_frame_hdr 路径下才是计数;
    // .debug_frame section(JIT ELF、odex miniDebugInfo)带的是 ~0UL,
    // 所以"小"的判定还须接受按字节跨度。
    constexpr uintptr_t kSmallSectionFdeCount = 64;
    constexpr uintptr_t kSmallSectionBytes = 8 * 1024;
    uintptr_t endBoundary = uti.isDebugFrame ? uti.debugFrameEnd : uti.endPc;
    // 字节跨度判定只对 .debug_frame 成立:其 tableData 与 debugFrameEnd 是
    // 同一 mmap 内的偏移;endPc 是 pc 区间值、与 tableData 无量纲关系,
    // eh_frame 路径绝不做跨度判定。
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
                // 容忍坏表项:GetCieOrFde 已把 ptr 推进到表项末尾。
                // 防御原地不动/倒退以及无限连跳。
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

    // section 索引带缓存(真 LRU,F8:命中即提到队首):栈回溯在模块间
    // 交替,FIFO 缓存在 8 个以上热 section 时会反复抖动、反复重建索引。
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
    // 按 pcEnd 排序:先二分出第一个 pcEnd > pc 的候选,再向前找覆盖
    // 区间(pcStart <= pc < pcEnd)。扫描有界,病态 section 拖不死回溯。
    auto it = std::upper_bound(index->begin(), index->end(), pc,
        [](uintptr_t value, const FdeIndexEntry& entry) { return value < entry.pcEnd; });
    size_t scanned = 0;
    for (; it != index->end() && scanned < 256; ++it, ++scanned) {
        if (pc >= it->pcStart && pc < it->pcEnd) {
            DFXLOGU("Fde entry addr by index: %{public}" PRIx64 "", (uint64_t)it->fdeAddr);
            uei.unwindInfo = (void *)(it->fdeAddr);
            *cachedFde = it->entry; // F6:为空时 Step 里退回 ParseFde
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
    constexpr size_t maxSectionEntries = 512 * 1024; // 防御伪造的 fdeCount
    constexpr size_t maxCachedSections = 32;
    constexpr size_t maxTotalEntries = 1024 * 1024;  // 限制缓存内存(约 24MB)

    std::vector<FdeIndexEntry> entries;
    uintptr_t i = 0;
    uintptr_t ptr = tableData;
    uintptr_t consecutiveSkips = 0;
    FrameDescEntry fdeInfo;
    while (i++ < fdeCount && ptr < endBoundary && entries.size() < maxSectionEntries) {
        uintptr_t fdeAddr = ptr;
        // 内联走表项(语义同 GetCieOrFde,但收集全部 fde 区间而非查单个
        // pc;坏表项跳过,不致命)
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
                // F6:ParseFde 刚把该 fde 写入缓存;unordered_map 节点地址
                // 稳定,且被索引的表项永不删除(命中缓存的 ParseFde 直接
                // 返回,走不到失败删除路径)。
                const FrameDescEntry* parsed = nullptr;
                auto cached = fdeEntries_.find(fdeAddr);
                if (cached != fdeEntries_.end()) {
                    parsed = &cached->second;
                }
                entries.push_back({fdeInfo.pcStart, fdeInfo.pcEnd, fdeAddr, parsed});
            }
        } else {
            // 容忍:推进到表项末尾,收集得以继续
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

    // F6:索引命中自带已解析表项,完全跳过 ParseFde(它的缓存查找是
    // self-time 头号热点:哈希取模+桶遍历+深拷贝,重应用负载下约占
    // 后处理 41%)。
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

    // 尾序 ret 处理:pc 落在函数 ret 指令处(FDE 区间最后 4 字节)时,
    // 尾序已把 x29(fp)、x30(lr) 恢复成调用者的值。引用 fp 的 CFA 规则
    // 此时会用恢复后的(调用者的)fp 算出错误 CFA,寄存器保存值便从错误
    // 栈地址读取。与其修正 CFA,不如在此返回 false,让 UpdateRegsState
    // 走兜底路径:
    //   - LR 兜底:x30 已持有正确返回地址(尾序的 ldp 已加载),得到
    //     正确的下一 pc。
    //   - FpStep:fp 已是调用者的 fp,后续回溯拿到正确帧链。
    // 两个兜底用的寄存器值之所以有效,恰因尾序已完成恢复。
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
            // 容忍:推进到表项末尾,线性扫描得以跳过该表项
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
            // 容忍:推进到表项末尾,线性扫描得以跳过该表项
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
    // R4(F7:放在成功缓存之后,热步进不取锁):记下确定性失败的 fde
    // (以失败时刻的 section 基址为键),重复查找即可跳过完整解析;
    // 有界防膨胀。s_failedFdes 与 fdeEntries_ 互斥:失败路径先删成功
    // 表项再记失败。
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
        // R2:部分生成器在 eh_frame 里发出 debug_frame 风格的绝对 cie
        // 指针;放弃前先按绝对约定重试一次。
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
    // 无长度前缀的旧式 augmentation:内联解析已知字符,遇未知字符即停
    // (instructions 偏移随之停在当前 ptr)。
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
                i = augStr.size(); // 停止扫描
                break;
        }
    }
    cieInfo.instructionsOff = ptr;
    return true;
}
}   // namespace HiviewDFX
}   // namespace OHOS