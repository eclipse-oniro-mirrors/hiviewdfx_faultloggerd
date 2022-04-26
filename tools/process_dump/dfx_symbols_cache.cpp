/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

/* This files contains process dump header. */

#include "dfx_symbols_cache.h"

#include "dfx_define.h"
#include "libunwind_i-ohos.h"

#ifdef __cplusplus
extern "C" {
#endif
static std::vector<DfxSymbol> g_elfSymbols;
void SymbolCallback(uint64_t start, uint64_t end, uint64_t str)
{
    DfxSymbol symbol;
    symbol.start = start;
    symbol.end = end;
    symbol.nameOffset = str;
    g_elfSymbols.push_back(symbol);
};

bool SymbolComparator(DfxSymbol s1, DfxSymbol s2)
{
    return (s1.start < s2.start);
};
#ifdef __cplusplus
};
#endif
namespace OHOS {
namespace HiviewDFX {
DfxSymbolsCache &DfxSymbolsCache::GetInstance()
{
    static DfxSymbolsCache cache;
    return cache;
}

bool DfxSymbolsCache::GetNameAndOffsetByPc(struct unw_cursor *cursor,
    uint64_t pc, std::string& name, uint64_t& offset)
{
    if (GetNameAndOffsetByPc(pc, name, offset)) {
        return true;
    }

    unw_iterator_elf_symbols(cursor, pc, &SymbolCallback);
    if (g_elfSymbols.empty()) {
        return false;
    }

    DfxSymbol& symbol = g_elfSymbols[0];
    char buf[LOG_BUF_LEN] { 0 };
    unw_get_proc_name_by_offset(cursor, symbol.nameOffset, buf, LOG_BUF_LEN);
    if (strlen(buf) < LOG_BUF_LEN - 1) {
        symbol.funcName = std::string(buf, strlen(buf));
    }
    offset = pc - symbol.start;
    name = symbol.funcName;
    cachedSymbols_.push_back(symbol);
    g_elfSymbols.clear();
    std::sort(cachedSymbols_.begin(), cachedSymbols_.end(), SymbolComparator);
    return true;
}

bool DfxSymbolsCache::GetNameAndOffsetByPc(uint64_t pc, std::string& name, uint64_t& offset)
{
    size_t begin = 0;
    size_t end = cachedSymbols_.size();
    while (begin < end) {
        size_t mid = begin + (end - begin) / 2;
        DfxSymbol& symbol = cachedSymbols_[mid];
        if (pc < symbol.start) {
            end = mid;
        } else if (pc <= symbol.end) {
            offset = pc - symbol.start;
            name = symbol.funcName;
            return true;
        } else {
            begin = mid + 1;
        }
    }
    return false;
}
} // namespace HiviewDFX
} // namespace OHOS
