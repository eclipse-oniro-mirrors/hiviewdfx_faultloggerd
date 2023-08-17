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

#include "dfx_symbols.h"

#include <algorithm>
#include <cstdlib>
#include "dfx_define.h"
#include "dfx_log.h"
#include "dfx_demangle.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxSymbols"
}

bool DfxSymbols::ParseSymbols(std::vector<DfxSymbol>& symbols,
    const std::shared_ptr<DfxElf> elf, const std::string& filePath)
{
    if (elf == nullptr) {
        return false;
    }
    std::vector<ElfSymbol> elfSymbols;
    if (!elf->GetElfSymbols(elfSymbols)) {
        return false;
    }
    for (auto elfSymbol : elfSymbols) {
        if (ELF64_ST_TYPE(elfSymbol.info) == STT_FUNC ||
            ELF64_ST_TYPE(elfSymbol.info) == STT_GNU_IFUNC) {
            DfxSymbol symbol;
            symbol.SetVaddr(elfSymbol.value, elfSymbol.value, elfSymbol.size);
            std::string demangleName = DfxDemangle::Demangle(elfSymbol.nameStr);
            symbol.SetName(elfSymbol.nameStr, demangleName, filePath);
            symbols.emplace_back(symbol);
        } else {
            continue;
        }
    }
    return true;
}

bool DfxSymbols::AddSymbolsByPlt(std::vector<DfxSymbol>& symbols,
    const std::shared_ptr<DfxElf> elf, const std::string& filePath)
{
    if (elf == nullptr) {
        return false;
    }
    DfxSymbol symbol;
    ElfShdr shdr;
    elf->FindSection(shdr, PLT);
    symbol.SetVaddr(shdr.addr, shdr.addr, shdr.size);
    symbol.SetName(PLT, PLT, filePath);
    symbols.emplace_back(symbol);
    return true;
}

bool DfxSymbols::GetFuncNameAndOffset(uint64_t pc, const std::shared_ptr<DfxElf> elf,
    std::string* funcName, uint64_t* start, uint64_t* end)
{
    return true;
}
} // namespace HiviewDFX
} // namespace OHOS
