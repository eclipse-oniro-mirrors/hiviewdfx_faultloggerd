/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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
#ifndef DFX_SYMBOLS_H
#define DFX_SYMBOLS_H

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include "dfx_elf.h"
#include "dfx_symbol.h"

namespace OHOS {
namespace HiviewDFX {
class DfxSymbols final {
public:
    DfxSymbols() = default;
    ~DfxSymbols() = default;

    void Clear()
    {
        symbols_.clear();
    }

    static bool ParseSymbols(std::vector<DfxSymbol>& symbols, DfxElf* elf, const std::string& filePath);
    static bool AddSymbolsByPlt(std::vector<DfxSymbol>& symbols, DfxElf* elf, const std::string& filePath);
    static bool GetFuncNameAndOffset(uint64_t pc, DfxElf* elf, std::string* funcName, uint64_t* start, uint64_t* end);

private:
    static bool IsFunc(const ElfSymbol symbol);
private:
    std::vector<DfxSymbol> symbols_;
};
} // namespace HiviewDFX
} // namespace OHOS
#endif