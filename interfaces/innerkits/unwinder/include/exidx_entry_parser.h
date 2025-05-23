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

#ifndef EXIDX_ENTRY_PARSER_H
#define EXIDX_ENTRY_PARSER_H

#include <deque>
#include <memory>
#include <vector>

#include "dfx_errors.h"
#include "dfx_memory.h"
#include "unwind_context.h"
#include "unwind_entry_parser.h"

namespace OHOS {
namespace HiviewDFX {
struct ExidxContext {
public:
    int32_t vsp = 0;
    uint32_t transformedBits = 0;
    std::vector<int32_t> regs;

    void Reset(size_t size = 0);
    void Transform(uint32_t reg);
    bool IsTransformed(uint32_t reg);
    void AddUpVsp(int32_t imm);
};

class ExidxEntryParser : public UnwindEntryParser {
public:
    explicit ExidxEntryParser(const std::shared_ptr<DfxMemory>& memory) : UnwindEntryParser(memory)
    {
        context_.Reset(DfxRegsQut::GetQutRegsSize());
    }
    ~ExidxEntryParser() override = default;

    bool Step(uintptr_t pc, const UnwindTableInfo& uti, std::shared_ptr<RegLocState> rs) override;
private:
    struct DecodeTable {
        uint8_t mask;
        uint8_t result;
        bool (ExidxEntryParser::*decoder)();
    };
    bool SearchEntry(uintptr_t pc, const UnwindTableInfo &uti, struct UnwindEntryInfo& uei) override;
    bool Eval(uintptr_t entryOffset);
    void FlushInstr();

    void LogRawData();
    bool ExtractEntryData(uintptr_t entryOffset);
    bool ExtractEntryTab(uintptr_t tabOffset);
    bool ExtractEntryTabByPersonality(uintptr_t& tabOffset, uint32_t& data, uint8_t& tableCount);
    bool GetOpCode();
    bool Decode(DecodeTable decodeTable[], size_t size);
    bool Decode00xxxxxx();
    bool Decode01xxxxxx();
    bool Decode1000iiiiiiiiiiii();
    bool Decode1001nnnn();
    bool Decode1010nnnn();
    bool Decode10110000();
    bool Decode101100010000iiii();
    bool Decode10110010uleb128();
    bool Decode10110011sssscccc();
    bool Decode101101nn();
    bool Decode10111nnn();
    bool Decode11000110sssscccc();
    bool Decode110001110000iiii();
    bool Decode1100100nsssscccc();
    bool Decode11001yyy();
    bool Decode11000nnn();
    bool Decode11010nnn();
    bool Decode11xxxyyy();
    bool DecodeSpare();
    std::shared_ptr<RegLocState> rsState_;
    ExidxContext context_;
    std::deque<uint8_t> ops_;
    uint8_t curOp_ = 0;
    bool isPcSet_ = false;
};
} // namespace HiviewDFX
} // namespace OHOS
#endif
