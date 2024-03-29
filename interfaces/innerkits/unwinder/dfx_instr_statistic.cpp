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

#include "dfx_instr_statistic.h"
#include "dfx_define.h"
#include "dfx_log.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxInstrStatistic"
}

DfxInstrStatistic &DfxInstrStatistic::GetInstance()
{
    static DfxInstrStatistic instance;
    return instance;
}

void DfxInstrStatistic::SetCurrentStatLib(const std::string soName)
{
    soName_ = soName;
    statisticInfo_.clear();
}

void DfxInstrStatistic::AddInstrStatistic(InstrStatisticType type, uint64_t val, uint64_t err)
{
    if (err != 0) {
        LOGE("type: %u, val: %" PRIx64 ", err: %" PRIx64 "", type, val, err);
    } else {
        LOGU("type: %u, val: %" PRIx64 "", type, val);
    }
    std::shared_ptr<std::vector<std::pair<uint64_t, uint64_t>>> stats;
    auto iter = statisticInfo_.find(static_cast<uint32_t>(type));
    if (iter != statisticInfo_.end()) {
        stats = iter->second;
    } else {
        stats = std::make_shared<std::vector<std::pair<uint64_t, uint64_t>>>();
        statisticInfo_[type] = stats;
    }
    if (stats != nullptr) {
        stats->push_back(std::make_pair(val, err));
    }
}

void DfxInstrStatistic::DumpInstrStatResult(std::vector<std::pair<uint32_t, uint32_t>> &result)
{
    auto iter = statisticInfo_.begin();
    LOGU("++++++Dump Instr Statistic for elf file: %s", soName_.c_str());
    while (iter != statisticInfo_.end()) {
        InstrStatisticType type = static_cast<InstrStatisticType>(iter->first);
        std::shared_ptr<std::vector<std::pair<uint64_t, uint64_t>>> stats = iter->second;
        if (stats == nullptr) {
            iter++;
            continue;
        }
        switch (type) {
            case InstructionEntriesArmExidx:
            case InstructionEntriesEhFrame:
            case InstructionEntriesDebugFrame:
                LOGU("\t Type: %u, Count: %" PRIu64 "", type, (uint64_t) stats->size());
                for (size_t i = 0; i < stats->size(); ++i) {
                    LOGU("\t Value: %" PRIx64 "", (uint64_t) stats->at(i).first);
                    result.push_back(std::make_pair(type, static_cast<uint32_t>(stats->at(i).first)));
                }
                break;
            default:
                LOGU("\t Type: %u, Count: %" PRIu64 "", type, (uint64_t) stats->size());
                result.push_back(std::make_pair(type, static_cast<uint32_t>(stats->size())));
                break;
        }
        iter++;
    }
    LOGU("%s", "------Dump Instr Statistic End.");
}
} // namespace HiviewDFX
} // namespace OHOS
