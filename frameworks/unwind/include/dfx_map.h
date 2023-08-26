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

#ifndef DFX_MAP_H
#define DFX_MAP_H

#include <atomic>
#include <memory>
#include <mutex>
#include <string>
#include <sys/stat.h>

namespace OHOS {
namespace HiviewDFX {
namespace {
const int PROT_DEVICE_MAP = 0x8000;
}
class DfxElf;

class DfxMap {
public:
    static std::shared_ptr<DfxMap> Create(const std::string buf, int size);
    static void PermsToProts(const std::string perms, uint64_t& prots);

    DfxMap() = default;
    DfxMap(DfxMap* prevMap, uint64_t begin, uint64_t end, uint64_t offset,
        const std::string& perms, const std::string& name)
        : prevMap(prevMap), begin(begin), end(end), offset(offset), perms(perms), name(name) {}

    bool Parse(const std::string buf, int size);
    bool IsValidName();
    bool IsArkName();
    const std::shared_ptr<DfxElf>& GetElf();
    uint64_t GetRelPc(uint64_t pc);
    std::string ToString();

    DfxMap* prevMap;
    uint64_t begin = 0;
    uint64_t end = 0;
    uint64_t offset = 0;
    uint64_t prots = 0;
    uint64_t major = 0;
    uint64_t minor = 0;
    ino_t inode = 0;
    std::string perms = ""; // 5:rwxp
    std::string name = "";
    std::shared_ptr<DfxElf> elf;
    uint64_t elfOffset = 0;
    uint64_t elfStartOffset = 0;

    bool Contain(uint64_t pc) const
    {
        return (pc >= begin && pc < end);
    }

    // The range [first, last) must be partitioned with respect to the expression
    // !(value < element) or !comp(value, element)
    static bool ValueLessThen(uint64_t vaddr, const DfxMap &a)
    {
        return vaddr < a.begin;
    }
    static bool ValueLessEqual(uint64_t vaddr, const DfxMap &a)
    {
        return vaddr <= a.begin;
    }
};
} // namespace HiviewDFX
} // namespace OHOS

#endif