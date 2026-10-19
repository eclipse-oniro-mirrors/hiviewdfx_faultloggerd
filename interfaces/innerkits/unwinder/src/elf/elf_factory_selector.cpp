
/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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
#include "dfx_log.h"
#include "elf_factory.h"
#include "elf_factory_selector.h"
#include "string_util.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "ElfFactorySelector"
}
std::shared_ptr<ElfFactory> ElfFactorySelector::Select(DfxMap& map, pid_t pid)
{
    std::shared_ptr<ElfFactory> elfFactory = nullptr;
    if (map.name.find(SANDBOX_FILE_PATH_PREFIX) != std::string::npos && EndsWith(map.name, ".hap")) {
        uint64_t curOffset = map.offset;
        uint64_t curSize = map.end - map.begin;
        map.offset -= map.prevMap->offset;
        elfFactory = std::make_shared<CompressHapElfFactory>(map.name, map.prevMap, curOffset, curSize);
    } else if (EndsWith(map.name, ".apk")) {
        // apk 内未压缩、页对齐的 .so:r-xp 映射自身偏移即 .so 起点
        // (= elf_start_offset)。对齐 libunwindstack:elf_offset = offset -
        // elf_start_offset = 0,GetRelPc 得到的便是相对 .so 的 pc(同
        // debuggerd),而非 apk 文件偏移。
        uint64_t soStart = map.offset;
        elfFactory = std::make_shared<CompressHapElfFactory>(map.name, map.prevMap, soStart, map.end - map.begin);
        map.offset -= soStart;
    } else if (map.IsVdsoMap()) {
        elfFactory = std::make_shared<VdsoElfFactory>(map.begin, map.end - map.begin, pid);
    } else {
        elfFactory = std::make_shared<RegularElfFactory>(map.name, map.major, map.minor, map.inode);
    }
    return elfFactory;
}
} // namespace HiviewDFX
} // namespace OHOS