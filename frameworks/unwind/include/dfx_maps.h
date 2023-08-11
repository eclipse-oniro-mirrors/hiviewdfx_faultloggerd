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

#ifndef DFX_MAPS_H
#define DFX_MAPS_H

#include <mutex>
#include <string>
#include <vector>
#include "dfx_map.h"
#include "string_util.h"

namespace OHOS {
namespace HiviewDFX {
class DfxMaps {
public:
    DfxMaps() = default;
    ~DfxMaps() = default;
    static std::shared_ptr<DfxMaps> Create(pid_t pid = 0);
    static std::shared_ptr<DfxMaps> Create(const std::string path);

    void AddMap(std::shared_ptr<DfxMap> map);
    void Sort(bool less = true);
    bool FindMapByAddr(std::shared_ptr<DfxMap>& map, uintptr_t addr) const;
    bool FindMapByFileInfo(std::shared_ptr<DfxMap>& map, std::string name, uint64_t offset) const;
    bool FindMapsByName(std::vector<std::shared_ptr<DfxMap>>& maps, std::string name) const;
    const std::vector<std::shared_ptr<DfxMap>>& GetMaps() const {return maps_;}
    size_t GetMapsSize() const {return maps_.size();}
private:
    std::vector<std::shared_ptr<DfxMap>> maps_;
};
} // namespace HiviewDFX
} // namespace OHOS

#endif
