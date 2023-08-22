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
#ifndef DFX_MEMORY_H
#define DFX_MEMORY_H

#include <atomic>
#include <cstdint>
#include <string>
#include <unordered_map>
#include "dfx_accessors.h"
#include "unwind_context.h"

namespace OHOS {
namespace HiviewDFX {
class DfxMemory {
public:
    DfxMemory(DfxAccessors* acc, void* ctx) : acc_(acc), ctx_(ctx) {}
    virtual ~DfxMemory() = default;

    virtual int ReadReg(int reg, uintptr_t *val);
    virtual int ReadMem(uintptr_t addr, uintptr_t *val);

    virtual int Read(uintptr_t* addr, void* val, size_t size, bool incre = true);
    virtual int ReadU8(uintptr_t* addr, uint8_t *val, bool incre = true);
    virtual int ReadU16(uintptr_t* addr, uint16_t *val, bool incre = true);
    virtual int ReadU32(uintptr_t* addr, uint32_t *val, bool incre = true);
    virtual int ReadU64(uintptr_t* addr, uint64_t *val, bool incre = true);
    virtual int ReadUptr(uintptr_t* addr, uintptr_t *val, bool incre = true);
    template <typename T>
    T Read(uintptr_t* addr, bool incre = false)
    {
        T val = 0;
        Read(addr, (void *)val, sizeof(T), incre);
        return val;
    }

private:
    DfxAccessors* acc_;
    void* ctx_;
};
} // namespace HiviewDFX
} // namespace OHOS
#endif
