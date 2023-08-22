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

#include "dfx_memory.h"
#include <algorithm>
#include <securec.h>
#include "dfx_define.h"
#include "dfx_log.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxMemory"
}

int DfxMemory::ReadReg(int reg, uintptr_t *val)
{
    return acc_->AccessReg(reg, val, 0, ctx_);
}

int DfxMemory::ReadMem(uintptr_t addr, uintptr_t *val)
{
    return acc_->AccessMem(addr, val, 0, ctx_);
}

int DfxMemory::Read(uintptr_t* addr, void* val, size_t size, bool incre)
{
    uintptr_t tmpAddr = *addr;
    LOGU("addr: %llx", static_cast<uint64_t>(tmpAddr));
    uint64_t maxSize;
    if (__builtin_add_overflow(tmpAddr, size, &maxSize)) {
        return 0;
    }

    size_t bytesRead = 0;
    uintptr_t tmpVal;
    size_t alignBytes = tmpAddr & (sizeof(uintptr_t) - 1);
    if (alignBytes != 0) {
        uintptr_t alignedAddr = tmpAddr & (~sizeof(uintptr_t) - 1);
        LOGU("alignBytes: %d, alignedAddr: %llx", alignBytes, static_cast<uint64_t>(alignedAddr));
        if (ReadMem(alignedAddr, &tmpVal) != UNW_ERROR_NONE) {
            return bytesRead;
        }
        LOGU("tmpVal: %llx", static_cast<uint64_t>(tmpVal));
        size_t copyBytes = std::min(sizeof(uintptr_t) - alignBytes, size);
        LOGU("copyBytes: %d", copyBytes);
        memcpy_s(val, copyBytes, reinterpret_cast<uint8_t*>(&tmpVal) + alignBytes, copyBytes);
        tmpAddr += copyBytes;
        val = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(val) + copyBytes);
        size -= copyBytes;
        bytesRead += copyBytes;
    }

    for (size_t i = 0; i < size / sizeof(uintptr_t); i++) {
        if (ReadMem(tmpAddr, &tmpVal) != UNW_ERROR_NONE) {
            return bytesRead;
        }
        LOGU("tmpVal: %llx", static_cast<uint64_t>(tmpVal));
        memcpy_s(val, sizeof(uintptr_t), &tmpVal, sizeof(uintptr_t));
        val = reinterpret_cast<void*>(reinterpret_cast<uintptr_t>(val) + sizeof(uintptr_t));
        tmpAddr += sizeof(uintptr_t);
        bytesRead += sizeof(uintptr_t);
    }

    size_t leftOver = size & (sizeof(uintptr_t) - 1);
    LOGU("leftOver: %d", leftOver);
    if (leftOver) {
        if (ReadMem(tmpAddr, &tmpVal) != UNW_ERROR_NONE) {
            return bytesRead;
        }
        LOGU("tmpVal: %llx", static_cast<uint64_t>(tmpVal));
        memcpy_s(val, leftOver, &tmpVal, leftOver);
        tmpAddr += leftOver;
        bytesRead += leftOver;
    }

    if (incre) {
        *addr = tmpAddr;
    }
    return bytesRead;
}

int DfxMemory::ReadU8(uintptr_t* addr, uint8_t *val, bool incre)
{
    return Read(addr, val, sizeof(uint8_t), incre);
}

int DfxMemory::ReadU16(uintptr_t* addr, uint16_t *val, bool incre)
{
    return Read(addr, val, sizeof(uint16_t), incre);
}

int DfxMemory::ReadU32(uintptr_t* addr, uint32_t *val, bool incre)
{
    return Read(addr, val, sizeof(uint32_t), incre);
}

int DfxMemory::ReadU64(uintptr_t* addr, uint64_t *val, bool incre)
{
    return Read(addr, val, sizeof(uint64_t), incre);
}

int DfxMemory::ReadUptr(uintptr_t* addr, uintptr_t *val, bool incre)
{
    return Read(addr, val, sizeof(uintptr_t), incre);
}
} // namespace HiviewDFX
} // namespace OHOS
