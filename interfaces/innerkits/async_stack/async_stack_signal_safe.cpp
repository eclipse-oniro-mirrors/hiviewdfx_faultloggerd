/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "async_stack_signal_safe.h"
 
#include <cstdint>
 
#include "async_stack.h"
#include "unique_stack_table.h"
 
namespace OHOS {
namespace HiviewDFX {
namespace {
constexpr size_t ASYNC_MAX_CONTENT = 16;
constexpr size_t LINK_LAYER_MARKER = 0XFFFFFFFF;
} // namespace
 
bool GetPcsByStackIdSignalSafe(uint64_t stackId, void** buffer, size_t bufferSize)
{
    if (buffer == nullptr || bufferSize == 0) {
        return false;
    }
    StackId id;
    id.value = stackId;
    return UniqueStackTable::Instance()->GetPcsByStackIdSignalSafe(id, buffer, bufferSize);
}
 
size_t StitchAsyncStacksSignalSafe(void** frames, size_t capacity, size_t numFrames)
{
    if (frames == nullptr) {
        return 0;
    }
    uint64_t asyncStackId = DfxGetSubmitterStackId();
    if (asyncStackId != 0) {
        void* asyncPcArray[ASYNC_MAX_CONTENT] = {nullptr};
        uint32_t asyncCount = 0;
        if (GetPcsByStackIdSignalSafe(asyncStackId, asyncPcArray, ASYNC_MAX_CONTENT * sizeof(void*))) {
            while (asyncCount < ASYNC_MAX_CONTENT && asyncPcArray[asyncCount] != nullptr) {
                asyncCount++;
            }
        }
        if (asyncCount > 0 && numFrames < capacity) {
            frames[numFrames] = reinterpret_cast<void*>(LINK_LAYER_MARKER);
            ++numFrames;
            for (size_t i = 0; i < asyncCount && numFrames < capacity; ++i) {
                frames[numFrames] = asyncPcArray[i];
                ++numFrames;
            }
        }
    }
    return numFrames;
}
 
bool UniqueStackTable::GetPcsByStackIdSignalSafe(StackId stackId, void** buffer, size_t bufferSize)
{
    if (buffer == nullptr || stackId.section.nr > bufferSize / sizeof(void*)) {
        return false;
    }
    if (__atomic_load_n(&profilerInit_, __ATOMIC_ACQUIRE)) {
        return false;
    }
    void* tableBuf = __atomic_load_n(&stackTable_.tableBufMMap, __ATOMIC_ACQUIRE);
    if (tableBuf == nullptr) {
        return false;
    }
    uint32_t totalNodes = __atomic_load_n(&stackTable_.totalNodes, __ATOMIC_ACQUIRE);
    uint64_t nr = stackId.section.nr;
    uint64_t nodeIndex = stackId.section.id;
    if (nodeIndex >= totalNodes) {
        return false;
    }
    Node* tableHead = reinterpret_cast<Node*>(tableBuf);
    Node* node = &tableHead[nodeIndex];
    size_t bufferIndex = 0;
    while (nr-- && node != nullptr) {
        uint64_t nodeValue = __atomic_load_n(&node->value, __ATOMIC_ACQUIRE);
        buffer[bufferIndex++] = reinterpret_cast<void*>(nodeValue & ((1ULL << ADDR_BIT_LENGTH) - 1));
        uint64_t prevIdx = (nodeValue >> ADDR_BIT_LENGTH) & ((1ULL << IDX_BIT_LENGTH) - 1);
        if (prevIdx == HEAD_NODE_INDEX) {
            break;
        }
        if (prevIdx >= totalNodes) {
            return false;
        }
        node = &tableHead[prevIdx];
    }
    return true;
}
} // namespace HiviewDFX
} // namespace OHOS
 
extern "C" bool DfxGetPcsByStackId(uint64_t stackId, void** buffer, size_t bufferSize)
{
    return OHOS::HiviewDFX::GetPcsByStackIdSignalSafe(stackId, buffer, bufferSize);
}
 
extern "C" size_t StitchXsansAsyncStacks(void** frames, size_t capacity, size_t numFrames)
{
    return OHOS::HiviewDFX::StitchAsyncStacksSignalSafe(frames, capacity, numFrames);
}