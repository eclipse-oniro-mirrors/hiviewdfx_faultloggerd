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
#ifndef DFX_ASYNC_STACK_SIGNAL_SAFE_H
#define DFX_ASYNC_STACK_SIGNAL_SAFE_H
 
#include <cstddef>
#include <cstdint>
 
#ifdef __cplusplus
extern "C" {
#endif
 
/**
 * @brief get pcs by stack id in signal safe case
 *
 * @param stackId  the stack id to be resolved.
 * @param buffer  buffer used to store the pcs.
 * @param bufferSize  buffer size in bytes.
 * @return if succeed return true, otherwise return false
 *
 * @note This interface is async-signal-safe: it does not lock, allocate memory
 *       or call any non async-signal-safe function.
*/
bool DfxGetPcsByStackId(uint64_t stackId, void** buffer, size_t bufferSize);
 
/**
 * @brief stitch the async stack pcs of submitter to the collected frames
 *
 * The stitched frames are appended as: a link layer marker followed by the
 * submitter pcs. The marker value is 0xFFFFFFFF (zero extended to the pointer
 * width, i.e. 0x00000000FFFFFFFF on LP64), and consumers must mask the frame
 * with 0xFFFFFFFF before comparing it against this value. The marker is part
 * of the interface contract and must not be changed without updating the
 * consumers (e.g. the XSAN unwinder).
 *
 * @param frames  the collected frames.
 * @param capacity  the capacity of frames.
 * @param numFrames  the number of frames already collected.
 * @return the number of frames after stitching
*/
size_t StitchXsansAsyncStacks(void** frames, size_t capacity, size_t numFrames);
 
#ifdef __cplusplus
}
#endif
 
#endif // DFX_ASYNC_STACK_SIGNAL_SAFE_H