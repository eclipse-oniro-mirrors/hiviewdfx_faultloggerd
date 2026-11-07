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
 
#include <gtest/gtest.h>
 
#include <cstdint>
#include <cstring>
 
#include "async_stack.h"
#include "async_stack_signal_safe.h"
#include "unique_stack_table.h"
 
using namespace testing::ext;
 
namespace OHOS {
namespace HiviewDFX {
// Internal entry points of async_stack_signal_safe.cpp (no public header declaration).
bool GetPcsByStackIdSignalSafe(uint64_t stackId, void** buffer, size_t bufferSize);
size_t StitchAsyncStacksSignalSafe(void** frames, size_t capacity, size_t numFrames);
} // namespace HiviewDFX
} // namespace OHOS
 
namespace OHOS {
namespace HiviewDFX {
namespace {
constexpr uint32_t TABLE_NODE_CNT = 512;
constexpr uintptr_t PC_TAIL = 0xAAA;
constexpr uintptr_t PC_HEAD = 0xBBB;
constexpr uintptr_t PC_EXTRA = 0xCCC;
 
void FillNode(Node& node, uintptr_t pc, uint64_t prevIdx)
{
    node.value = 0;
    node.section.pc = pc;
    node.section.prevIdx = prevIdx;
}
 
StackId MakeStackId(uint64_t index, uint64_t nr)
{
    StackId id;
    id.value = 0;
    id.section.id = index;
    id.section.nr = nr;
    return id;
}
 
UniqueStackTable* ResetSingletonTable()
{
    UniqueStackTable* instance = UniqueStackTable::Instance();
    if (instance == nullptr) {
        return nullptr;
    }
    instance->SwitchExternalBuffer(nullptr, 0);
    if (!instance->Init()) {
        return nullptr;
    }
    // A previous profiler test may have left the flag set, which disables the signal safe lookup.
    instance->profilerInit_ = false;
    return instance;
}
} // namespace
 
class AsyncStackSignalSafeTest : public testing::Test {};
 
/**
 * @tc.name: AsyncStackSignalSafeTest001
 * @tc.desc: DfxGetPcsByStackId returns false when buffer is null
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest001, TestSize.Level2)
{
    void* out[2] = {nullptr};
    EXPECT_FALSE(DfxGetPcsByStackId(0, nullptr, sizeof(out)));
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest002
 * @tc.desc: DfxGetPcsByStackId returns false when bufferSize is zero
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest002, TestSize.Level2)
{
    void* out[2] = {nullptr};
    EXPECT_FALSE(DfxGetPcsByStackId(0, out, 0));
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest003
 * @tc.desc: GetPcsByStackIdSignalSafe returns false when the table buffer is not initialized
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest003, TestSize.Level2)
{
    UniqueStackTable table;
    void* out[2] = {nullptr};
    EXPECT_FALSE(table.GetPcsByStackIdSignalSafe(MakeStackId(1, 1), out, sizeof(out)));
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest003A
 * @tc.desc: GetPcsByStackIdSignalSafe returns false when the output buffer is null
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest003A, TestSize.Level2)
{
    Node buf[TABLE_NODE_CNT] = {};
    UniqueStackTable table(buf, sizeof(buf), false);
    EXPECT_FALSE(table.GetPcsByStackIdSignalSafe(MakeStackId(1, 1), nullptr, sizeof(void*)));
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest004
 * @tc.desc: GetPcsByStackIdSignalSafe returns false when nr exceeds the buffer capacity
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest004, TestSize.Level2)
{
    Node buf[TABLE_NODE_CNT] = {};
    UniqueStackTable table(buf, sizeof(buf), false);
    void* out[1] = {nullptr};
    // nr = 2 but buffer can only hold 1 pointer.
    EXPECT_FALSE(table.GetPcsByStackIdSignalSafe(MakeStackId(1, 2), out, sizeof(out)));
    EXPECT_EQ(out[0], nullptr);
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest005
 * @tc.desc: GetPcsByStackIdSignalSafe returns false when the table is profiler initialized
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest005, TestSize.Level2)
{
    Node buf[TABLE_NODE_CNT] = {};
    UniqueStackTable table(buf, sizeof(buf), false);
    Node head = {};
    FillNode(head, PC_HEAD, HEAD_NODE_INDEX);
    ASSERT_TRUE(table.ImportNode(1, head));
    void* out[2] = {nullptr};
    // Control: the same lookup succeeds while the profiler flag is clear.
    table.profilerInit_ = false;
    ASSERT_TRUE(table.GetPcsByStackIdSignalSafe(MakeStackId(1, 1), out, sizeof(out)));
    EXPECT_EQ(reinterpret_cast<uintptr_t>(out[0]), PC_HEAD);
    table.profilerInit_ = true;
    EXPECT_FALSE(table.GetPcsByStackIdSignalSafe(MakeStackId(1, 1), out, sizeof(out)));
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest006
 * @tc.desc: GetPcsByStackIdSignalSafe returns false when the node index is out of range
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest006, TestSize.Level2)
{
    Node buf[TABLE_NODE_CNT] = {};
    UniqueStackTable table(buf, sizeof(buf), false);
    void* out[2] = {nullptr};
    // totalNodes equals TABLE_NODE_CNT for this buffer, so the index must exceed it.
    EXPECT_FALSE(table.GetPcsByStackIdSignalSafe(MakeStackId(TABLE_NODE_CNT + 1, 1), out, sizeof(out)));
    EXPECT_EQ(out[0], nullptr);
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest007
 * @tc.desc: GetPcsByStackIdSignalSafe returns false when a prev index is out of range
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest007, TestSize.Level2)
{
    Node buf[TABLE_NODE_CNT] = {};
    UniqueStackTable table(buf, sizeof(buf), false);
    Node node = {};
    FillNode(node, PC_EXTRA, TABLE_NODE_CNT + 1);
    ASSERT_TRUE(table.ImportNode(3, node));
    void* out[2] = {nullptr};
    EXPECT_FALSE(table.GetPcsByStackIdSignalSafe(MakeStackId(3, 2), out, sizeof(out)));
    // The current pc is written before the prev index is validated, so out[0] holds it
    // while the remaining slot stays untouched.
    EXPECT_EQ(reinterpret_cast<uintptr_t>(out[0]), PC_EXTRA);
    EXPECT_EQ(out[1], nullptr);
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest008
 * @tc.desc: GetPcsByStackIdSignalSafe returns true and resolves the pc chain in order
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest008, TestSize.Level2)
{
    Node buf[TABLE_NODE_CNT] = {};
    UniqueStackTable table(buf, sizeof(buf), false);
    Node head = {};
    FillNode(head, PC_HEAD, HEAD_NODE_INDEX);
    Node tail = {};
    FillNode(tail, PC_TAIL, 1);
    ASSERT_TRUE(table.ImportNode(1, head));
    ASSERT_TRUE(table.ImportNode(2, tail));
    void* out[2] = {nullptr};
    ASSERT_TRUE(table.GetPcsByStackIdSignalSafe(MakeStackId(2, 2), out, sizeof(out)));
    EXPECT_EQ(reinterpret_cast<uintptr_t>(out[0]), PC_TAIL);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(out[1]), PC_HEAD);
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest009
 * @tc.desc: GetPcsByStackIdSignalSafe returns true with an empty node count
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest009, TestSize.Level2)
{
    Node buf[TABLE_NODE_CNT] = {};
    UniqueStackTable table(buf, sizeof(buf), false);
    void* out[2] = {nullptr};
    EXPECT_TRUE(table.GetPcsByStackIdSignalSafe(MakeStackId(1, 0), out, sizeof(out)));
    // nr == 0 must not write any slot.
    EXPECT_EQ(out[0], nullptr);
    EXPECT_EQ(out[1], nullptr);
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest010
 * @tc.desc: GetPcsByStackIdSignalSafe stops at the head node marker
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest010, TestSize.Level2)
{
    Node buf[TABLE_NODE_CNT] = {};
    UniqueStackTable table(buf, sizeof(buf), false);
    Node head = {};
    FillNode(head, PC_HEAD, HEAD_NODE_INDEX);
    ASSERT_TRUE(table.ImportNode(1, head));
    void* out[4] = {nullptr};
    // nr is larger than the actual chain length, the head marker must stop the walk.
    ASSERT_TRUE(table.GetPcsByStackIdSignalSafe(MakeStackId(1, 4), out, sizeof(out)));
    EXPECT_EQ(reinterpret_cast<uintptr_t>(out[0]), PC_HEAD);
    // The head marker must stop the walk, so the remaining slots stay untouched.
    EXPECT_EQ(out[1], nullptr);
    EXPECT_EQ(out[2], nullptr);
    EXPECT_EQ(out[3], nullptr);
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest011
 * @tc.desc: namespace GetPcsByStackIdSignalSafe resolves pcs from the singleton table
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest011, TestSize.Level2)
{
    UniqueStackTable* instance = ResetSingletonTable();
    ASSERT_NE(instance, nullptr);
    uintptr_t pcs[2] = {PC_TAIL, PC_HEAD};
    StackId stackId;
    stackId.value = 0;
    ASSERT_NE(instance->PutPcsInTable(&stackId, pcs, 2), 0U);
    void* out[2] = {nullptr};
    ASSERT_TRUE(GetPcsByStackIdSignalSafe(stackId.value, out, sizeof(out)));
    EXPECT_EQ(reinterpret_cast<uintptr_t>(out[0]), PC_TAIL);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(out[1]), PC_HEAD);
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest012
 * @tc.desc: StitchAsyncStacksSignalSafe returns zero when frames is null
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest012, TestSize.Level2)
{
    EXPECT_EQ(StitchAsyncStacksSignalSafe(nullptr, 8, 3), 0U);
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest013
 * @tc.desc: StitchAsyncStacksSignalSafe keeps numFrames when no submitter stack id is set
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest013, TestSize.Level2)
{
#if defined(__aarch64__)
    DfxInitAsyncStack();
    DfxSetSubmitterStackId(0);
#endif
    void* frames[8] = {nullptr};
    EXPECT_EQ(StitchAsyncStacksSignalSafe(frames, 8, 3), 3U);
    EXPECT_EQ(frames[0], nullptr);
    EXPECT_EQ(frames[1], nullptr);
    EXPECT_EQ(frames[2], nullptr);
    EXPECT_EQ(frames[3], nullptr);
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest014
 * @tc.desc: StitchAsyncStacksSignalSafe appends the link marker and submitter pcs
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest014, TestSize.Level2)
{
#if defined(__aarch64__)
    UniqueStackTable* instance = ResetSingletonTable();
    ASSERT_NE(instance, nullptr);
    uintptr_t pcs[2] = {PC_TAIL, PC_HEAD};
    StackId stackId;
    stackId.value = 0;
    ASSERT_NE(instance->PutPcsInTable(&stackId, pcs, 2), 0U);
    ASSERT_TRUE(DfxInitAsyncStack());
    DfxSetSubmitterStackId(stackId.value);
    void* frames[8] = {nullptr};
    size_t result = StitchAsyncStacksSignalSafe(frames, 8, 0);
    EXPECT_EQ(result, 3U);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(frames[0]), LINK_LAYER_MARKER);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(frames[1]), PC_TAIL);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(frames[2]), PC_HEAD);
    EXPECT_EQ(frames[3], nullptr);
    DfxSetSubmitterStackId(0);
#endif
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest015
 * @tc.desc: StitchAsyncStacksSignalSafe does not append when the capacity is already full
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest015, TestSize.Level2)
{
#if defined(__aarch64__)
    UniqueStackTable* instance = ResetSingletonTable();
    ASSERT_NE(instance, nullptr);
    uintptr_t pcs[2] = {PC_TAIL, PC_HEAD};
    StackId stackId;
    stackId.value = 0;
    ASSERT_NE(instance->PutPcsInTable(&stackId, pcs, 2), 0U);
    ASSERT_TRUE(DfxInitAsyncStack());
    DfxSetSubmitterStackId(stackId.value);
    void* frames[2] = {nullptr};
    EXPECT_EQ(StitchAsyncStacksSignalSafe(frames, 2, 2), 2U);
    EXPECT_EQ(frames[0], nullptr);
    EXPECT_EQ(frames[1], nullptr);
    DfxSetSubmitterStackId(0);
#endif
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest016
 * @tc.desc: StitchAsyncStacksSignalSafe truncates the submitter pcs to the remaining capacity
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest016, TestSize.Level2)
{
#if defined(__aarch64__)
    UniqueStackTable* instance = ResetSingletonTable();
    ASSERT_NE(instance, nullptr);
    uintptr_t pcs[2] = {PC_TAIL, PC_HEAD};
    StackId stackId;
    stackId.value = 0;
    ASSERT_NE(instance->PutPcsInTable(&stackId, pcs, 2), 0U);
    ASSERT_TRUE(DfxInitAsyncStack());
    DfxSetSubmitterStackId(stackId.value);
    void* frames[2] = {nullptr};
    // capacity 2: marker + the first pc only.
    EXPECT_EQ(StitchAsyncStacksSignalSafe(frames, 2, 0), 2U);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(frames[0]), LINK_LAYER_MARKER);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(frames[1]), PC_TAIL);
    DfxSetSubmitterStackId(0);
#endif
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest018
 * @tc.desc: StitchAsyncStacksSignalSafe keeps numFrames when the submitter stack id cannot be resolved
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest018, TestSize.Level2)
{
#if defined(__aarch64__)
    UniqueStackTable* instance = ResetSingletonTable();
    ASSERT_NE(instance, nullptr);
    ASSERT_TRUE(DfxInitAsyncStack());
    // A non-zero id whose node index is out of range makes the lookup fail.
    StackId stackId;
    stackId.value = 0;
    stackId.section.id = 0xFFFFF;
    stackId.section.nr = 1;
    DfxSetSubmitterStackId(stackId.value);
    void* frames[8] = {nullptr};
    EXPECT_EQ(StitchAsyncStacksSignalSafe(frames, 8, 2), 2U);
    EXPECT_EQ(frames[2], nullptr);
    DfxSetSubmitterStackId(0);
#endif
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest019
 * @tc.desc: StitchAsyncStacksSignalSafe keeps numFrames when the resolved stack has no pcs
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest019, TestSize.Level2)
{
#if defined(__aarch64__)
    UniqueStackTable* instance = ResetSingletonTable();
    ASSERT_NE(instance, nullptr);
    ASSERT_TRUE(DfxInitAsyncStack());
    // Find an empty node so the resolved chain yields a zero pc and asyncCount stays 0.
    Node* head = instance->GetHeadNode();
    ASSERT_NE(head, nullptr);
    uint64_t emptyIndex = 0;
    for (uint64_t i = 1; i < instance->stackTable_.totalNodes; ++i) {
        if (head[i].value == 0) {
            emptyIndex = i;
            break;
        }
    }
    ASSERT_NE(emptyIndex, 0U);
    StackId stackId;
    stackId.value = 0;
    stackId.section.id = emptyIndex;
    stackId.section.nr = 1;
    DfxSetSubmitterStackId(stackId.value);
    void* frames[8] = {nullptr};
    EXPECT_EQ(StitchAsyncStacksSignalSafe(frames, 8, 1), 1U);
    EXPECT_EQ(frames[1], nullptr);
    DfxSetSubmitterStackId(0);
#endif
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest020
 * @tc.desc: extern "C" DfxGetPcsByStackId resolves the pc chain from the singleton table
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest020, TestSize.Level2)
{
    UniqueStackTable* instance = ResetSingletonTable();
    ASSERT_NE(instance, nullptr);
    uintptr_t pcs[2] = {PC_TAIL, PC_HEAD};
    StackId stackId;
    stackId.value = 0;
    ASSERT_NE(instance->PutPcsInTable(&stackId, pcs, 2), 0U);
    void* out[2] = {nullptr};
    ASSERT_TRUE(DfxGetPcsByStackId(stackId.value, out, sizeof(out)));
    EXPECT_EQ(reinterpret_cast<uintptr_t>(out[0]), PC_TAIL);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(out[1]), PC_HEAD);
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest021
 * @tc.desc: extern "C" DfxGetPcsByStackId returns false when the buffer is smaller than the pc count
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest021, TestSize.Level2)
{
    UniqueStackTable* instance = ResetSingletonTable();
    ASSERT_NE(instance, nullptr);
    uintptr_t pcs[2] = {PC_TAIL, PC_HEAD};
    StackId stackId;
    stackId.value = 0;
    ASSERT_NE(instance->PutPcsInTable(&stackId, pcs, 2), 0U);
    void* out[1] = {nullptr};
    EXPECT_FALSE(DfxGetPcsByStackId(stackId.value, out, sizeof(out)));
    EXPECT_EQ(out[0], nullptr);
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest022
 * @tc.desc: GetPcsByStackIdSignalSafe returns false when the node index equals totalNodes
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest022, TestSize.Level2)
{
    Node buf[TABLE_NODE_CNT] = {};
    UniqueStackTable table(buf, sizeof(buf), false);
    void* out[2] = {nullptr};
    EXPECT_FALSE(table.GetPcsByStackIdSignalSafe(MakeStackId(TABLE_NODE_CNT, 1), out, sizeof(out)));
    EXPECT_EQ(out[0], nullptr);
    EXPECT_EQ(out[1], nullptr);
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest023
 * @tc.desc: GetPcsByStackIdSignalSafe returns false when bufferSize is not a whole pointer multiple
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest023, TestSize.Level2)
{
    Node buf[TABLE_NODE_CNT] = {};
    UniqueStackTable table(buf, sizeof(buf), false);
    Node head = {};
    FillNode(head, PC_HEAD, HEAD_NODE_INDEX);
    ASSERT_TRUE(table.ImportNode(1, head));
    void* out[2] = {nullptr};
    EXPECT_FALSE(table.GetPcsByStackIdSignalSafe(MakeStackId(1, 1), out, sizeof(void*) - 1));
    EXPECT_EQ(out[0], nullptr);
    EXPECT_EQ(out[1], nullptr);
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest024
 * @tc.desc: extern "C" StitchXsansAsyncStacks appends the link marker and submitter pcs
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest024, TestSize.Level2)
{
#if defined(__aarch64__)
    UniqueStackTable* instance = ResetSingletonTable();
    ASSERT_NE(instance, nullptr);
    uintptr_t pcs[2] = {PC_TAIL, PC_HEAD};
    StackId stackId;
    stackId.value = 0;
    ASSERT_NE(instance->PutPcsInTable(&stackId, pcs, 2), 0U);
    ASSERT_TRUE(DfxInitAsyncStack());
    DfxSetSubmitterStackId(stackId.value);
    void* frames[8] = {nullptr};
    ASSERT_EQ(StitchXsansAsyncStacks(frames, 8, 1), 4U);
    // The pre-existing frame must be left untouched.
    EXPECT_EQ(frames[0], nullptr);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(frames[1]), LINK_LAYER_MARKER);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(frames[2]), PC_TAIL);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(frames[3]), PC_HEAD);
    DfxSetSubmitterStackId(0);
#endif
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest025
 * @tc.desc: StitchAsyncStacksSignalSafe keeps numFrames when the submitter stack exceeds the lookup limit
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest025, TestSize.Level2)
{
#if defined(__aarch64__)
    UniqueStackTable* instance = ResetSingletonTable();
    ASSERT_NE(instance, nullptr);
    constexpr size_t pcCount = 20;
    uintptr_t pcs[pcCount] = {0};
    for (size_t i = 0; i < pcCount; ++i) {
        pcs[i] = PC_TAIL + i;
    }
    StackId stackId;
    stackId.value = 0;
    ASSERT_NE(instance->PutPcsInTable(&stackId, pcs, pcCount), 0U);
    ASSERT_TRUE(DfxInitAsyncStack());
    DfxSetSubmitterStackId(stackId.value);
    void* frames[32] = {nullptr};
    // The signal safe lookup only accepts up to 16 pcs, so nothing is stitched.
    EXPECT_EQ(StitchAsyncStacksSignalSafe(frames, 32, 4), 4U);
    EXPECT_EQ(frames[4], nullptr);
    EXPECT_EQ(frames[5], nullptr);
    DfxSetSubmitterStackId(0);
#endif
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest026
 * @tc.desc: StitchAsyncStacksSignalSafe appends only the link marker when one slot is left
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest026, TestSize.Level2)
{
#if defined(__aarch64__)
    UniqueStackTable* instance = ResetSingletonTable();
    ASSERT_NE(instance, nullptr);
    uintptr_t pcs[2] = {PC_TAIL, PC_HEAD};
    StackId stackId;
    stackId.value = 0;
    ASSERT_NE(instance->PutPcsInTable(&stackId, pcs, 2), 0U);
    ASSERT_TRUE(DfxInitAsyncStack());
    DfxSetSubmitterStackId(stackId.value);
    void* frames[3] = {nullptr};
    // capacity 3 with 2 frames already collected leaves room for the marker only.
    EXPECT_EQ(StitchAsyncStacksSignalSafe(frames, 3, 2), 3U);
    // The two pre-existing frames must be left untouched.
    EXPECT_EQ(frames[0], nullptr);
    EXPECT_EQ(frames[1], nullptr);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(frames[2]), LINK_LAYER_MARKER);
    DfxSetSubmitterStackId(0);
#endif
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest027
 * @tc.desc: StitchAsyncStacksSignalSafe stitches at most 16 submitter pcs when the chain is longer
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest027, TestSize.Level2)
{
#if defined(__aarch64__)
    UniqueStackTable* instance = ResetSingletonTable();
    ASSERT_NE(instance, nullptr);
    constexpr size_t pcCount = 16;
    uintptr_t pcs[pcCount] = {0};
    for (size_t i = 0; i < pcCount; ++i) {
        pcs[i] = PC_TAIL + i;
    }
    StackId stackId;
    stackId.value = 0;
    ASSERT_NE(instance->PutPcsInTable(&stackId, pcs, pcCount), 0U);
    ASSERT_TRUE(DfxInitAsyncStack());
    DfxSetSubmitterStackId(stackId.value);
    void* frames[32] = {nullptr};
    // marker + all 16 pcs are stitched, and the scan stops at the ASYNC_MAX_CONTENT bound.
    ASSERT_EQ(StitchAsyncStacksSignalSafe(frames, 32, 0), pcCount + 1);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(frames[0]), LINK_LAYER_MARKER);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(frames[1]), PC_TAIL);
    EXPECT_EQ(reinterpret_cast<uintptr_t>(frames[pcCount]), PC_TAIL + pcCount - 1);
    EXPECT_EQ(frames[pcCount + 1], nullptr);
    EXPECT_EQ(frames[pcCount + 2], nullptr);
    DfxSetSubmitterStackId(0);
#endif
}
 
/**
 * @tc.name: AsyncStackSignalSafeTest017
 * @tc.desc: extern "C" StitchXsansAsyncStacks delegates to the signal safe implementation
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackSignalSafeTest, AsyncStackSignalSafeTest017, TestSize.Level2)
{
    EXPECT_EQ(StitchXsansAsyncStacks(nullptr, 8, 5), 0U);
#if defined(__aarch64__)
    DfxInitAsyncStack();
    DfxSetSubmitterStackId(0);
#endif
    void* frames[4] = {nullptr};
    EXPECT_EQ(StitchXsansAsyncStacks(frames, 4, 2), 2U);
    // No submitter stack id is set, so nothing is appended.
    EXPECT_EQ(frames[2], nullptr);
    EXPECT_EQ(frames[3], nullptr);
}
} // namespace HiviewDFX
} // namespace OHOS