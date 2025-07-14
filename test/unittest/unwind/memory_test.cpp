/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <ctime>
#include <securec.h>
#include <string>
#include <vector>

#include "dfx_accessors.h"
#include "dfx_elf.h"
#include "dfx_maps.h"
#include "dfx_memory.h"
#include "dfx_regs.h"
#include "dfx_regs_get.h"
#include "dfx_symbols.h"
#include "dfx_ptrace.h"
#include "dfx_test_util.h"
#include "dwarf_define.h"
#include "elf_factory.h"
#include "stack_utils.h"

using namespace OHOS::HiviewDFX;
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace HiviewDFX {
class DfxMemoryTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

namespace {
/**
 * @tc.name: DfxMemoryTest001
 * @tc.desc: test DfxMemory class ReadReg
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest001: start.";
    uintptr_t regs[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa};
    UnwindContext ctx;
    ctx.regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regs, sizeof(regs) / sizeof(regs[0]));
    auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_LOCAL);
    memory->SetCtx(&ctx);
    uintptr_t value;
    bool ret = memory->ReadReg(0, &value);
    EXPECT_EQ(true, ret) << "DfxMemoryTest001: ret" << ret;
    EXPECT_EQ(static_cast<uintptr_t>(0x1), value) << "DfxMemoryTest001: value" << value;
    GTEST_LOG_(INFO) << "DfxMemoryTest001: end.";
}

/**
 * @tc.name: DfxMemoryTest002
 * @tc.desc: test DfxMemory class Read
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest002: start.";
    uint8_t values[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};

    uintptr_t addr = reinterpret_cast<uintptr_t>(&values[0]);
    uintptr_t value;
    auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_LOCAL);
    bool ret = memory->Read<uintptr_t>(addr, &value, false);
    EXPECT_EQ(true, ret) << "DfxMemoryTest002: ret:" << ret;


    uint64_t tmp;
    memory->Read(addr, &tmp, sizeof(uint8_t), false);
    ASSERT_EQ(tmp, 0x01);

    memory->Read(addr, &tmp, sizeof(uint16_t), false);
    ASSERT_EQ(tmp, 0x0201);

    memory->Read(addr, &tmp, sizeof(uint32_t), false);
    ASSERT_EQ(tmp, 0x04030201);

    memory->Read(addr, &tmp, sizeof(uint64_t), false);
    ASSERT_EQ(tmp, 0x0807060504030201);

    GTEST_LOG_(INFO) << "DfxMemoryTest002: end.";
}

/**
 * @tc.name: DfxMemoryTest003
 * @tc.desc: test DfxMemory class Read
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest003, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest003: start.";
    uint8_t values[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
    UnwindContext ctx;
    ASSERT_TRUE(StackUtils::GetSelfStackRange(ctx.stackBottom, ctx.stackTop));
    ctx.stackCheck = true;
    auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_LOCAL);
    memory->SetCtx(&ctx);
    uintptr_t addr = reinterpret_cast<uintptr_t>(&values[0]);
    uintptr_t value;
    ASSERT_TRUE(memory->Read<uintptr_t>(addr, &value, false));
#if defined(__arm__)
    ASSERT_EQ(value, 0x04030201);
#elif defined(__aarch64__)
    ASSERT_EQ(value, 0x0807060504030201);
#endif

    uint64_t tmp;
    ASSERT_TRUE(memory->Read(addr, &tmp, sizeof(uint8_t), false));
    ASSERT_EQ(tmp, 0x01);

    ASSERT_TRUE(memory->Read(addr, &tmp, sizeof(uint16_t), false));
    ASSERT_EQ(tmp, 0x0201);

    ASSERT_TRUE(memory->Read(addr, &tmp, sizeof(uint32_t), false));
    ASSERT_EQ(tmp, 0x04030201);

    ASSERT_TRUE(memory->Read(addr, &tmp, sizeof(uint64_t), false));
    ASSERT_EQ(tmp, 0x0807060504030201);

    GTEST_LOG_(INFO) << "DfxMemoryTest003: end.";
}

/**
 * @tc.name: DfxMemoryTest004
 * @tc.desc: test DfxMemory class Read
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest004, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest004: start.";
    uint8_t values[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
    UnwindContext ctx;
    ASSERT_TRUE(StackUtils::GetSelfStackRange(ctx.stackBottom, ctx.stackTop));
    ctx.stackCheck = true;
    auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_LOCAL);
    memory->SetCtx(&ctx);
    uintptr_t addr = reinterpret_cast<uintptr_t>(&values[0]);
    uint8_t tmp8;
    ASSERT_TRUE(memory->Read<uint8_t>(addr, &tmp8, false));
    ASSERT_EQ(tmp8, 0x01);
    uint16_t tmp16;
    ASSERT_TRUE(memory->Read<uint16_t>(addr, &tmp16, false));
    ASSERT_EQ(tmp16, 0x0201);
    uint32_t tmp32;
    ASSERT_TRUE(memory->Read<uint32_t>(addr, &tmp32, false));
    ASSERT_EQ(tmp32, 0x04030201);
    uint64_t tmp64;
    ASSERT_TRUE(memory->Read<uint64_t>(addr, &tmp64, false));
    ASSERT_EQ(tmp64, 0x0807060504030201);
    GTEST_LOG_(INFO) << "DfxMemoryTest004: end.";
}

/**
 * @tc.name: DfxMemoryTest005
 * @tc.desc: test DfxMemory class Read
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest005, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest005: start.";
    uint8_t values[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
    UnwindContext ctx;
    ASSERT_TRUE(StackUtils::GetSelfStackRange(ctx.stackBottom, ctx.stackTop));
    ctx.stackCheck = true;
    auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_LOCAL);
    memory->SetCtx(&ctx);
    uintptr_t addr = reinterpret_cast<uintptr_t>(&values[0]);
    uintptr_t valuePrel32;
    ASSERT_TRUE(memory->ReadPrel31(addr, &valuePrel32));
    uintptr_t invalidAddr = 0;
    ASSERT_FALSE(memory->ReadPrel31(invalidAddr, &valuePrel32));
    ASSERT_EQ(valuePrel32, 0x04030201 + addr);
    char testStr[] = "Test ReadString Func";
    std::string resultStr;
    uintptr_t addrStr = reinterpret_cast<uintptr_t>(&testStr[0]);
    ASSERT_TRUE(memory->ReadString(addrStr, &resultStr, sizeof(testStr)/sizeof(char), false));
    ASSERT_EQ(testStr, resultStr);
    ASSERT_EQ(memory->ReadUleb128(addr), 1U);
    ASSERT_EQ(memory->ReadSleb128(addr), 2);
    ASSERT_EQ(memory->ReadSleb128(invalidAddr), 0);
    GTEST_LOG_(INFO) << "DfxMemoryTest005: end.";
}

/**
 * @tc.name: DfxMemoryTest006
 * @tc.desc: test DfxMemory class Read
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest006, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest006: start.";
    UnwindContext ctx;
    ASSERT_TRUE(StackUtils::GetSelfStackRange(ctx.stackBottom, ctx.stackTop));
    ctx.stackCheck = true;
    auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_LOCAL);
    memory->SetCtx(&ctx);
    ASSERT_EQ(memory->GetEncodedSize(DW_EH_PE_absptr), sizeof(uintptr_t));
    ASSERT_EQ(memory->GetEncodedSize(DW_EH_PE_sdata1), 1);
    ASSERT_EQ(memory->GetEncodedSize(DW_EH_PE_sdata2), 2);
    ASSERT_EQ(memory->GetEncodedSize(DW_EH_PE_sdata4), 4);
    ASSERT_EQ(memory->GetEncodedSize(DW_EH_PE_sdata8), 8);
    ASSERT_EQ(memory->GetEncodedSize(DW_EH_PE_sleb128), 0);
    ASSERT_EQ(memory->GetEncodedSize(DW_EH_PE_omit), 0);
    GTEST_LOG_(INFO) << "DfxMemoryTest006: end.";
}

/**
 * @tc.name: DfxMemoryTest007
 * @tc.desc: test DfxMemory class ReadReg in remote case
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest007, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest007: start.";
    uintptr_t regs[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa};
    UnwindContext ctx;
    ctx.regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regs, sizeof(regs) / sizeof(regs[0]));
    auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_REMOTE);
    uintptr_t value;
    EXPECT_FALSE(memory->ReadReg(0, &value));
    memory->SetCtx(&ctx);
    bool ret = memory->ReadReg(0, &value);
    EXPECT_EQ(true, ret) << "DfxMemoryTest007: ret" << ret;
    EXPECT_EQ(static_cast<uintptr_t>(0x1), value) << "DfxMemoryTest007: value" << value;
    GTEST_LOG_(INFO) << "DfxMemoryTest007: end.";
}
/**
 * @tc.name: DfxMemoryTest008
 * @tc.desc: test DfxMemory class Read in remote case
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest008, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest008: start.";
    static pid_t pid = getpid();
    uint8_t values[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
    pid_t child = fork();
    if (child == 0) {
        GTEST_LOG_(INFO) << "pid: " << pid << ", ppid:" << getppid();
        DfxPtrace::Attach(pid);
        uintptr_t value;
        UnwindContext ctx;
        ctx.pid = pid;
        auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_REMOTE);
        memory->SetCtx(&ctx);
        uintptr_t addr = reinterpret_cast<uintptr_t>(&values[0]);
        bool ret = memory->Read<uintptr_t>(addr, &value, false);
        EXPECT_EQ(true, ret) << "DfxMemoryTest008: ret:" << ret;
        uint64_t tmp;
        memory->Read(addr, &tmp, sizeof(uint8_t), false);
        EXPECT_EQ(tmp, 0x01);

        memory->Read(addr, &tmp, sizeof(uint16_t), false);
        EXPECT_EQ(tmp, 0x0201);

        memory->Read(addr, &tmp, sizeof(uint32_t), false);
        EXPECT_EQ(tmp, 0x04030201);

        memory->Read(addr, &tmp, sizeof(uint64_t), false);
        EXPECT_EQ(tmp, 0x0807060504030201);
        DfxPtrace::Detach(pid);
        CheckAndExit(HasFailure());
    }
    int status;
    wait(&status);
    ASSERT_EQ(status, 0);
    GTEST_LOG_(INFO) << "DfxMemoryTest008: end.";
}

/**
 * @tc.name: DfxMemoryTest009
 * @tc.desc: test DfxMemory class Read in remote case
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest009, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest009: start.";
    static pid_t pid = getpid();
    uint8_t values[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
    pid_t child = fork();
    if (child == 0) {
        GTEST_LOG_(INFO) << "pid: " << pid << ", ppid:" << getppid();
        DfxPtrace::Attach(pid);
        UnwindContext ctx;
        ctx.pid = pid;
        auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_REMOTE);
        memory->SetCtx(&ctx);
        uintptr_t addr = reinterpret_cast<uintptr_t>(&values[0]);
        uintptr_t value;
        EXPECT_TRUE(memory->Read<uintptr_t>(addr, &value, false));
#if defined(__arm__)
        EXPECT_EQ(value, 0x04030201);
#elif defined(__aarch64__)
        EXPECT_EQ(value, 0x0807060504030201);
#endif

        uint64_t tmp;
        EXPECT_TRUE(memory->Read(addr, &tmp, sizeof(uint8_t), false));
        EXPECT_EQ(tmp, 0x01);

        EXPECT_TRUE(memory->Read(addr, &tmp, sizeof(uint16_t), false));
        EXPECT_EQ(tmp, 0x0201);

        EXPECT_TRUE(memory->Read(addr, &tmp, sizeof(uint32_t), false));
        EXPECT_EQ(tmp, 0x04030201);

        EXPECT_TRUE(memory->Read(addr, &tmp, sizeof(uint64_t), false));
        EXPECT_EQ(tmp, 0x0807060504030201);
        DfxPtrace::Detach(pid);
        CheckAndExit(HasFailure());
    }
    int status;
    wait(&status);
    ASSERT_EQ(status, 0);
    GTEST_LOG_(INFO) << "DfxMemoryTest009: end.";
}

/**
 * @tc.name: DfxMemoryTest010
 * @tc.desc: test DfxMemory class Read in remote case
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest010, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest010: start.";
    static pid_t pid = getpid();
    uint8_t values[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
    pid_t child = fork();
    if (child == 0) {
        GTEST_LOG_(INFO) << "pid: " << pid << ", ppid:" << getppid();
        DfxPtrace::Attach(pid);

        UnwindContext ctx;
        ctx.pid = pid;
        auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_REMOTE);
        memory->SetCtx(&ctx);
        uintptr_t addr = reinterpret_cast<uintptr_t>(&values[0]);
        uint8_t tmp8;
        EXPECT_TRUE(memory->Read<uint8_t>(addr, &tmp8, false));
        EXPECT_EQ(tmp8, 0x01);
        uint16_t tmp16;
        EXPECT_TRUE(memory->Read<uint16_t>(addr, &tmp16, false));
        EXPECT_EQ(tmp16, 0x0201);
        uint32_t tmp32;
        EXPECT_TRUE(memory->Read<uint32_t>(addr, &tmp32, false));
        EXPECT_EQ(tmp32, 0x04030201);
        uint64_t tmp64;
        EXPECT_TRUE(memory->Read<uint64_t>(addr, &tmp64, false));
        EXPECT_EQ(tmp64, 0x0807060504030201);
        DfxPtrace::Detach(pid);
        CheckAndExit(HasFailure());
    }
    int status;
    wait(&status);
    ASSERT_EQ(status, 0);
    GTEST_LOG_(INFO) << "DfxMemoryTest010: end.";
}

/**
 * @tc.name: DfxMemoryTest011
 * @tc.desc: test DfxMemory class Read in remote case
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest011, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest011: start.";
    static pid_t pid = getpid();
    uint8_t values[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0x10};
    char testStr[] = "Test ReadString Func Test ReadString Func Test ReadString Func \
        Test ReadString Func Test ReadString Func Test ReadString Func Test ReadString Func";
    pid_t child = fork();
    if (child == 0) {
        GTEST_LOG_(INFO) << "pid: " << pid << ", ppid:" << getppid();
        DfxPtrace::Attach(getppid());
        UnwindContext ctx;
        ctx.pid = getppid();
        auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_REMOTE);
        memory->SetCtx(&ctx);
        uintptr_t addr = reinterpret_cast<uintptr_t>(&values[0]);
        std::string resultStr;
        uintptr_t addrStr = reinterpret_cast<uintptr_t>(&testStr[0]);
        EXPECT_TRUE(memory->ReadString(addrStr, &resultStr, sizeof(testStr)/sizeof(char), false));
        EXPECT_EQ(testStr, resultStr);
        EXPECT_TRUE(memory->ReadString(addrStr, &resultStr, sizeof(testStr)/sizeof(char), true));
        EXPECT_EQ(testStr, resultStr);
        EXPECT_FALSE(memory->ReadString(addrStr, nullptr, sizeof(testStr)/sizeof(char), true));

        uintptr_t val;
        EXPECT_EQ(memory->ReadUleb128(addr), 1U);
        EXPECT_EQ(memory->ReadSleb128(addr), 2);
        memory->ReadFormatEncodedValue(addr, val, DW_EH_PE_uleb128);
        memory->ReadFormatEncodedValue(addr, val, DW_EH_PE_sleb128);
        memory->ReadFormatEncodedValue(addr, val, DW_EH_PE_udata1);
        memory->ReadFormatEncodedValue(addr, val, DW_EH_PE_sdata1);
        memory->ReadFormatEncodedValue(addr, val, DW_EH_PE_udata2);
        memory->ReadFormatEncodedValue(addr, val, DW_EH_PE_sdata2);
        memory->ReadFormatEncodedValue(addr, val, DW_EH_PE_udata4);
        memory->ReadFormatEncodedValue(addr, val, DW_EH_PE_sdata4);
        memory->ReadFormatEncodedValue(addr, val, DW_EH_PE_udata8);
        memory->ReadFormatEncodedValue(addr, val, DW_EH_PE_sdata8);
        memory->ReadFormatEncodedValue(addr, val, DW_EH_PE_omit);
        DfxPtrace::Detach(pid);
        CheckAndExit(HasFailure());
    }
    int status;
    wait(&status);
    ASSERT_EQ(status, 0);
    GTEST_LOG_(INFO) << "DfxMemoryTest011: end.";
}

/**
 * @tc.name: DfxMemoryTest012
 * @tc.desc: test DfxMemory class Read in remote case
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest012, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest012: start.";
    static pid_t pid = getpid();
    pid_t child = fork();
    if (child == 0) {
        GTEST_LOG_(INFO) << "pid: " << pid << ", ppid:" << getppid();
        DfxPtrace::Attach(pid);
        UnwindContext ctx;
        ctx.pid = pid;
        auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_REMOTE);
        memory->SetCtx(&ctx);
        EXPECT_EQ(memory->GetEncodedSize(DW_EH_PE_absptr), sizeof(uintptr_t));
        EXPECT_EQ(memory->GetEncodedSize(DW_EH_PE_sdata1), 1);
        EXPECT_EQ(memory->GetEncodedSize(DW_EH_PE_sdata2), 2);
        EXPECT_EQ(memory->GetEncodedSize(DW_EH_PE_sdata4), 4);
        EXPECT_EQ(memory->GetEncodedSize(DW_EH_PE_sdata8), 8);
        DfxPtrace::Detach(pid);
        CheckAndExit(HasFailure());
    }
    int status;
    wait(&status);
    ASSERT_EQ(status, 0);
    GTEST_LOG_(INFO) << "DfxMemoryTest012: end.";
}

/**
 * @tc.name: DfxMemoryTest013
 * @tc.desc: test DfxMemory class Read in error case
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest013, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest013: start.";
    auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_LOCAL);
    uintptr_t val;
    EXPECT_FALSE(memory->ReadReg(0, &val));
    uintptr_t regs[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa};
    UnwindContext ctx;
    ctx.regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regs, sizeof(regs) / sizeof(regs[0]));
    memory->SetCtx(&ctx);
    EXPECT_FALSE(memory->ReadReg(-1, &val));

    uint8_t values[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
    uintptr_t addr = reinterpret_cast<uintptr_t>(&values[0]);
    EXPECT_FALSE(memory->ReadMem(addr, nullptr));
    EXPECT_FALSE(memory->Read<uintptr_t>(addr, nullptr, false));
    EXPECT_FALSE(memory->Read(addr, nullptr, sizeof(uint8_t), false));
    EXPECT_FALSE(memory->Read<uint8_t>(addr, nullptr, false));
    EXPECT_FALSE(memory->Read<uint16_t>(addr, nullptr, false));
    EXPECT_FALSE(memory->Read<uint32_t>(addr, nullptr, false));
    EXPECT_FALSE(memory->Read<uint64_t>(addr, nullptr, false));
    GTEST_LOG_(INFO) << "DfxMemoryTest013: end.";
}

/**
 * @tc.name: DfxMemoryTest014
 * @tc.desc: test DfxMemory class Read in error case
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest014, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest014: start.";
    auto memory1 = std::make_shared<DfxMemory>(UNWIND_TYPE_CUSTOMIZE, nullptr);
    uintptr_t addr = 0;
    int val = memory1->ReadEncodedValue(addr, DW_EH_PE_omit);
    EXPECT_EQ(val, 0);
    memory1->ReadEncodedValue(addr, DW_EH_PE_aligned);
    std::shared_ptr<DfxMap> map = nullptr;
    auto memory2 = std::make_shared<DfxMemory>(UNWIND_TYPE_CUSTOMIZE_LOCAL, nullptr);
    auto memory3 = std::make_shared<DfxMemory>((UnwindType)1, nullptr);
    val = memory2->GetMapByPc(0, map);
    EXPECT_EQ(val, UNW_ERROR_INVALID_MEMORY);
    UnwindTableInfo uti;
    val = memory2->FindUnwindTable(0, uti);
    EXPECT_EQ(val, UNW_ERROR_INVALID_MEMORY);
    bool cur = DfxAccessors::GetMapByPcAndCtx(0, map, nullptr);
    EXPECT_FALSE(cur);
    GTEST_LOG_(INFO) << "DfxMemoryTest014: end.";
}
/**
 * @tc.name: DfxMemoryTest015
 * @tc.desc: test DfxMemory class 256 Read
 * @tc.type: FUNC
 */
HWTEST_F(DfxMemoryTest, DfxMemoryTest015, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMemoryTest015: start.";
    uint8_t values[] = {0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8};
    UnwindContext ctx;
    ASSERT_TRUE(StackUtils::GetSelfStackRange(ctx.stackBottom, ctx.stackTop));
    ctx.stackCheck = true;
    auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_LOCAL);
    memory->SetCtx(&ctx);
    uintptr_t addr = reinterpret_cast<uintptr_t>(&values[0]);
    uintptr_t valuePrel32;
    ASSERT_TRUE(memory->ReadPrel31(addr, &valuePrel32));
    uintptr_t invalidAddr = 0;
    ASSERT_FALSE(memory->ReadPrel31(invalidAddr, &valuePrel32));
    ASSERT_EQ(valuePrel32, 0x04030201 + addr);
    char testStr[] = "Test ReadString Func adfjak adfaaea- adfaf zxcdaa adfae ?dafafe aeacvdcx "
                     "edascccfae egfag xzfafasdaeacvdcx edfae egfag xzfafasd Test ReadString"
                     " Func adfjak adfaaea- adfaf zxcdaa adfae ?dafafe aeacvdcx edascccfae"
                     " egfag xzfafasdaeacvdcx edfae egfag xzfafasdc";
    std::string resultStr;
    uintptr_t addrStr = reinterpret_cast<uintptr_t>(&testStr[0]);
    ASSERT_TRUE(memory->ReadString(addrStr, &resultStr, sizeof(testStr)/sizeof(char), false));
    ASSERT_EQ(testStr, resultStr);
    ASSERT_EQ(memory->ReadUleb128(addr), 1U);
    ASSERT_EQ(memory->ReadSleb128(addr), 2);
    ASSERT_EQ(memory->ReadSleb128(invalidAddr), 0);
    GTEST_LOG_(INFO) << "DfxMemoryTest015: end.";
}
}
} // namespace HiviewDFX
} // namespace OHOS
