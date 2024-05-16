/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#include <dlfcn.h>
#include <securec.h>

#include <ctime>
#include <cstdio>
#include <fstream>
#include <memory>
#include <string>
#include <vector>

#include <fcntl.h>
#include <unistd.h>

#include <sys/stat.h>
#include <sys/types.h>

#include "string_ex.h"

#include "dfx_elf.h"
#include "dfx_log.h"
#include "dfx_memory.h"
#include "dwarf_cfa_instructions.h"
#include "dwarf_define.h"
#include "dwarf_op.h"
#include "dwarf_section.h"
#include "unwind_arm64_define.h"

using namespace OHOS::HiviewDFX;
using namespace testing::ext;
using namespace std;
#define HEX 16
#define STACK_VALUE (-8)

namespace OHOS {
namespace HiviewDFX {
class DwarfTest : public testing::Test {
public:
    static void SetUpTestCase(void)
    {
        InitDebugFd(STDOUT_FILENO);
    };

    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};

class DwarfSectionTest : public DwarfSection {
public:
    explicit DwarfSectionTest(std::shared_ptr<DfxMemory> memory) : DwarfSection(memory) {};
    ~DwarfSectionTest() {};
    bool ParseFdeTest(uintptr_t addr, FrameDescEntry &fde)
    {
        return ParseFde(addr, addr, fde);
    };

    bool ParseCieTest(uintptr_t cieAddr, CommonInfoEntry &cieInfo)
    {
        return ParseCie(cieAddr, cieAddr, cieInfo);
    };
};

struct MemoryArea {
    MemoryArea(uintptr_t addr, std::vector<uint8_t> buffer)
    {
        this->addr = addr;
        this->data = buffer;
    }
    uintptr_t addr;
    std::vector<uint8_t> data;
};

class DfxMemoryTest : public DfxMemory {
public:
    DfxMemoryTest() {};
    virtual ~DfxMemoryTest() {};
    size_t Read(uintptr_t& addr, void* val, size_t size, bool incre = false) override;
    void SetBuffer(uintptr_t addr, std::vector<uint8_t> buffer);
    void Reset();
    bool increaseAddr = false;

private:
    std::vector<MemoryArea> buffers;
};

void DfxMemoryTest::Reset()
{
    buffers.clear();
}

size_t DfxMemoryTest::Read(uintptr_t& addr, void* val, size_t size, bool incre)
{
    printf("DfxMemoryTest::Request Read:%" PRIxPTR " size:%zu\n", addr, size);
    for (const auto& buffer : buffers) {
        if (addr >= buffer.addr &&
            addr + size <= buffer.addr + buffer.data.size()) {
            size_t offset = addr - buffer.addr;
            auto data = const_cast<uint8_t*>(buffer.data.data());
            (void)memcpy_s(val, size, data + offset, size);
            if (increaseAddr) {
                addr = addr + size;
            }
            printf("DfxMemoryTest::Read addr:0x%" PRIxPTR "\n", addr);
            return size;
        }
    }
    return 0;
}

void DfxMemoryTest::SetBuffer(uintptr_t addr, std::vector<uint8_t> buffer)
{
    printf("DfxMemoryTest::SetBuffer:%" PRIxPTR " size:%zu\n", addr, buffer.size());
    buffers.push_back({addr, buffer});
}

class DwarfOpTest : public DwarfOp<uintptr_t> {
public:
    using DwarfOp<uintptr_t>::DwarfOp;
    bool Test01();
    bool Test02();
    bool Test03();
    bool Test04(std::shared_ptr<DfxMemoryTest> memory);
    bool Test05(std::shared_ptr<DfxMemoryTest> memory);
    bool Test06();
    bool Test07();
    bool Test08();
    bool Test09(std::shared_ptr<DfxMemoryTest> memory);
    bool Test10(std::shared_ptr<DfxMemoryTest> memory);
    friend class DwarfTest;
};

bool DwarfOpTest::Test01()
{
    std::shared_ptr<DfxRegs> regs = std::make_shared<DfxRegsArm64>();
    uintptr_t addr = 0;
    return Eval(*(regs.get()), 0, addr);
}

bool DwarfOpTest::Test02()
{
    bool ret = false;
    const uintptr_t value = 10;
    StackPush(value);
    ret = (value == stack_.front());
    StackReset(0);
    ret &= (0 == stack_.front());
    return ret;
}

bool DwarfOpTest::Test03()
{
    StackReset(0);
    bool ret = false;
    const uintptr_t value = 10;
    StackPush(value);
    ret = (value == StackPop());
    ret &= (StackAt(0) == 0);
    ret &= (StackSize() == 1);
    return ret;
}

bool DwarfOpTest::Test04(std::shared_ptr<DfxMemoryTest> memory)
{
    // OpDerefSize
    bool ret = false;
    StackReset(0);
    std::vector<uint8_t> exprData {
        0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09
    };

    std::vector<uint8_t> valueData {
        0x08, // U8
        0x10, 0x11, // U16
        0x20, 0x21, 0x22, 0x23, // U32
        0x31, 0x32, 0x33, 0x34, // U32
        0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48,  // U64
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x24,  // U64
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x25,  // U64
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x26,  // U64
    };

    uintptr_t exprPtr = reinterpret_cast<uintptr_t>(exprData.data());
    uintptr_t valuePtr = reinterpret_cast<uintptr_t>(valueData.data());
    memory->SetBuffer(valuePtr, valueData);
    memory->SetBuffer(exprPtr, exprData);
    printf("Test04 exprPtr:%" PRIxPTR " valuePtr:%" PRIxPTR "\n", exprPtr, valuePtr);

    // u8
    StackPush(valuePtr);
    OpDerefSize(exprPtr);
    uintptr_t value = StackPop();
    uintptr_t expectedValue = 0x08;
    ret = (value == expectedValue);
    printf("Test04-u8 value:%" PRIxPTR " expectedValue:%" PRIxPTR "\n", value, expectedValue);

    // u16
    valuePtr = valuePtr + sizeof(uint8_t);
    exprPtr = exprPtr + sizeof(uint8_t);
    StackPush(valuePtr);
    OpDerefSize(exprPtr);
    value = StackPop();
    expectedValue = 0x1110;
    ret &= (value == expectedValue);
    printf("Test04-u16 value:%" PRIxPTR " expectedValue:%" PRIxPTR "\n", value, expectedValue);

    // u32
    valuePtr = valuePtr + sizeof(uint16_t);
    exprPtr = exprPtr + sizeof(uint8_t);
    StackPush(valuePtr);
    OpDerefSize(exprPtr);
    value = StackPop();
    expectedValue = 0x23222120;
    ret &= (value == expectedValue);
    printf("Test04-u32-0 value:%" PRIxPTR " expectedValue:%" PRIxPTR "\n", value, expectedValue);

    // u32
    valuePtr = valuePtr + sizeof(uint32_t);
    exprPtr = exprPtr + sizeof(uint8_t);
    StackPush(valuePtr);
    OpDerefSize(exprPtr);
    value = StackPop();
    expectedValue = 0x34333231;
    ret &= (value == expectedValue);
    printf("Test04-u32-1 value:%" PRIxPTR " expectedValue:%" PRIxPTR "\n", value, expectedValue);

    // u64
    valuePtr = valuePtr + sizeof(uint32_t);
    exprPtr = exprPtr + sizeof(uint8_t);
    StackPush(valuePtr);
    OpDerefSize(exprPtr);
    value = StackPop();
    expectedValue = 0x4847464544434241;
    ret &= (value == expectedValue);
    printf("Test04-u64-0 value:%" PRIxPTR " expectedValue:%" PRIxPTR "\n", value, expectedValue);
    return ret;
}

bool DwarfOpTest::Test05(std::shared_ptr<DfxMemoryTest> memory)
{
    bool ret = false;
    StackReset(0);
    memory->Reset();
    std::vector<uint8_t> valueData {
        0x31, 0x32, 0x33, 0x34, 0x31, 0x32, 0x33, 0x34,
    };
    // OpDeref
    uintptr_t valuePtr = reinterpret_cast<uintptr_t>(valueData.data());
    memory->SetBuffer(valuePtr, valueData);
    OpPush(valuePtr);
    OpDeref();
    uintptr_t value = StackPop();
    uintptr_t expectedValue = 0x3433323134333231;
    printf("Test05-u64 value:%" PRIxPTR " expectedValue:%" PRIxPTR "\n", value, expectedValue);
    ret = (value == expectedValue);
    printf("Test05-01 %d\n", ret);
    OpPush(valuePtr);
    OpDup();
    ret &= (StackAt(0) == valuePtr);
    printf("Test05-02 %d\n", ret);
    ret &= (StackAt(1) == valuePtr);
    printf("Test05-03 %d\n", ret);
    return ret;
}

bool DwarfOpTest::Test06()
{
    // OpDrop OpOver OpSwap OpRot
    MAYBE_UNUSED bool ret = false;
    StackReset(0);
    ret = (StackSize() == 1);
    OpPush(1);
    ret &= (StackSize() == 2); // 2:stack_.size()

    OpDrop();
    ret &= (StackSize() == 1);

    OpPush(1);
    OpPush(2); // 2:stack_.index
    ret &= (StackSize() == 3); // 3:stack_.size()

    OpOver();
    ret &= (StackSize() == 4); // 4:stack_.size()
    uintptr_t value = StackPop();
    ret &= (value == 1);
    ret &= (StackSize() == 3); // 3:stack_.size()

    ret &= (StackAt(0) == 2); // 2:stack.value
    ret &= (StackAt(1) == 1);
    OpSwap();
    ret &= (StackAt(0) == 1);
    ret &= (StackAt(1) == 2); // 2:stack.value

    OpRot();
    ret &= (StackAt(0) == 0);
    ret &= (StackAt(1) == 1);
    ret &= (StackAt(2) == 2); // 2:stack.value
    return true;
}

bool DwarfOpTest::Test07()
{
    bool ret = false;
    StackReset(0);
    intptr_t value = -10;
    StackPush(value);
    OpAbs();
    ret = (static_cast<uintptr_t>(-value) == StackPop());

    StackReset(0);
    StackPush(0x1122334455667788);
    StackPush(0xFFFFFFFF00000000);
    OpAnd();
    ret &= (0x1122334400000000 == StackPop());

    StackReset(0);
    StackPush(0x8);
    StackPush(0x2);
    OpDiv();
    ret &= (0x4 == StackPop());

    StackReset(0);
    StackPush(0x8);
    StackPush(0x2);
    OpMinus();
    ret &= (0x6 == StackPop());

    StackReset(0);
    StackPush(0x8);
    StackPush(0x2);
    OpMod();
    ret &= (0 == StackPop());

    StackReset(0);
    StackPush(0x8);
    StackPush(0x2);
    OpMul();
    ret &= (0x10 == StackPop());

    StackReset(0);
    StackPush(0x8);
    OpNeg();
    ret &= (static_cast<uintptr_t>(STACK_VALUE) == StackPop());

    StackReset(0);
    StackPush(1);
    OpNot();
    ret &= (static_cast<uintptr_t>(~1) == StackPop());
    return ret;
}

bool DwarfOpTest::Test08()
{
    bool ret = false;
    StackReset(0);
    StackPush(0x2);
    StackPush(0x2);
    OpEQ();
    ret = (1 == StackPop());

    StackReset(0);
    StackPush(0x2);
    StackPush(0x3);
    OpGE();
    ret &= (0 == StackPop());

    StackReset(0);
    StackPush(0x2);
    StackPush(0x3);
    OpGT();
    ret &= (0 == StackPop());

    StackReset(0);
    StackPush(0x2);
    StackPush(0x3);
    OpLE();
    ret &= (1 == StackPop());

    StackReset(0);
    StackPush(0x2);
    StackPush(0x3);
    OpLT();
    ret &= (1 == StackPop());

    StackReset(0);
    StackPush(0x2);
    StackPush(0x3);
    OpNE();
    ret &= (1 == StackPop());
    return ret;
}

bool DwarfOpTest::Test09(std::shared_ptr<DfxMemoryTest> memory)
{
    bool ret = false;
    StackReset(0);
    memory->Reset();
    std::vector<uint8_t> exprData {
        0x10, 0x00,
    };
    uintptr_t exprPtr = reinterpret_cast<uintptr_t>(exprData.data());
    memory->SetBuffer(exprPtr, exprData);
    OpPlusULEBConst(exprPtr);
    uintptr_t value = StackPop();
    printf("Test09-01 value:%" PRIxPTR "\n", value);
    ret = (value == 0x10);

    StackReset(0);
    uintptr_t exprPtrOld = exprPtr;
    OpSkip(exprPtr);
    ret &= (exprPtrOld + exprData[0] == exprPtr);
    printf("Test09-02 exprPtrOld:%" PRIxPTR " exprPtrNew:%" PRIxPTR "\n",
        exprPtrOld, exprPtr);

    StackReset(0);
    StackPush(0x2);
    exprPtr = exprPtrOld;
    OpBra(exprPtr);
    ret &= (exprPtrOld + exprData[0] == exprPtr);
    printf("Test09-03 exprPtrOld:%" PRIxPTR " exprPtrNew:%" PRIxPTR "\n",
        exprPtrOld, exprPtr);

    StackReset(0);
    exprPtr = exprPtrOld;
    OpBra(exprPtr);
    ret &= (exprPtrOld == exprPtr);
    printf("Test09-04 exprPtrOld:%" PRIxPTR " exprPtrNew:%" PRIxPTR "\n",
        exprPtrOld, exprPtr);
    return ret;
}

bool DwarfOpTest::Test10(std::shared_ptr<DfxMemoryTest> memory)
{
    bool ret = false;
    memory->Reset();
    std::vector<uint8_t> exprData {
        0x1e, 0x00,
    };
    uintptr_t exprPtr = reinterpret_cast<uintptr_t>(exprData.data());
    memory->SetBuffer(exprPtr, exprData);

    StackReset(0);
    OpLit(DW_OP_lit1);
    uintptr_t value = StackPop();
    ret = (value == 0x01);
    printf("Test10-01 value:%" PRIxPTR " ret:%d\n", value, ret);

    OpLit(DW_OP_lit31);
    value = StackPop();
    ret &= (value == 0x1f);
    printf("Test10-02 value:%" PRIxPTR " ret:%d\n", value, ret);

    StackReset(0);
    auto reg = std::make_shared<DfxRegsArm64>();
    (*reg)[0] = 0xa;
    OpReg(DW_OP_reg0, *(reg.get()));
    value = StackPop();
    ret &= (value == 0xa);
    printf("Test10-03 value:%" PRIxPTR " ret:%d\n", value, ret);

    StackReset(0);
    (*reg)[0x1e] = 0x14;
    OpRegx(exprPtr, *(reg.get()));
    value = StackPop();
    ret &= (value == 0x14);
    printf("Test10-04 value:%" PRIxPTR " ret:%d\n", value, ret);

    StackReset(0);
    OpBReg(DW_OP_breg0, exprPtr, *(reg.get()));
    value = StackPop();
    ret &= (value == 0x28); // 0xa + 0x1e
    printf("Test10-05 value:%" PRIxPTR " ret:%d\n", value, ret);

    StackReset(0);
    OpBRegx(exprPtr, *(reg.get()));
    value = StackPop();
    ret &= (value == 0x32); // 0x14 + 0x1e
    printf("Test10-06 value:%" PRIxPTR " ret:%d\n", value, ret);
    return ret;
}

using RequestFdFunc = int32_t (*)(int32_t);
namespace {
/**
 * @tc.name: DwarfTest001
 * @tc.desc: test parse fde in libfaultloggerd_client.so
 * @tc.type: FUNC
 */
HWTEST_F(DwarfTest, DwarfTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DwarfTest001: start.";
    void* handle = dlopen("libfaultloggerd.z.so", RTLD_LAZY | RTLD_NODELETE);
    if (handle == nullptr) {
        printf("Failed to dlopen libfaultloggerd, %s\n", dlerror());
        return;
    }

    // 00000000000037e4   156 FUNC    GLOBAL DEFAULT   14 RequestFileDescriptor
    RequestFdFunc requestFdFunc = (RequestFdFunc)dlsym(handle, "RequestFileDescriptor");
    if (requestFdFunc == nullptr) {
        printf("Failed to find RequestFdFunc, %s\n", dlerror());
        return;
    }

    const uintptr_t pcOffset = 32;
    uintptr_t pc = reinterpret_cast<uintptr_t>(requestFdFunc) + pcOffset;
    struct UnwindTableInfo uti;
    ASSERT_EQ(DfxElf::FindUnwindTableLocal(pc, uti), 0);

    auto acc = std::make_shared<DfxAccessorsLocal>();
    auto memory = std::make_shared<DfxMemory>(acc);
    DwarfSectionTest dwarfSection(memory);
    struct UnwindEntryInfo pi;
    ASSERT_EQ(true, dwarfSection.SearchEntry(pc, uti, pi));

    FrameDescEntry fde;
    ASSERT_EQ(true, dwarfSection.ParseFdeTest(reinterpret_cast<uintptr_t>(pi.unwindInfo), fde));
    ASSERT_GT(fde.cieAddr, 0);

    CommonInfoEntry cie;
    ASSERT_EQ(true, dwarfSection.ParseCieTest(fde.cieAddr, cie));

    RegLocState rsState;
    DwarfCfaInstructions instructions(memory);
    ASSERT_EQ(true, instructions.Parse(pc, fde, rsState));
    /*
        Version:               1
        Augmentation:          "zR"
        Code alignment factor: 1
        Data alignment factor: -4
        Return address column: 30
        Augmentation data:     1b
        DW_CFA_def_cfa: r31 (sp) ofs 0
        DW_CFA_nop
        DW_CFA_nop
        DW_CFA_nop
        DW_CFA_nop
    */
    ASSERT_EQ(cie.codeAlignFactor, 1);
    ASSERT_EQ(cie.dataAlignFactor, -4);
    ASSERT_EQ(cie.returnAddressRegister, 30);
    ASSERT_EQ(cie.hasAugmentationData, true);
    ASSERT_EQ(cie.pointerEncoding, 0x1b);

    /*
        DW_CFA_advance_loc: 20 to 0000000000003680
        DW_CFA_def_cfa_offset: 80
        DW_CFA_advance_loc: 12 to 000000000000368c
        DW_CFA_def_cfa: r29 (x29) ofs 32
        DW_CFA_offset: r15 (x15) at cfa-8
        DW_CFA_offset: r19 (x19) at cfa-16
        DW_CFA_offset: r30 (x30) at cfa-24
        DW_CFA_offset: r29 (x29) at cfa-32
    */
    ASSERT_EQ(fde.pcStart, reinterpret_cast<uintptr_t>(requestFdFunc));
    ASSERT_EQ(rsState.cfaReg, REG_AARCH64_X29);
    ASSERT_EQ(rsState.cfaRegOffset, 32); // 32 : DW_CFA_def_cfa: r29 (x29) ofs 32

    size_t qutIdx = 0;
    if (DfxRegsQut::IsQutReg(static_cast<uint16_t>(REG_AARCH64_X30), qutIdx)) {
        ASSERT_EQ(static_cast<uint8_t>(rsState.locs[qutIdx].type),
            static_cast<uint8_t>(REG_LOC_MEM_OFFSET));
        ASSERT_EQ(rsState.locs[qutIdx].val, -24); // -24: r30 (x30) at cfa-24
    }
    if (DfxRegsQut::IsQutReg(static_cast<uint16_t>(REG_AARCH64_X29), qutIdx)) {
        ASSERT_EQ(static_cast<uint8_t>(rsState.locs[qutIdx].type),
            static_cast<uint8_t>(REG_LOC_MEM_OFFSET));
        ASSERT_EQ(rsState.locs[qutIdx].val, -32); // -32: r29 (x29) at cfa-32
    }

    RegLocState rsState2;
    ASSERT_EQ(true, instructions.Parse(reinterpret_cast<uintptr_t>(requestFdFunc), fde, rsState2));
    ASSERT_EQ(rsState2.cfaReg, REG_AARCH64_X31);
    ASSERT_EQ(rsState2.cfaRegOffset, 0); // DW_CFA_def_cfa: r31 (sp) ofs 0

    RegLocState rsState3;
    ASSERT_EQ(true, instructions.Parse(reinterpret_cast<uintptr_t>(requestFdFunc) + 24, fde, rsState3));
    ASSERT_EQ(rsState3.cfaReg, REG_AARCH64_X31);
    ASSERT_EQ(rsState3.cfaRegOffset, 80); // DW_CFA_def_cfa_offset: 80
    GTEST_LOG_(INFO) << "DwarfTest001: end.";
}

struct FdeParseResult {
    int32_t index;
    uintptr_t relPcStart;
    uintptr_t relPcEnd;
    std::vector<std::string> operateResult;
};

static std::vector<std::string> cieResult = {
    "DW_CFA_def_cfa: r31 ofs 0",
    "DW_CFA_nop",
    "DW_CFA_nop",
    "DW_CFA_nop",
    "DW_CFA_nop"
};

/**
 * @tc.name: DwarfTest003
 * @tc.desc: test dwarf operations
 * @tc.type: FUNC
 */
HWTEST_F(DwarfTest, DwarfTest003, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DwarfTest003: start.\n";
    auto memory = std::make_shared<DfxMemoryTest>();
    DwarfOpTest op(memory);
    ASSERT_EQ(op.Test01(), false);
    ASSERT_EQ(op.Test02(), true);
    ASSERT_EQ(op.Test03(), true);
    ASSERT_EQ(op.Test04(memory), true);
    ASSERT_EQ(op.Test05(memory), true);
    ASSERT_EQ(op.Test06(), true);
    ASSERT_EQ(op.Test07(), true);
    ASSERT_EQ(op.Test08(), true);
    ASSERT_EQ(op.Test09(memory), true);
    ASSERT_EQ(op.Test10(memory), true);
    GTEST_LOG_(INFO) << "DwarfTest003: end.\n";
}

/**
 * @tc.name: DwarfTest004
 * @tc.desc: test dwarf DW_OP_reserved oprations
 * @tc.type: FUNC
 */
HWTEST_F(DwarfTest, DwarfTest004, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DwarfTest004: start.\n";
    auto memory = std::make_shared<DfxMemoryTest>();
    memory->increaseAddr = true;
    DwarfOpTest op(memory);
    std::vector<uint8_t> opcodes = {
        0x08, // size
        0x01, 0x02, 0x04, 0x05, 0x07, // DW_OP_reserved
        0x01, 0x02, 0x04, 0x05, 0x07, // DW_OP_reserved
    };
    uintptr_t exprPtr = reinterpret_cast<uintptr_t>(opcodes.data());
    memory->SetBuffer(exprPtr, opcodes);
    auto reg = std::make_shared<DfxRegsArm64>();
    auto ret = op.Eval(*reg.get(), 0, exprPtr);
    ASSERT_EQ(ret, 0);
    printf("DwarfTest004:%" PRIxPTR "\n", ret);
    GTEST_LOG_(INFO) << "DwarfTest004: end.\n";
}

/**
 * @tc.name: DwarfTest005
 * @tc.desc: test dwarf DW_OP_addr oprations
 * @tc.type: FUNC
 */
HWTEST_F(DwarfTest, DwarfTest005, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DwarfTest005: start.\n";
    auto memory = std::make_shared<DfxMemoryTest>();
    memory->increaseAddr = true;
    DwarfOpTest op(memory);
    std::vector<uint8_t> opcodes = {
        0x0a, // size
        DW_OP_addr, // DW_OP_addr
        0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        DW_OP_deref, 0x01, 0x01, 0x01, 0x01, // DW_OP_deref
    };

    std::vector<uint8_t> data = {
        0x02, 0x04, 0x05, 0x07,
        0x02, 0x04, 0x05, 0x07,
    };

    uintptr_t exprPtr = reinterpret_cast<uintptr_t>(opcodes.data());
    memory->SetBuffer(exprPtr, opcodes);
    memory->SetBuffer(0x4, data);

    auto reg = std::make_shared<DfxRegsArm64>();
    uintptr_t ret = op.Eval(*reg.get(), 0, exprPtr);
    ASSERT_EQ(ret, 0x0705040207050402);
    printf("DwarfTest005:%" PRIxPTR "\n", ret);
    GTEST_LOG_(INFO) << "DwarfTest005: end.\n";
}

/**
 * @tc.name: DwarfTest006
 * @tc.desc: test dwarf DW_OP_const oprations
 * @tc.type: FUNC
 */
HWTEST_F(DwarfTest, DwarfTest006, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DwarfTest006: start.\n";
    auto memory = std::make_shared<DfxMemoryTest>();
    memory->increaseAddr = true;
    DwarfOpTest op(memory);
    std::vector<uint8_t> opcodes = {
        0x2a, // size
        DW_OP_constu, 0x01,
        DW_OP_consts, 0x01,
        DW_OP_const1u, 0x01,
        DW_OP_const1s, 0x02,
        DW_OP_const2u, 0x03, 0x04,
        DW_OP_const2s, 0x04, 0x04,
        DW_OP_const4u, 0x03, 0x04, 0x03, 0x04,
        DW_OP_const4s, 0x04, 0x04, 0x03, 0x04,
        DW_OP_const8u,
        0x03, 0x04, 0x03, 0x04, 0x03, 0x04, 0x03, 0x04,
        DW_OP_const8s,
        0x03, 0x04, 0x03, 0x04, 0x03, 0x04, 0x03, 0x04,
        0x01, 0x01, 0x01, 0x01,
    };

    uintptr_t exprPtr = reinterpret_cast<uintptr_t>(opcodes.data());
    memory->SetBuffer(exprPtr, opcodes);
    auto reg = std::make_shared<DfxRegsArm64>();
    uintptr_t ret = op.Eval(*reg.get(), 0, exprPtr);
    ASSERT_EQ(ret, 0x0403040304030403);
    printf("DwarfTest006:%" PRIxPTR "\n", ret);
    GTEST_LOG_(INFO) << "DwarfTest006: end.\n";
}

/**
 * @tc.name: DwarfTest007
 * @tc.desc: test dwarf DW_OP_litxx oprations
 * @tc.type: FUNC
 */
HWTEST_F(DwarfTest, DwarfTest007, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DwarfTest007: start.\n";
    auto memory = std::make_shared<DfxMemoryTest>();
    memory->increaseAddr = true;
    DwarfOpTest op(memory);
    std::vector<uint8_t> opcodes = {
        0x20, // size
        DW_OP_lit0,
        DW_OP_lit1, DW_OP_lit2, DW_OP_lit3, DW_OP_lit4,
        DW_OP_lit5, DW_OP_lit6, DW_OP_lit7, DW_OP_lit8,
        DW_OP_lit9, DW_OP_lit10, DW_OP_lit11, DW_OP_lit12,
        DW_OP_lit13, DW_OP_lit14, DW_OP_lit15, DW_OP_lit16,
        DW_OP_lit17, DW_OP_lit18, DW_OP_lit19, DW_OP_lit20,
        DW_OP_lit21, DW_OP_lit22, DW_OP_lit23, DW_OP_lit24,
        DW_OP_lit25, DW_OP_lit26, DW_OP_lit27, DW_OP_lit28,
        DW_OP_lit29, DW_OP_lit30, DW_OP_lit31,
        0x01, 0x01, 0x01, 0x01,
    };

    uintptr_t exprPtr = reinterpret_cast<uintptr_t>(opcodes.data());
    memory->SetBuffer(exprPtr, opcodes);
    auto reg = std::make_shared<DfxRegsArm64>();
    uintptr_t ret = op.Eval(*reg.get(), 0, exprPtr);
    ASSERT_EQ(ret, static_cast<uintptr_t>(DW_OP_lit31 - DW_OP_lit0));
    printf("DwarfTest007:%" PRIxPTR "\n", ret);
    GTEST_LOG_(INFO) << "DwarfTest007: end.\n";
}

/**
 * @tc.name: DwarfTest008
 * @tc.desc: test dwarf DW_OP_regxx oprations
 * @tc.type: FUNC
 */
HWTEST_F(DwarfTest, DwarfTest008, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DwarfTest008: start.\n";
    auto memory = std::make_shared<DfxMemoryTest>();
    memory->increaseAddr = true;
    DwarfOpTest op(memory);
    std::vector<uint8_t> opcodes = {
        0x20, // size
        DW_OP_reg0,
        DW_OP_reg1, DW_OP_reg2, DW_OP_reg3, DW_OP_reg4,
        DW_OP_reg5, DW_OP_reg6, DW_OP_reg7, DW_OP_reg8,
        DW_OP_reg9, DW_OP_reg10, DW_OP_reg11, DW_OP_reg12,
        DW_OP_reg13, DW_OP_reg14, DW_OP_reg15, DW_OP_reg16,
        DW_OP_reg17, DW_OP_reg18, DW_OP_reg19, DW_OP_reg20,
        DW_OP_reg21, DW_OP_reg22, DW_OP_reg23, DW_OP_reg24,
        DW_OP_reg25, DW_OP_reg26, DW_OP_reg27, DW_OP_reg28,
        DW_OP_reg29, DW_OP_reg30, DW_OP_reg31,
        0x01, 0x01, 0x01, 0x01,
    };

    uintptr_t exprPtr = reinterpret_cast<uintptr_t>(opcodes.data());
    memory->SetBuffer(exprPtr, opcodes);
    auto reg = std::make_shared<DfxRegsArm64>();
    const uintptr_t result = 0x5544332211;
    (*reg)[DW_OP_reg31 - DW_OP_reg0] = result;
    uintptr_t ret = op.Eval(*reg.get(), 0, exprPtr);
    ASSERT_EQ(ret, result);
    printf("DwarfTest008:%" PRIxPTR "\n", ret);
    GTEST_LOG_(INFO) << "DwarfTest008: end.\n";
}

/**
 * @tc.name: DwarfTest009
 * @tc.desc: test dwarf DW_OP_nop oprations
 * @tc.type: FUNC
 */
HWTEST_F(DwarfTest, DwarfTest009, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DwarfTest009: start.\n";
    auto memory = std::make_shared<DfxMemoryTest>();
    memory->increaseAddr = true;
    DwarfOpTest op(memory);
    std::vector<uint8_t> opcodes = {
        0x0a, // size
        DW_OP_fbreg,
        DW_OP_piece,
        DW_OP_xderef,
        DW_OP_xderef_size,
        DW_OP_nop,
        DW_OP_push_object_address,
        DW_OP_call2,
        DW_OP_call4,
        DW_OP_call_ref,
        DW_OP_lo_user,
        0x01, 0x01, 0x01, 0x01,
    };
    uintptr_t exprPtr = reinterpret_cast<uintptr_t>(opcodes.data());
    memory->SetBuffer(exprPtr, opcodes);
    auto reg = std::make_shared<DfxRegsArm64>();
    uintptr_t ret = op.Eval(*reg.get(), 0, exprPtr);
    ASSERT_EQ(ret, 0);
    printf("DwarfTest009:%" PRIxPTR "\n", ret);
    GTEST_LOG_(INFO) << "DwarfTest009: end.\n";
}

/**
 * @tc.name: DwarfTest010
 * @tc.desc: test dwarf numerical oprations
 * @tc.type: FUNC
 */
HWTEST_F(DwarfTest, DwarfTest010, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DwarfTest010: start.\n";
    auto memory = std::make_shared<DfxMemoryTest>();
    memory->increaseAddr = true;
    DwarfOpTest op(memory);
    std::vector<uint8_t> opcodes = {
        0x09, // size
        DW_OP_lit31,
        DW_OP_dup,
        DW_OP_dup,
        DW_OP_swap,
        DW_OP_rot,
        DW_OP_abs,
        DW_OP_and,
        DW_OP_div,
        0x01, 0x01, 0x01, 0x01,
    };
    uintptr_t exprPtr = reinterpret_cast<uintptr_t>(opcodes.data());
    memory->SetBuffer(exprPtr, opcodes);
    auto reg = std::make_shared<DfxRegsArm64>();
    uintptr_t ret = op.Eval(*reg.get(), 0, exprPtr);
    ASSERT_EQ(ret, 1);
    printf("DwarfTest010:%" PRIxPTR "\n", ret);
    GTEST_LOG_(INFO) << "DwarfTest010: end.\n";
}


/**
 * @tc.name: DwarfTest011
 * @tc.desc: test dwarf numerical oprations 2
 * @tc.type: FUNC
 */
HWTEST_F(DwarfTest, DwarfTest011, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DwarfTest011: start.\n";
    auto memory = std::make_shared<DfxMemoryTest>();
    memory->increaseAddr = true;
    DwarfOpTest op(memory);
    std::vector<uint8_t> opcodes = {
        0x05, // size
        DW_OP_lit31,
        DW_OP_dup,
        DW_OP_over,
        DW_OP_drop,
        DW_OP_minus,
        0x01, 0x01, 0x01, 0x01,
    };
    uintptr_t exprPtr = reinterpret_cast<uintptr_t>(opcodes.data());
    memory->SetBuffer(exprPtr, opcodes);
    auto reg = std::make_shared<DfxRegsArm64>();
    uintptr_t ret = op.Eval(*reg.get(), 0, exprPtr);
    ASSERT_EQ(ret, 0);
    printf("DwarfTest011:%" PRIxPTR "\n", ret);
    GTEST_LOG_(INFO) << "DwarfTest011: end.\n";
}

/**
 * @tc.name: DwarfTest012
 * @tc.desc: test dwarf numerical oprations 3
 * @tc.type: FUNC
 */
HWTEST_F(DwarfTest, DwarfTest012, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DwarfTest012: start.\n";
    auto memory = std::make_shared<DfxMemoryTest>();
    memory->increaseAddr = true;
    DwarfOpTest op(memory);
    std::vector<uint8_t> opcodes = {
        0x09, // size
        DW_OP_lit5,
        DW_OP_lit2,
        DW_OP_mod, // 5 % 2
        DW_OP_lit2,
        DW_OP_mul, // 1 * 2
        DW_OP_lit2,
        DW_OP_plus, // 2 + 2
        DW_OP_lit4,
        DW_OP_eq,
        0x01, 0x01, 0x01, 0x01,
    };
    uintptr_t exprPtr = reinterpret_cast<uintptr_t>(opcodes.data());
    memory->SetBuffer(exprPtr, opcodes);
    auto reg = std::make_shared<DfxRegsArm64>();
    uintptr_t ret = op.Eval(*reg.get(), 0, exprPtr);
    ASSERT_EQ(ret, 1);
    printf("DwarfTest012:%" PRIxPTR "\n", ret);
    GTEST_LOG_(INFO) << "DwarfTest012: end.\n";
}

/**
 * @tc.name: DwarfTest013
 * @tc.desc: test dwarf logical oprations
 * @tc.type: FUNC
 */
HWTEST_F(DwarfTest, DwarfTest013, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DwarfTest013: start.\n";
    auto memory = std::make_shared<DfxMemoryTest>();
    memory->increaseAddr = true;
    DwarfOpTest op(memory);
    std::vector<uint8_t> opcodes = {
        0x0a, // size
        DW_OP_lit1, // 1
        DW_OP_lit1, // 1
        DW_OP_shl,  // 1 << 1
        DW_OP_lit1, // 1
        DW_OP_shr,  // 2 >> 1
        DW_OP_lit1, // 1
        DW_OP_shra, // 1
        DW_OP_xor,  // 0
        DW_OP_lit1, // 1
        DW_OP_eq,   // 0
        0x01, 0x01, 0x01, 0x01,
    };
    uintptr_t exprPtr = reinterpret_cast<uintptr_t>(opcodes.data());
    memory->SetBuffer(exprPtr, opcodes);
    auto reg = std::make_shared<DfxRegsArm64>();
    uintptr_t ret = op.Eval(*reg.get(), 0, exprPtr);
    ASSERT_EQ(ret, 0);
    printf("DwarfTest013:%" PRIxPTR "\n", ret);
    GTEST_LOG_(INFO) << "DwarfTest013: end.\n";
}
}
} // namespace HiviewDFX
} // namespace OHOS
