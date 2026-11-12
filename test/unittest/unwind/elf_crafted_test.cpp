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
#include <sys/mman.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "dfx_elf.h"
#include "dfx_errors.h"
#include "dfx_map.h"
#include "dfx_mmap.h"
#include "elf_craft_builder.h"
#include "unwind_context.h"

using namespace OHOS::HiviewDFX;
using namespace testing::ext;

namespace OHOS {
namespace HiviewDFX {
namespace {
std::shared_ptr<DfxElf> MakeCraftedElf(const CraftedElfOptions& opt)
{
    auto image = ElfCraftBuilder::Build(opt);
    auto mmap = std::make_shared<DfxMmap>();
    if (!mmap->Init(std::move(image))) {
        return nullptr;
    }
    return std::make_shared<DfxElf>(mmap);
}

std::shared_ptr<DfxMap> MakeCraftedMap()
{
    return std::make_shared<DfxMap>(0, 0x10000, 0, PROT_READ | PROT_EXEC, "crafted.so");
}

CraftedElfOptions::ExtraSection MakeSection(const std::string& name, size_t size, bool bogusOffset = false)
{
    CraftedElfOptions::ExtraSection section;
    section.name = name;
    section.addr = 0x5000;
    section.data.assign(size, 0);
    section.bogusOffset = bogusOffset;
    return section;
}
} // namespace

class ElfCraftedTest : public testing::Test {};

/**
 * @tc.name: ElfCraftedTest001
 * @tc.desc: test IsValidPc with an explicit runtime range
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest001: start.";
    CraftedElfOptions opt;
    auto elf = MakeCraftedElf(opt);
    ASSERT_NE(elf, nullptr);
    ASSERT_TRUE(elf->IsValid());
    EXPECT_FALSE(elf->HasRuntimeRange());
    elf->SetRuntimeRange(0x1000, 0x2000);
    EXPECT_TRUE(elf->HasRuntimeRange());
    EXPECT_EQ(elf->GetRuntimeStart(), 0x1000U);
    EXPECT_EQ(elf->GetRuntimeEnd(), 0x2000U);
    EXPECT_TRUE(elf->IsValidPc(0x1000));
    EXPECT_TRUE(elf->IsValidPc(0x1fff));
    EXPECT_FALSE(elf->IsValidPc(0xfff));
    EXPECT_FALSE(elf->IsValidPc(0x2000));
    GTEST_LOG_(INFO) << "ElfCraftedTest001: end.";
}

/**
 * @tc.name: ElfCraftedTest002
 * @tc.desc: test IsValidPc falls back to pt loads and honors the load base
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest002: start.";
    CraftedElfOptions opt;
    opt.withLoad = true;
    opt.loadVaddr = 0x3000;
    opt.loadMemSize = 0x40;
    auto elf = MakeCraftedElf(opt);
    ASSERT_NE(elf, nullptr);
    ASSERT_TRUE(elf->IsValid());
    EXPECT_TRUE(elf->IsValidPc(0x3000));
    EXPECT_TRUE(elf->IsValidPc(0x303f));
    EXPECT_FALSE(elf->IsValidPc(0x3040));
    EXPECT_FALSE(elf->IsValidPc(0x2fff));

    elf->SetLoadBase(0x10000);
    EXPECT_TRUE(elf->IsValidPc(0x13020));
    EXPECT_FALSE(elf->IsValidPc(0x3020));
    GTEST_LOG_(INFO) << "ElfCraftedTest002: end.";
}

/**
 * @tc.name: ElfCraftedTest003
 * @tc.desc: test IsValidPc with an invalid elf and with no program headers
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest003, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest003: start.";
    auto mmap = std::make_shared<DfxMmap>();
    ASSERT_TRUE(mmap->Init(ElfCraftBuilder::BuildGarbage(0x40))); // 0x40 : not an ELF
    auto invalidElf = std::make_shared<DfxElf>(mmap);
    EXPECT_FALSE(invalidElf->IsValid());
    EXPECT_FALSE(invalidElf->IsValidPc(0x1000));

    CraftedElfOptions opt;
    opt.withLoad = false; // no program headers: pt loads empty, vaddr range stays unset
    auto elf = MakeCraftedElf(opt);
    ASSERT_NE(elf, nullptr);
    ASSERT_TRUE(elf->IsValid());
    EXPECT_FALSE(elf->IsValidPc(0x1000));
    EXPECT_FALSE(elf->IsValidPc(0));
    GTEST_LOG_(INFO) << "ElfCraftedTest003: end.";
}

/**
 * @tc.name: ElfCraftedTest004
 * @tc.desc: test FindGlobalVariableByName hit, miss and unparsed elf
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest004, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest004: start.";
    CraftedElfOptions opt;
    opt.withObjectSym = true;
    opt.objectVaddr = 0x4000;
    opt.objectName = "__jit_debug_descriptor";
    auto elf = MakeCraftedElf(opt);
    ASSERT_NE(elf, nullptr);

    ElfSymbol symbol;
    // headers not parsed yet: elfParse_ is still null
    EXPECT_FALSE(elf->FindGlobalVariableByName("__jit_debug_descriptor", symbol));
    ASSERT_TRUE(elf->IsValid());
    EXPECT_TRUE(elf->FindGlobalVariableByName("__jit_debug_descriptor", symbol));
    EXPECT_EQ(symbol.value, 0x4000U);
    EXPECT_EQ(symbol.nameStr, "__jit_debug_descriptor");
    EXPECT_FALSE(elf->FindGlobalVariableByName("__not_exist_symbol", symbol));

    CraftedElfOptions noSymOpt;
    auto noSymElf = MakeCraftedElf(noSymOpt);
    ASSERT_NE(noSymElf, nullptr);
    ASSERT_TRUE(noSymElf->IsValid());
    EXPECT_FALSE(noSymElf->FindGlobalVariableByName("__jit_debug_descriptor", symbol));
    GTEST_LOG_(INFO) << "ElfCraftedTest004: end.";
}

/**
 * @tc.name: ElfCraftedTest005
 * @tc.desc: test GetSectionInfo and GetFuncSymbols on a crafted elf
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest005, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest005: start.";
    CraftedElfOptions opt;
    opt.withText = true;
    opt.textVaddr = 0x1000;
    opt.textSize = 0x100;
    opt.withFuncSym = true;
    opt.funcVaddr = 0x1010;
    opt.funcSize = 0x20;
    auto elf = MakeCraftedElf(opt);
    ASSERT_NE(elf, nullptr);
    ASSERT_TRUE(elf->IsValid());

    ShdrInfo textShdr;
    EXPECT_TRUE(elf->GetSectionInfo(textShdr, ".text"));
    EXPECT_EQ(textShdr.addr, 0x1000U);
    EXPECT_EQ(textShdr.size, 0x100U);
    ShdrInfo missing;
    EXPECT_FALSE(elf->GetSectionInfo(missing, ".not_exist"));

    const auto& symbols = elf->GetFuncSymbols();
    ASSERT_EQ(symbols.size(), 1U);
    EXPECT_EQ(symbols.begin()->value, 0x1010U);
    EXPECT_EQ(symbols.begin()->size, 0x20U);
    EXPECT_EQ(symbols.begin()->nameStr, "JitFunc");
    GTEST_LOG_(INFO) << "ElfCraftedTest005: end.";
}

/**
 * @tc.name: ElfCraftedTest006
 * @tc.desc: test FindUnwindTableInfo with a null map and a pc outside the runtime range
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest006, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest006: start.";
    CraftedElfOptions opt;
    opt.loadVaddr = 0;
    opt.loadMemSize = 0x8000;
    auto elf = MakeCraftedElf(opt);
    ASSERT_NE(elf, nullptr);
    ASSERT_TRUE(elf->IsValid());
    elf->SetRuntimeRange(0x1000, 0x2000);

    UnwindTableInfo uti;
    EXPECT_EQ(elf->FindUnwindTableInfo(0x1500, nullptr, uti), UNW_ERROR_INVALID_MAP);
    auto map = MakeCraftedMap();
    EXPECT_EQ(elf->FindUnwindTableInfo(0x2500, map, uti), UNW_ERROR_PC_NOT_IN_UNWIND_INFO);
    EXPECT_EQ(uti.startPc, 0x1000U);
    EXPECT_EQ(uti.endPc, 0x2000U);
    GTEST_LOG_(INFO) << "ElfCraftedTest006: end.";
}

/**
 * @tc.name: ElfCraftedTest007
 * @tc.desc: test FindUnwindTableInfo fills a linear table from .debug_frame
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest007, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest007: start.";
    CraftedElfOptions opt;
    opt.loadVaddr = 0;
    opt.loadMemSize = 0x8000;
    opt.extraSections.push_back(MakeSection(".debug_frame", 0x40)); // 0x40 : section size
    auto elf = MakeCraftedElf(opt);
    ASSERT_NE(elf, nullptr);
    ASSERT_TRUE(elf->IsValid());
    elf->SetRuntimeRange(0x1000, 0x2000);

    ShdrInfo debugFrame;
    ASSERT_TRUE(elf->GetSectionInfo(debugFrame, ".debug_frame"));
    auto map = MakeCraftedMap();
    UnwindTableInfo uti;
    ASSERT_EQ(elf->FindUnwindTableInfo(0x1500, map, uti), UNW_ERROR_NONE);
    EXPECT_TRUE(uti.isDebugFrame);
    EXPECT_TRUE(uti.isLinear);
    EXPECT_EQ(uti.tableLen, ~static_cast<uintptr_t>(0));
    EXPECT_EQ(uti.tableData, static_cast<uintptr_t>(debugFrame.offset));
    EXPECT_EQ(uti.debugFrameEnd, static_cast<uintptr_t>(debugFrame.offset + debugFrame.size));
    EXPECT_EQ(uti.debugFrameMmap, elf->GetMmap());
    EXPECT_EQ(uti.startPc, 0x1000U);
    EXPECT_EQ(uti.endPc, 0x2000U);

    // second lookup inside the cached range returns the cached table
    UnwindTableInfo cached;
    EXPECT_EQ(elf->FindUnwindTableInfo(0x1600, map, cached), UNW_ERROR_NONE);
    EXPECT_TRUE(cached.isDebugFrame);
    GTEST_LOG_(INFO) << "ElfCraftedTest007: end.";
}

/**
 * @tc.name: ElfCraftedTest008
 * @tc.desc: test FindUnwindTableInfo synthesizes an eh_frame_hdr when only .eh_frame exists
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest008, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest008: start.";
    CraftedElfOptions opt;
    opt.loadVaddr = 0;
    opt.loadMemSize = 0x8000;
    opt.extraSections.push_back(MakeSection(".eh_frame", 0x40)); // 0x40 : section size
    auto elf = MakeCraftedElf(opt);
    ASSERT_NE(elf, nullptr);
    ASSERT_TRUE(elf->IsValid());
    elf->SetRuntimeRange(0x1000, 0x2000);

    auto map = MakeCraftedMap();
    UnwindTableInfo uti;
    ASSERT_EQ(elf->FindUnwindTableInfo(0x1500, map, uti), UNW_ERROR_NONE);
    EXPECT_FALSE(uti.isDebugFrame);
    EXPECT_TRUE(uti.isLinear);
    EXPECT_EQ(uti.tableLen, ~static_cast<uintptr_t>(0));
    GTEST_LOG_(INFO) << "ElfCraftedTest008: end.";
}

/**
 * @tc.name: ElfCraftedTest009
 * @tc.desc: test FindUnwindTableInfo reads a binary search table from .eh_frame_hdr
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest009, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest009: start.";
    CraftedElfOptions opt;
    opt.loadVaddr = 0;
    opt.loadMemSize = 0x8000;
    auto hdrSection = MakeSection(".eh_frame_hdr", 0x40); // 0x40 : section size
    hdrSection.data[0] = 1;    // version
    hdrSection.data[1] = 0x1b; // eh_frame_ptr_enc : pcrel | sdata4
    hdrSection.data[2] = 0x03; // fde_count_enc : udata4
    hdrSection.data[3] = 0x3b; // table_enc : datarel | sdata4
    opt.extraSections.push_back(hdrSection);
    auto elf = MakeCraftedElf(opt);
    ASSERT_NE(elf, nullptr);
    ASSERT_TRUE(elf->IsValid());
    elf->SetRuntimeRange(0x1000, 0x2000);

    auto map = MakeCraftedMap();
    UnwindTableInfo uti;
    ASSERT_EQ(elf->FindUnwindTableInfo(0x1500, map, uti), UNW_ERROR_NONE);
    EXPECT_FALSE(uti.isDebugFrame);
    EXPECT_FALSE(uti.isLinear); // binary search table
    GTEST_LOG_(INFO) << "ElfCraftedTest009: end.";
}

/**
 * @tc.name: ElfCraftedTest010
 * @tc.desc: test FindUnwindTableInfo rejects unwind sections whose offset is out of the image
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest010, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest010: start.";
    auto map = MakeCraftedMap();

    CraftedElfOptions hdrOpt;
    hdrOpt.loadVaddr = 0;
    hdrOpt.loadMemSize = 0x8000;
    hdrOpt.extraSections.push_back(MakeSection(".eh_frame_hdr", 0x40, true)); // bogus offset
    auto hdrElf = MakeCraftedElf(hdrOpt);
    ASSERT_NE(hdrElf, nullptr);
    ASSERT_TRUE(hdrElf->IsValid());
    hdrElf->SetRuntimeRange(0x1000, 0x2000);
    UnwindTableInfo uti;
    EXPECT_EQ(hdrElf->FindUnwindTableInfo(0x1500, map, uti), UNW_ERROR_NO_UNWIND_INFO);

    CraftedElfOptions ehOpt;
    ehOpt.loadVaddr = 0;
    ehOpt.loadMemSize = 0x8000;
    ehOpt.extraSections.push_back(MakeSection(".eh_frame", 0x40, true)); // bogus offset
    auto ehElf = MakeCraftedElf(ehOpt);
    ASSERT_NE(ehElf, nullptr);
    ASSERT_TRUE(ehElf->IsValid());
    ehElf->SetRuntimeRange(0x1000, 0x2000);
    UnwindTableInfo uti2;
    EXPECT_EQ(ehElf->FindUnwindTableInfo(0x1500, map, uti2), UNW_ERROR_NO_UNWIND_INFO);
    GTEST_LOG_(INFO) << "ElfCraftedTest010: end.";
}

/**
 * @tc.name: ElfCraftedTest011
 * @tc.desc: test FindUnwindTableInfo reports no unwind info without any unwind section
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest011, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest011: start.";
    CraftedElfOptions opt;
    opt.loadVaddr = 0;
    opt.loadMemSize = 0x8000;
    auto elf = MakeCraftedElf(opt);
    ASSERT_NE(elf, nullptr);
    ASSERT_TRUE(elf->IsValid());
    elf->SetRuntimeRange(0x1000, 0x2000);

    auto map = MakeCraftedMap();
    UnwindTableInfo uti;
    EXPECT_EQ(elf->FindUnwindTableInfo(0x1500, map, uti), UNW_ERROR_NO_UNWIND_INFO);
    GTEST_LOG_(INFO) << "ElfCraftedTest011: end.";
}

/**
 * @tc.name: ElfCraftedTest012
 * @tc.desc: test FindUnwindTableInfo takes start/end pc from the elf without a runtime range
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest012, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest012: start.";
    CraftedElfOptions opt;
    opt.withText = false;
    opt.loadVaddr = 0x3000;
    opt.loadMemSize = 0x40;
    auto elf = MakeCraftedElf(opt);
    ASSERT_NE(elf, nullptr);
    ASSERT_TRUE(elf->IsValid());
    EXPECT_FALSE(elf->HasRuntimeRange());
    elf->SetLoadBase(0); // let GetStartPc/GetEndPc resolve from the executable pt load

    auto map = MakeCraftedMap();
    UnwindTableInfo uti;
    // no unwind section: the lookup passes the pc gate then reports no unwind info
    EXPECT_EQ(elf->FindUnwindTableInfo(0x3020, map, uti), UNW_ERROR_NO_UNWIND_INFO);
    EXPECT_EQ(elf->FindUnwindTableInfo(0x4000, map, uti), UNW_ERROR_PC_NOT_IN_UNWIND_INFO);
    GTEST_LOG_(INFO) << "ElfCraftedTest012: end.";
}

/**
 * @tc.name: ElfCraftedTest013
 * @tc.desc: test a crafted ELF32 image parses through ElfParser32
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest013, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest013: start.";
    CraftedElfOptions opt;
    opt.elfClass32 = true;
    opt.withText = true;
    opt.textVaddr = 0x1000;
    opt.textSize = 0x100;
    opt.withFuncSym = true;
    opt.funcVaddr = 0x1010;
    opt.funcSize = 0x20;
    opt.withObjectSym = true;
    opt.objectVaddr = 0x4000;
    opt.loadVaddr = 0x3000;
    opt.loadMemSize = 0x40;
    auto elf = MakeCraftedElf(opt);
    ASSERT_NE(elf, nullptr);
    ASSERT_TRUE(elf->IsValid());
    EXPECT_EQ(elf->GetClassType(), ELFCLASS32);
    EXPECT_EQ(elf->GetArchType(), ARCH_ARM);
    // pt loads fallback without a runtime range
    EXPECT_TRUE(elf->IsValidPc(0x3020));
    EXPECT_FALSE(elf->IsValidPc(0x3040));
    EXPECT_EQ(elf->GetFuncSymbols().size(), 1U);
    // note: FindGlobalVariableByName walks the symbol table with Elf64_Sym regardless
    // of the elf class, so it is only asserted on 64-bit images (004/014)
    GTEST_LOG_(INFO) << "ElfCraftedTest013: end.";
}

/**
 * @tc.name: ElfCraftedTest014
 * @tc.desc: test FindSymbolByName reject paths for crafted bad symbols
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest014, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest014: start.";
    CraftedElfOptions opt;
    opt.withText = true;
    opt.withObjectSym = true;
    opt.withBadObjectSyms = true;
    auto elf = MakeCraftedElf(opt);
    ASSERT_NE(elf, nullptr);
    ASSERT_TRUE(elf->IsValid());

    ElfSymbol symbol;
    // the good symbol is still found although the table carries bad neighbours
    EXPECT_TRUE(elf->FindGlobalVariableByName("__jit_debug_descriptor", symbol));
    EXPECT_EQ(symbol.value, 0x4000U);
    // SHN_UNDEF entry is skipped even with a valid value
    EXPECT_FALSE(elf->FindGlobalVariableByName("bad_undef", symbol));
    // entry whose st_name is beyond the strtab is skipped
    EXPECT_FALSE(elf->FindGlobalVariableByName("bad_name_off", symbol));
    // missing name stays missing
    EXPECT_FALSE(elf->FindGlobalVariableByName("__not_exist", symbol));
    GTEST_LOG_(INFO) << "ElfCraftedTest014: end.";
}

/**
 * @tc.name: ElfCraftedTest015
 * @tc.desc: test malformed program header fields fail InitHeaders
 * @tc.type: FUNC
 */
HWTEST_F(ElfCraftedTest, ElfCraftedTest015, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfCraftedTest015: start.";
    CraftedElfOptions badEntsize;
    badEntsize.badPhentsize = true;
    auto elf = MakeCraftedElf(badEntsize);
    ASSERT_NE(elf, nullptr);
    EXPECT_FALSE(elf->IsValid());

    CraftedElfOptions badOff;
    badOff.badPhoff = true;
    auto elf2 = MakeCraftedElf(badOff);
    ASSERT_NE(elf2, nullptr);
    EXPECT_FALSE(elf2->IsValid());
    GTEST_LOG_(INFO) << "ElfCraftedTest015: end.";
}
} // namespace HiviewDFX
} // namespace OHOS
