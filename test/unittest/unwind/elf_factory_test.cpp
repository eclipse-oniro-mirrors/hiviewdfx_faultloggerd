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
#include <gtest/gtest.h>

#include <cstdio>
#include <dlfcn.h>
#include <cerrno>
#include <cstdint>

#include "dfx_maps.h"
#include "dfx_symbols.h"
#include "dfx_test_util.h"
#include <unistd.h>
#include "dfx_elf.h"
#include "dfx_map.h"
#include "elf_craft_builder.h"
#include "elf_factory.h"
#include "elf_factory_selector.h"
#include "unwinder_config.h"

using namespace testing;
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace HiviewDFX {
namespace {
#if defined(ENABLE_MINIDEBUGINFO)
#ifndef __x86_64__
    constexpr const char* const DUMPCATCHER_ELF_FILE = "/system/bin/dumpcatcher";
#endif //__x86_64__
#endif //ENABLE_MINIDEBUGINFO
}
class ElfFactoryTest : public testing::Test {};

/**
 * @tc.name: ElfFactoryTest001
 * @tc.desc: test VdsoElfFactory normal case
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest001: start.";
    std::string res = ExecuteCommands("uname");
    bool linuxKernel = res.find("Linux") != std::string::npos;
    if (linuxKernel) {
        ASSERT_TRUE(linuxKernel);
    } else {
        pid_t pid = GetProcessPid(FOUNDATION_NAME);
        auto maps = DfxMaps::Create(pid);
        std::vector<std::shared_ptr<DfxMap>> shmmMaps;
        ASSERT_TRUE(maps->FindMapsByName("[shmm]", shmmMaps));
        std::shared_ptr<DfxMap> shmmMap = nullptr;
        for (auto map : shmmMaps) {
            if (map->IsMapExec()) {
                shmmMap = map;
                break;
            }
        }
        ASSERT_TRUE(shmmMap != nullptr);
        VdsoElfFactory factory(shmmMap->begin, shmmMap->end - shmmMap->begin, pid);
        auto shmmElf = factory.Create();
        ASSERT_TRUE(shmmElf != nullptr);
        std::vector<DfxSymbol> shmmSyms;
        DfxSymbols::ParseSymbols(shmmSyms, shmmElf, "");
        GTEST_LOG_(INFO) << "shmm symbols size" << shmmSyms.size();
        ASSERT_GT(shmmSyms.size(), 0);
        for (const auto& sym : shmmSyms) {
            GTEST_LOG_(INFO) << sym.ToDebugString();
        }
        GTEST_LOG_(INFO) << "ElfFactoryTest001 : end.";
    }
}

/**
 * @tc.name: ElfFactoryTest002
 * @tc.desc: test VdsoElfFactory using not vdso exec map case
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest002: start.";
    pid_t pid = GetProcessPid(FOUNDATION_NAME);
    auto dfxMaps = DfxMaps::Create(pid);
    std::vector<std::shared_ptr<DfxMap>> maps;
    ASSERT_TRUE(dfxMaps->FindMapsByName("libunwinder.z.so", maps));
    for (const auto& map : maps) {
        if (map->IsMapExec()) {
            VdsoElfFactory factory(map->begin, map->end - map->begin, pid);
            auto elf = factory.Create();
            ASSERT_TRUE(elf == nullptr);
            break;
        }
    }
    GTEST_LOG_(INFO) << "ElfFactoryTest002 : end.";
}

/**
 * @tc.name: ElfFactoryTest003
 * @tc.desc: test VdsoElfFactory using abnormal param
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest003, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest003: start.";
    uint64_t begin = 0;
    size_t size = 0;
    pid_t pid = 0;
    VdsoElfFactory factory(begin, size, pid);
    auto elf = factory.Create();
    ASSERT_TRUE(elf == nullptr);
    GTEST_LOG_(INFO) << "ElfFactoryTest003 : end.";
}

#if defined(ENABLE_MINIDEBUGINFO)
#ifndef __x86_64__
/**
 * @tc.name: ElfFactoryTest004
 * @tc.desc: test MiniDebugInfoFactory normal case
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest004, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest004: start.";
    UnwinderConfig::SetEnableMiniDebugInfo(true);
    RegularElfFactory regularElfFactory(DUMPCATCHER_ELF_FILE);
    auto elf = regularElfFactory.Create();
    ASSERT_TRUE(elf->IsValid());
    auto gnuDebugDataHdr = elf->GetGnuDebugDataHdr();
    ASSERT_TRUE(gnuDebugDataHdr.size != 0);
    MiniDebugInfoFactory miniDebugInfoFactory(gnuDebugDataHdr);
    elf = miniDebugInfoFactory.Create();
    ASSERT_TRUE(elf->IsValid());
    GTEST_LOG_(INFO) << "ElfFactoryTest004: end.";
}

/**
 * @tc.name: ElfFactoryTest005
 * @tc.desc: test MiniDebugInfoFactory normal case with test parsing symbol
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest005, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest005: start.";
    UnwinderConfig::SetEnableMiniDebugInfo(true);
    RegularElfFactory regularElfFactory(DUMPCATCHER_ELF_FILE);
    auto elf = regularElfFactory.Create();
    ASSERT_TRUE(elf->IsValid());
    auto gnuDebugDataHdr = elf->GetGnuDebugDataHdr();
    ASSERT_TRUE(gnuDebugDataHdr.size != 0);
    MiniDebugInfoFactory miniDebugInfoFactory(gnuDebugDataHdr);
    elf = miniDebugInfoFactory.Create();
    ASSERT_TRUE(elf->IsValid());
    std::vector<DfxSymbol> symbols;
    DfxSymbols::ParseSymbols(symbols, elf, "");
    GTEST_LOG_(INFO) << "symbols size" << symbols.size();
    ASSERT_GT(symbols.size(), 0);
    for (const auto& symbol : symbols) {
        GTEST_LOG_(INFO) << symbol.ToDebugString();
    }
    GTEST_LOG_(INFO) << "ElfFactoryTest005: end.";
}

/**
 * @tc.name: ElfFactoryTest006
 * @tc.desc: test MiniDebugInfoFactory disable minidebuginfo case
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest006, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest006: start.";
    UnwinderConfig::SetEnableMiniDebugInfo(false);
    RegularElfFactory regularElfFactory(DUMPCATCHER_ELF_FILE);
    auto elf = regularElfFactory.Create();
    ASSERT_TRUE(elf->IsValid());
    auto gnuDebugDataHdr = elf->GetGnuDebugDataHdr();
    ASSERT_TRUE(gnuDebugDataHdr.size != 0);
    MiniDebugInfoFactory miniDebugInfoFactory(gnuDebugDataHdr);
    elf = miniDebugInfoFactory.Create();
    ASSERT_TRUE(elf == nullptr);
    GTEST_LOG_(INFO) << "ElfFactoryTest006: end.";
}

/**
 * @tc.name: ElfFactoryTest007
 * @tc.desc: test MiniDebugInfoFactory using abnormal param
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest007, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest007: start.";
    UnwinderConfig::SetEnableMiniDebugInfo(true);
    GnuDebugDataHdr hdr;
    MiniDebugInfoFactory miniDebugInfoFactory(hdr);
    auto elf = miniDebugInfoFactory.Create();
    ASSERT_TRUE(elf == nullptr);
    GTEST_LOG_(INFO) << "ElfFactoryTest007: end.";
}

/**
 * @tc.name: ElfFactoryTest008
 * @tc.desc: test MiniDebugInfoFactory using abnormal param
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest008, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest008: start.";
    UnwinderConfig::SetEnableMiniDebugInfo(false);
    GnuDebugDataHdr hdr;
    MiniDebugInfoFactory miniDebugInfoFactory(hdr);
    auto elf = miniDebugInfoFactory.Create();
    ASSERT_TRUE(elf == nullptr);
    GTEST_LOG_(INFO) << "ElfFactoryTest008: end.";
}
#endif //__x86_64__
#endif //ENABLE_MINIDEBUGINFO

/**
 * @tc.name: ElfFactoryTest009
 * @tc.desc: test ElfFactoryTest with 64 bit ELF
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest009, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest009: start.";
    const char* elf64File = "/data/test/resource/testdata/elf_test";
    RegularElfFactory factory(elf64File);
    auto elf = factory.Create();
    ASSERT_TRUE(elf->IsValid());
    GTEST_LOG_(INFO) << "ElfFactoryTest009: end.";
}

/**
 * @tc.name: ElfFactoryTest010
 * @tc.desc: ElfFactoryTest with 32 bit ELF
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest010, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest010: start.";
    const char* elf32File = "/data/test/resource/testdata/elf32_test";
    RegularElfFactory factory(elf32File);
    auto elf = factory.Create();
    ASSERT_TRUE(elf->IsValid());
    GTEST_LOG_(INFO) << "ElfFactoryTest010: end.";
}

/**
 * @tc.name: ElfFactoryTest011
 * @tc.desc: test DfxElf functions with empty file path
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest011, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest002: start.";
    std::string filePath  = "";
    RegularElfFactory factory(filePath);
    auto elf = factory.Create();
    ASSERT_FALSE(elf->IsValid());
    GTEST_LOG_(INFO) << "ElfFactoryTest011: end.";
}

/**
 * @tc.name: ElfFactoryTest012
 * @tc.desc: test DfxElf functions with invalid filePath
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest012, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest012: start.";
    std::string filePath  = "[anno:stack:2345]";
    RegularElfFactory factory(filePath);
    auto elf = factory.Create();
    ASSERT_FALSE(elf->IsValid());
    GTEST_LOG_(INFO) << "ElfFactoryTest012: end.";
}

/**
 * @tc.name: ElfFactoryTest013
 * @tc.desc: ElfFactorySelector in normal case
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest013, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest013: start.";
    pid_t pid = GetProcessPid(FOUNDATION_NAME);
    auto dfxMaps = DfxMaps::Create(pid);
    auto maps = dfxMaps->GetMaps();
    for (const auto& map : maps) {
        auto elfFactory = ElfFactorySelector::Select(*(map.get()), pid);
        auto elf = elfFactory->Create();
        if (map->IsVdsoMap()) {
            ASSERT_TRUE(elf->IsValid());
            GTEST_LOG_(INFO) << elf->GetElfName();
            ASSERT_TRUE(elf->GetElfName().find("shmm") != std::string::npos ||
                elf->GetElfName().find("vdso") != std::string::npos);
        } else if (DfxMaps::IsLegalMapItem(map->name) && map->IsMapExec()) {
            ASSERT_TRUE(elf->IsValid()) << map->name;
        }
    }
    GTEST_LOG_(INFO) << "ElfFactoryTest013: end.";
}

/**
 * @tc.name: ElfFactoryTest014
 * @tc.desc: ElfFactorySelector using abnormal param
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest014, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest014: start.";
    DfxMap map;
    auto elfFactory = ElfFactorySelector::Select(map);
    auto elf = elfFactory->Create();
    ASSERT_FALSE(elf->IsValid());

    map.begin = 0xc38a6000;
    map.end = 0xc39450000;
    map.offset = 0x1d9000;
    map.prots |= PROT_READ;
    map.prots |= PROT_EXEC;
    map.name = "/proc/data/storage/el1/bundle/entry.hap"; // invalid path
    auto prevMap = std::make_shared<DfxMap>();
    prevMap->begin = 0xc3840000;
    prevMap->end = 0xc38a6000;
    prevMap->offset = 0x174000;
    prevMap->prots |= PROT_READ;
    prevMap->name = "/proc/data/storage/el1/bundle/entry.hap"; // invalid path
    map.prevMap = prevMap;
    elfFactory = ElfFactorySelector::Select(map);
    elf = elfFactory->Create();
    ASSERT_EQ(elf, nullptr);
    GTEST_LOG_(INFO) << "ElfFactoryTest014: end.";
}

namespace {
std::string WriteElfFile(const std::vector<uint8_t>& data, const std::string& suffix)
{
    std::string path = "/data/local/tmp/elf_factory_test_XXXXXX" + suffix;
    std::vector<char> buf(path.begin(), path.end());
    buf.push_back(0);
    int fd = mkstemps(buf.data(), static_cast<int>(suffix.size()));
    if (fd < 0) {
        return "";
    }
    size_t written = 0;
    while (written < data.size()) {
        ssize_t n = write(fd, data.data() + written, data.size() - written);
        if (n < 0 && errno == EINTR) {
            continue; // interrupted before writing anything, retry
        }
        if (n <= 0) {
            close(fd);
            unlink(buf.data());
            return "";
        }
        written += static_cast<size_t>(n);
    }
    close(fd);
    return std::string(buf.data());
}
} // namespace

/**
 * @tc.name: ElfFactoryTest015
 * @tc.desc: test CompressHapElfFactory guard clauses
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest015, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest015: start.";
    // neither an offset nor a prev map: nothing can be loaded
    CompressHapElfFactory noSource("/data/local/tmp/guard.apk", nullptr, 0, 0);
    ASSERT_EQ(noSource.Create(), nullptr);
    // hap without the sandbox prefix is illegal
    CompressHapElfFactory badHap("/data/local/tmp/guard.hap", nullptr, 0x100, 0x100);
    ASSERT_EQ(badHap.Create(), nullptr);
    // neither hap nor apk
    CompressHapElfFactory badSuffix("/data/local/tmp/guard.so", nullptr, 0x100, 0x100);
    ASSERT_EQ(badSuffix.Create(), nullptr);
    // apk pointing at a missing file
    CompressHapElfFactory missingFile("/data/local/tmp/not_exist_guard.apk", nullptr, 0x100, 0x100);
    ASSERT_EQ(missingFile.Create(), nullptr);
    GTEST_LOG_(INFO) << "ElfFactoryTest015: end.";
}

/**
 * @tc.name: ElfFactoryTest016
 * @tc.desc: test LoadEmbeddedElf loads an elf image embedded at a file offset
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest016, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest016: start.";
    CraftedElfOptions opt;
    opt.withText = true;
    auto image = ElfCraftBuilder::Build(opt);
    std::vector<uint8_t> file(0x1000, 0x41); // 0x1000 : leading padding
    file.insert(file.end(), image.begin(), image.end());
    std::string goodPath = WriteElfFile(file, ".apk");
    if (goodPath.empty()) {
        GTEST_SKIP() << "temp file not writable";
    }

    CompressHapElfFactory factory(goodPath, nullptr, 0x1000, image.size());
    auto elf = factory.Create();
    ASSERT_NE(elf, nullptr);
    EXPECT_TRUE(elf->IsValid());
    EXPECT_EQ(elf->GetBaseOffset(), 0x1000U);

    // prev map fallback: curOffset is zero, the elf sits at prevMap->offset
    auto prevMap = std::make_shared<DfxMap>(0x7000000, 0x7000000 + image.size(), 0x1000, PROT_READ, goodPath);
    CompressHapElfFactory prevFactory(goodPath, prevMap, 0, 0);
    auto prevElf = prevFactory.Create();
    ASSERT_NE(prevElf, nullptr);
    EXPECT_EQ(prevElf->GetBaseOffset(), 0x1000U);

    unlink(goodPath.c_str());
    GTEST_LOG_(INFO) << "ElfFactoryTest016: end.";
}

/**
 * @tc.name: ElfFactoryTest017
 * @tc.desc: test ElfFactorySelector routes hap/apk/vdso/plain maps
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest017, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest017: start.";
    auto prev = std::make_shared<DfxMap>(0x7000000, 0x7001000, 0x800, PROT_READ,
        "/data/storage/el1/bundle/test.hap");

    // no rtti in this target: assert through the observable map offset side effects
    DfxMap hapMap(0x7001000, 0x7002000, 0x1000, PROT_READ, "/data/storage/el1/bundle/test.hap");
    hapMap.prevMap = prev;
    auto hapFactory = ElfFactorySelector::Select(hapMap, getpid());
    ASSERT_NE(hapFactory, nullptr);
    EXPECT_EQ(hapMap.offset, 0x800U); // 0x800 : relative to the previous hap map

    DfxMap apkMap(0x7100000, 0x7101000, 0x2000, PROT_READ, "/data/app/el1/bundle/test.apk");
    apkMap.prevMap = prev;
    auto apkFactory = ElfFactorySelector::Select(apkMap, getpid());
    ASSERT_NE(apkFactory, nullptr);
    EXPECT_EQ(apkMap.offset, 0U); // apk maps are rebased to their own start

    DfxMap vdsoMap(0x7200000, 0x7201000, 0, PROT_EXEC, "[vdso]");
    auto vdsoFactory = ElfFactorySelector::Select(vdsoMap, getpid());
    EXPECT_NE(vdsoFactory, nullptr);

    DfxMap plainMap(0x7300000, 0x7301000, 0, PROT_EXEC, "/system/lib/libtest.so");
    auto plainFactory = ElfFactorySelector::Select(plainMap, getpid());
    EXPECT_NE(plainFactory, nullptr);
    GTEST_LOG_(INFO) << "ElfFactoryTest017: end.";
}

/**
 * @tc.name: ElfFactoryTest018
 * @tc.desc: test VdsoElfFactory loads the vdso mapping of this process
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest018, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest018: start.";
    // size guard: oversized requests are rejected before any read
    VdsoElfFactory huge(0x1000, 10 * 1024 * 1024, getpid());
    ASSERT_EQ(huge.Create(), nullptr);

    auto maps = DfxMaps::Create(getpid());
    ASSERT_NE(maps, nullptr);
    uintptr_t vdsoBegin = 0;
    size_t vdsoSize = 0;
    for (const auto& map : maps->GetMaps()) {
        if (map != nullptr && map->name == "[vdso]" && map->IsMapExec()) {
            vdsoBegin = static_cast<uintptr_t>(map->begin);
            vdsoSize = static_cast<size_t>(map->end - map->begin);
            break;
        }
    }
    if (vdsoBegin == 0) {
        GTEST_SKIP() << "no [vdso] mapping found";
    }
    VdsoElfFactory factory(vdsoBegin, vdsoSize, getpid());
    auto elf = factory.Create();
    ASSERT_NE(elf, nullptr);
    EXPECT_TRUE(elf->IsValid());
    GTEST_LOG_(INFO) << "ElfFactoryTest018: end.";
}

/**
 * @tc.name: ElfFactoryTest019
 * @tc.desc: test malformed embedded elf images are rejected by LoadEmbeddedElf
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest019, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest019: start.";
    CraftedElfOptions opt;
    opt.withText = true;
    auto image = ElfCraftBuilder::Build(opt);

    // an elf whose section table runs past the file end is rejected
    std::vector<uint8_t> truncFile(0x1000, 0x41); // 0x1000 : leading padding
    truncFile.insert(truncFile.end(), image.begin(), image.begin() + sizeof(Elf64_Ehdr));
    std::string truncPath = WriteElfFile(truncFile, ".apk");
    if (truncPath.empty()) {
        GTEST_SKIP() << "temp file not writable";
    }
    CompressHapElfFactory truncFactory(truncPath, nullptr, 0x1000, image.size());
    ASSERT_EQ(truncFactory.Create(), nullptr);
    unlink(truncPath.c_str());

    // a computed elf size of zero (no section table) is rejected
    std::vector<uint8_t> zeroImage = image;
    const uint64_t zeroShoff = 0;
    if (memcpy_s(zeroImage.data() + 0x28, 8, &zeroShoff, 8) != 0) { // 0x28 : e_shoff offset
        ASSERT_TRUE(false);
    }
    const uint16_t zeroShnum = 0;
    if (memcpy_s(zeroImage.data() + 0x3c, 2, &zeroShnum, 2) != 0) { // 0x3c : e_shnum offset
        ASSERT_TRUE(false);
    }
    std::vector<uint8_t> zeroFile(0x1000, 0x41);
    zeroFile.insert(zeroFile.end(), zeroImage.begin(), zeroImage.end());
    std::string zeroPath = WriteElfFile(zeroFile, ".apk");
    if (zeroPath.empty()) {
        GTEST_SKIP() << "temp file not writable";
    }
    CompressHapElfFactory zeroFactory(zeroPath, nullptr, 0x1000, image.size());
    ASSERT_EQ(zeroFactory.Create(), nullptr);
    unlink(zeroPath.c_str());
    GTEST_LOG_(INFO) << "ElfFactoryTest019: end.";
}
}
}
