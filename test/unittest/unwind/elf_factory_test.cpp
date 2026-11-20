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
#include <sys/stat.h>
#include <sys/types.h>

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

/**
 * @tc.name: ElfFactoryTest009_MiniDebugInfo
 * @tc.desc: test BuildChunkIndex produces monotonic block index
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest009_MiniDebugInfo, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest009_MiniDebugInfo: start.";
    UnwinderConfig::SetEnableMiniDebugInfo(true);
    RegularElfFactory regularElfFactory(DUMPCATCHER_ELF_FILE);
    auto elf = regularElfFactory.Create();
    ASSERT_TRUE(elf->IsValid());
    auto gnuDebugDataHdr = elf->GetGnuDebugDataHdr();
    ASSERT_TRUE(gnuDebugDataHdr.size != 0);
    MiniDebugInfoFactory miniDebugInfoFactory(gnuDebugDataHdr);
    auto src = reinterpret_cast<const uint8_t *>(gnuDebugDataHdr.address);
    ChunkIndex idx = miniDebugInfoFactory.BuildChunkIndex(src, gnuDebugDataHdr.size);
    ASSERT_FALSE(idx.entries.empty());
    ASSERT_EQ(idx.entries[0].dstOff, 0ULL);
    for (size_t i = 1; i < idx.entries.size(); ++i) {
        ASSERT_GT(idx.entries[i].dstOff, idx.entries[i - 1].dstOff);
        ASSERT_EQ(idx.entries[i - 1].dstOff + idx.entries[i - 1].unpackSize, idx.entries[i].dstOff);
    }
    GTEST_LOG_(INFO) << "ElfFactoryTest009_MiniDebugInfo: end.";
}

/**
 * @tc.name: ElfFactoryTest010_MiniDebugInfo
 * @tc.desc: test BlockProvider block-by-block decompression yields valid ELF
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest010_MiniDebugInfo, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest010_MiniDebugInfo: start.";
    UnwinderConfig::SetEnableMiniDebugInfo(true);
    RegularElfFactory regularElfFactory(DUMPCATCHER_ELF_FILE);
    auto elf = regularElfFactory.Create();
    ASSERT_TRUE(elf->IsValid());
    auto gnuDebugDataHdr = elf->GetGnuDebugDataHdr();
    ASSERT_TRUE(gnuDebugDataHdr.size != 0);
    MiniDebugInfoFactory miniDebugInfoFactory(gnuDebugDataHdr);
    auto src = reinterpret_cast<const uint8_t *>(gnuDebugDataHdr.address);
    ChunkIndex idx = miniDebugInfoFactory.BuildChunkIndex(src, gnuDebugDataHdr.size);
    ASSERT_FALSE(idx.entries.empty());
    BlockProvider provider(src, gnuDebugDataHdr.size, ChunkIndex{idx});
    std::vector<uint8_t> fullOut;
    for (const auto& blk : idx.entries) {
        std::vector<uint8_t> blockOut;
        ASSERT_TRUE(provider.DecompressBlock(blk, blockOut));
        fullOut.insert(fullOut.end(), blockOut.begin(), blockOut.end());
    }
    ASSERT_FALSE(fullOut.empty());
    constexpr uint8_t elfMagic0 = 0x7f;
    ASSERT_EQ(fullOut[0], elfMagic0);
    ASSERT_EQ(fullOut[1], 'E');
    ASSERT_EQ(fullOut[2], 'L');
    ASSERT_EQ(fullOut[3], 'F');
    GTEST_LOG_(INFO) << "ElfFactoryTest010_MiniDebugInfo: end.";
}

/**
 * @tc.name: ElfFactoryTest011_MiniDebugInfo
 * @tc.desc: test block-by-block decompression bytes equal to full XzDecompress (AC-01)
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest011_MiniDebugInfo, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest011_MiniDebugInfo: start.";
    UnwinderConfig::SetEnableMiniDebugInfo(true);
    RegularElfFactory regularElfFactory(DUMPCATCHER_ELF_FILE);
    auto elf = regularElfFactory.Create();
    ASSERT_TRUE(elf->IsValid());
    auto gnuDebugDataHdr = elf->GetGnuDebugDataHdr();
    ASSERT_TRUE(gnuDebugDataHdr.size != 0);
    MiniDebugInfoFactory miniDebugInfoFactory(gnuDebugDataHdr);
    auto src = reinterpret_cast<const uint8_t *>(gnuDebugDataHdr.address);
    size_t srcLen = gnuDebugDataHdr.size;

    std::vector<uint8_t> fullOut;
    ASSERT_TRUE(miniDebugInfoFactory.XzDecompress(src, srcLen, fullOut));
    ASSERT_FALSE(fullOut.empty());

    ChunkIndex idx = miniDebugInfoFactory.BuildChunkIndex(src, srcLen);
    ASSERT_FALSE(idx.entries.empty());
    ASSERT_EQ(idx.entries[0].dstOff, 0ULL);
    for (size_t i = 1; i < idx.entries.size(); ++i) {
        ASSERT_EQ(idx.entries[i - 1].dstOff + idx.entries[i - 1].unpackSize, idx.entries[i].dstOff);
    }
    BlockProvider provider(src, srcLen, ChunkIndex{idx});
    std::vector<uint8_t> segOut;
    for (const auto& blk : idx.entries) {
        std::vector<uint8_t> blockOut;
        ASSERT_TRUE(provider.DecompressBlock(blk, blockOut));
        segOut.insert(segOut.end(), blockOut.begin(), blockOut.end());
    }
    ASSERT_EQ(segOut.size(), fullOut.size());
    EXPECT_EQ(memcmp(segOut.data(), fullOut.data(), fullOut.size()), 0);
    GTEST_LOG_(INFO) << "ElfFactoryTest011_MiniDebugInfo: end.";
}

/**
 * @tc.name: ElfFactoryTest012_MiniDebugInfo
 * @tc.desc: test Create adaptive path returns valid elf with symbols (AC-04)
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest012_MiniDebugInfo, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest012_MiniDebugInfo: start.";
    UnwinderConfig::SetEnableMiniDebugInfo(true);
    RegularElfFactory regularElfFactory(DUMPCATCHER_ELF_FILE);
    auto elf = regularElfFactory.Create();
    ASSERT_TRUE(elf->IsValid());
    auto gnuDebugDataHdr = elf->GetGnuDebugDataHdr();
    ASSERT_TRUE(gnuDebugDataHdr.size != 0);
    auto src = reinterpret_cast<const uint8_t *>(gnuDebugDataHdr.address);
    MiniDebugInfoFactory miniDebugInfoFactory(gnuDebugDataHdr);
    ChunkIndex idx = miniDebugInfoFactory.BuildChunkIndex(src, gnuDebugDataHdr.size);
    GTEST_LOG_(INFO) << "block count: " << idx.entries.size();
    auto mini = miniDebugInfoFactory.Create();
    ASSERT_TRUE(mini != nullptr);
    ASSERT_TRUE(mini->IsValid());
    std::vector<DfxSymbol> symbols;
    DfxSymbols::ParseSymbols(symbols, mini, "");
    ASSERT_GT(symbols.size(), 0);
    GTEST_LOG_(INFO) << "ElfFactoryTest012_MiniDebugInfo: end.";
}

/**
 * @tc.name: ElfFactoryTest013_MiniDebugInfo
 * @tc.desc: test Create fallback on corrupt input returns nullptr (AC-04)
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest013_MiniDebugInfo, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest013_MiniDebugInfo: start.";
    UnwinderConfig::SetEnableMiniDebugInfo(true);
    std::vector<uint8_t> corrupt(64, 0xAA);
    GnuDebugDataHdr hdr;
    hdr.address = reinterpret_cast<uintptr_t>(corrupt.data());
    hdr.size = static_cast<uintptr_t>(corrupt.size());
    MiniDebugInfoFactory miniDebugInfoFactory(hdr);
    auto mini = miniDebugInfoFactory.Create();
    EXPECT_EQ(mini, nullptr);
    GTEST_LOG_(INFO) << "ElfFactoryTest013_MiniDebugInfo: end.";
}

/**
 * @tc.name: ElfFactoryTest014_MiniDebugInfo
 * @tc.desc: test Create preserves enableLoadSymbolLazily switch semantics (AC-04)
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest014_MiniDebugInfo, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest014_MiniDebugInfo: start.";
    UnwinderConfig::SetEnableMiniDebugInfo(true);
    RegularElfFactory regularElfFactory(DUMPCATCHER_ELF_FILE);
    auto elf = regularElfFactory.Create();
    ASSERT_TRUE(elf->IsValid());
    auto gnuDebugDataHdr = elf->GetGnuDebugDataHdr();
    ASSERT_TRUE(gnuDebugDataHdr.size != 0);
    for (bool lazy : { false, true }) {
        UnwinderConfig::SetEnableLoadSymbolLazily(lazy);
        MiniDebugInfoFactory miniDebugInfoFactory(gnuDebugDataHdr);
        auto mini = miniDebugInfoFactory.Create();
        ASSERT_TRUE(mini != nullptr);
        ASSERT_TRUE(mini->IsValid());
    }
    UnwinderConfig::SetEnableLoadSymbolLazily(false);
    GTEST_LOG_(INFO) << "ElfFactoryTest014_MiniDebugInfo: end.";
}
namespace {
// Loads the real dumpcatcher minidebuginfo together with its block index.
// elf must be kept alive: it owns the mmap backing src, which the block provider
// dereferences lazily during the tests.
struct MiniInput {
    std::shared_ptr<DfxElf> elf;
    const uint8_t *src = nullptr;
    size_t srcLen = 0;
    ChunkIndex idx;
};

bool LoadMiniInput(MiniInput &in)
{
    UnwinderConfig::SetEnableMiniDebugInfo(true);
    RegularElfFactory regularElfFactory(DUMPCATCHER_ELF_FILE);
    auto elf = regularElfFactory.Create();
    if (elf == nullptr || !elf->IsValid()) {
        return false;
    }
    GnuDebugDataHdr hdr = elf->GetGnuDebugDataHdr();
    if (hdr.size == 0) {
        return false;
    }
    in.elf = elf;
    in.src = reinterpret_cast<const uint8_t *>(hdr.address);
    in.srcLen = static_cast<size_t>(hdr.size);
    MiniDebugInfoFactory factory(hdr);
    in.idx = factory.BuildChunkIndex(in.src, in.srcLen);
    return !in.idx.entries.empty();
}

// xz stream tail layout: [blocks][Stream Index][Stream Footer(XZ_FOOTER_SIZE)] where the
// footer is CRC32(4) | Backward Size(4) | Stream Flags(2) | "YZ"(2) and Backward Size
// stores (index size / XZ_INDEX_SIZE_UNIT) - 1.
constexpr size_t XZ_FOOTER_SIZE = 12;
constexpr size_t XZ_FOOTER_BACKWARD_OFFSET = 4;
constexpr size_t XZ_INDEX_SIZE_UNIT = 4;

size_t XzIndexStart(const std::vector<uint8_t> &raw)
{
    uint32_t backward = 0;
    size_t off = raw.size() - XZ_FOOTER_SIZE + XZ_FOOTER_BACKWARD_OFFSET;
    if (memcpy_s(&backward, sizeof(backward), raw.data() + off, sizeof(backward)) != 0) {
        return raw.size();
    }
    size_t indexSize = (static_cast<size_t>(backward) + 1) * XZ_INDEX_SIZE_UNIT;
    return raw.size() - XZ_FOOTER_SIZE - indexSize;
}

ChunkBlk MakeBlk(uint64_t dstOff, uint64_t unpackSize)
{
    ChunkBlk blk;
    blk.dstOff = dstOff;
    blk.packOff = 0;
    blk.unpackSize = unpackSize;
    blk.packSize = 0;
    return blk;
}
} // namespace

/**
 * @tc.name: ElfFactoryTest020_MiniDebugInfo
 * @tc.desc: test BuildChunkIndex rejects corrupted xz streams and Create falls back (BR-04)
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest020_MiniDebugInfo, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest020_MiniDebugInfo: start.";
    MiniInput in;
    ASSERT_TRUE(LoadMiniInput(in));
    GnuDebugDataHdr hdr;
    hdr.address = reinterpret_cast<uintptr_t>(in.src);
    hdr.size = static_cast<uintptr_t>(in.srcLen);
    MiniDebugInfoFactory factory(hdr);
    std::vector<uint8_t> raw;

    // footer signature corrupted: the "YZ" magic is no longer at the stream tail
    raw.assign(in.src, in.src + in.srcLen);
    raw[raw.size() - 1] = 0;
    EXPECT_TRUE(factory.BuildChunkIndex(raw.data(), raw.size()).entries.empty());

    // backward size claims an index reaching far beyond the stream
    raw.assign(in.src, in.src + in.srcLen);
    constexpr uint32_t hugeBackward = 0xFFFFFFFF;
    if (memcpy_s(raw.data() + raw.size() - XZ_FOOTER_SIZE + XZ_FOOTER_BACKWARD_OFFSET,
        sizeof(hugeBackward), &hugeBackward, sizeof(hugeBackward)) != 0) {
        ASSERT_TRUE(false);
    }
    EXPECT_TRUE(factory.BuildChunkIndex(raw.data(), raw.size()).entries.empty());

    // stream index indicator corrupted (must be 0x00)
    raw.assign(in.src, in.src + in.srcLen);
    raw[XzIndexStart(raw)] = 1;
    EXPECT_TRUE(factory.BuildChunkIndex(raw.data(), raw.size()).entries.empty());

    // record count of zero
    raw.assign(in.src, in.src + in.srcLen);
    raw[XzIndexStart(raw) + 1] = 0;
    EXPECT_TRUE(factory.BuildChunkIndex(raw.data(), raw.size()).entries.empty());

    // truncated stream: the footer no longer sits at the tail
    std::vector<uint8_t> trunc(in.src, in.src + in.srcLen - XZ_FOOTER_SIZE);
    EXPECT_TRUE(factory.BuildChunkIndex(trunc.data(), trunc.size()).entries.empty());

    // null or undersized input
    EXPECT_TRUE(factory.BuildChunkIndex(nullptr, in.srcLen).entries.empty());
    EXPECT_TRUE(factory.BuildChunkIndex(in.src, 0).entries.empty());

    // a corrupted stream propagates to Create: the index falls back to the full
    // decompress, which fails on the corrupted bytes, so Create returns nullptr
    raw.assign(in.src, in.src + in.srcLen);
    raw[raw.size() - 1] = 0;
    GnuDebugDataHdr badHdr;
    badHdr.address = reinterpret_cast<uintptr_t>(raw.data());
    badHdr.size = static_cast<uintptr_t>(raw.size());
    MiniDebugInfoFactory corruptedFactory(badHdr);
    EXPECT_EQ(corruptedFactory.Create(), nullptr);
    GTEST_LOG_(INFO) << "ElfFactoryTest020_MiniDebugInfo: end.";
}

/**
 * @tc.name: ElfFactoryTest021_MiniDebugInfo
 * @tc.desc: test FindBlock locates every block boundary of the real index
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest021_MiniDebugInfo, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest021_MiniDebugInfo: start.";
    MiniInput in;
    ASSERT_TRUE(LoadMiniInput(in));
    BlockProvider provider(in.src, in.srcLen, ChunkIndex{in.idx});
    const std::vector<ChunkBlk> &blocks = provider.Blocks();
    ASSERT_FALSE(blocks.empty());
    // the first and the last byte of every block resolve to that block
    for (size_t i = 0; i < blocks.size(); i++) {
        const ChunkBlk *first = provider.FindBlock(static_cast<uintptr_t>(blocks[i].dstOff));
        ASSERT_NE(first, nullptr);
        EXPECT_EQ(first->dstOff, blocks[i].dstOff);
        uintptr_t lastByte = static_cast<uintptr_t>(blocks[i].dstOff + blocks[i].unpackSize - 1);
        const ChunkBlk *last = provider.FindBlock(lastByte);
        ASSERT_NE(last, nullptr);
        EXPECT_EQ(last->dstOff, blocks[i].dstOff);
    }
    // one past the image end and beyond resolve to no block
    EXPECT_EQ(provider.FindBlock(static_cast<uintptr_t>(provider.TotalUnpackSize())), nullptr);
    EXPECT_EQ(provider.FindBlock(static_cast<uintptr_t>(provider.TotalUnpackSize() + 1)), nullptr);
    GTEST_LOG_(INFO) << "ElfFactoryTest021_MiniDebugInfo: end.";
}

/**
 * @tc.name: ElfFactoryTest022_MiniDebugInfo
 * @tc.desc: test block lookup for uniform (shift path) and non-uniform (binary search) layouts
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest022_MiniDebugInfo, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest022_MiniDebugInfo: start.";
    // non-uniform layout: block sizes are not a power of two, lookup uses binary search
    constexpr uint64_t sizeA = 100;
    constexpr uint64_t sizeB = 50;
    constexpr uint64_t sizeC = 70;
    const uint64_t offB = sizeA;
    const uint64_t offC = sizeA + sizeB;
    const uint64_t total = offC + sizeC;
    ChunkIndex nonUniform;
    nonUniform.entries.push_back(MakeBlk(0, sizeA));
    nonUniform.entries.push_back(MakeBlk(offB, sizeB));
    nonUniform.entries.push_back(MakeBlk(offC, sizeC));
    BlockProvider provider(nullptr, 0, ChunkIndex{nonUniform});
    EXPECT_EQ(provider.FindBlock(0)->dstOff, 0ULL);
    EXPECT_EQ(provider.FindBlock(static_cast<uintptr_t>(sizeA - 1))->dstOff, 0ULL);
    EXPECT_EQ(provider.FindBlock(static_cast<uintptr_t>(offB))->dstOff, offB);
    EXPECT_EQ(provider.FindBlock(static_cast<uintptr_t>(offB + sizeB - 1))->dstOff, offB);
    EXPECT_EQ(provider.FindBlock(static_cast<uintptr_t>(offC))->dstOff, offC);
    EXPECT_EQ(provider.FindBlock(static_cast<uintptr_t>(offC + sizeC - 1))->dstOff, offC);
    EXPECT_EQ(provider.FindBlock(static_cast<uintptr_t>(total)), nullptr);
    EXPECT_EQ(provider.TotalUnpackSize(), static_cast<size_t>(total));

    // uniform power-of-two layout with a shorter trailing block: lookup uses the shift path
    constexpr uint64_t uniformSize = 4096;
    constexpr uint64_t trailingSize = 1000;
    const uint64_t tailOff = uniformSize * 3;
    ChunkIndex uniform;
    uniform.entries.push_back(MakeBlk(0, uniformSize));
    uniform.entries.push_back(MakeBlk(uniformSize, uniformSize));
    uniform.entries.push_back(MakeBlk(uniformSize * 2, uniformSize));
    uniform.entries.push_back(MakeBlk(tailOff, trailingSize));
    BlockProvider uniformProvider(nullptr, 0, ChunkIndex{uniform});
    EXPECT_EQ(uniformProvider.FindBlock(static_cast<uintptr_t>(uniformSize - 1))->dstOff, 0ULL);
    EXPECT_EQ(uniformProvider.FindBlock(static_cast<uintptr_t>(uniformSize))->dstOff, uniformSize);
    EXPECT_EQ(uniformProvider.FindBlock(static_cast<uintptr_t>(uniformSize * 2))->dstOff,
        uniformSize * 2);
    EXPECT_EQ(uniformProvider.FindBlock(static_cast<uintptr_t>(tailOff))->dstOff, tailOff);
    EXPECT_EQ(uniformProvider.FindBlock(static_cast<uintptr_t>(tailOff + trailingSize - 1))->dstOff,
        tailOff);
    EXPECT_EQ(uniformProvider.FindBlock(static_cast<uintptr_t>(tailOff + trailingSize)), nullptr);
    GTEST_LOG_(INFO) << "ElfFactoryTest022_MiniDebugInfo: end.";
}

/**
 * @tc.name: ElfFactoryTest023_MiniDebugInfo
 * @tc.desc: test DecompressBlock rejects a tampered chunk index (integrity guard)
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest023_MiniDebugInfo, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest023_MiniDebugInfo: start.";
    MiniInput in;
    ASSERT_TRUE(LoadMiniInput(in));
    std::vector<uint8_t> out;
    // baseline: the untouched index decodes the first block
    BlockProvider valid(in.src, in.srcLen, ChunkIndex{in.idx});
    ASSERT_TRUE(valid.DecompressBlock(in.idx.entries[0], out));

    // tampered packOff: decoding starts inside the block and must be rejected
    ChunkIndex tampered = in.idx;
    tampered.entries[0].packOff += 1;
    BlockProvider shifted(in.src, in.srcLen, ChunkIndex{tampered});
    EXPECT_FALSE(shifted.DecompressBlock(tampered.entries[0], out));

    // tampered unpackSize: the decoded size disagrees with the record
    tampered = in.idx;
    tampered.entries[0].unpackSize += 1;
    BlockProvider grown(in.src, in.srcLen, ChunkIndex{tampered});
    EXPECT_FALSE(grown.DecompressBlock(tampered.entries[0], out));

    // tampered packSize: the recorded block span disagrees with the decoder
    tampered = in.idx;
    tampered.entries[0].packSize += 1;
    BlockProvider span(in.src, in.srcLen, ChunkIndex{tampered});
    EXPECT_FALSE(span.DecompressBlock(tampered.entries[0], out));
    GTEST_LOG_(INFO) << "ElfFactoryTest023_MiniDebugInfo: end.";
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
std::string WriteElfFileToDir(const std::vector<uint8_t>& data, const std::string& dir, const std::string& suffix)
{
    std::string path = dir + "/elf_factory_test_XXXXXX" + suffix;
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

std::string WriteElfFile(const std::vector<uint8_t>& data, const std::string& suffix)
{
    return WriteElfFileToDir(data, "/data/local/tmp", suffix);
}

bool EnsureDirExists(const std::string& dir)
{
    // owner read/write/execute, group and others read/execute
    constexpr mode_t tempDirMode = 0755;
    if (access(dir.c_str(), F_OK) == 0) {
        return true;
    }
    return mkdir(dir.c_str(), tempDirMode) == 0;
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

/**
 * @tc.name: ElfFactoryTest020
 * @tc.desc: test CompressHapElfFactory guard clauses for hsp and hqf files
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest020, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest020: start.";
    // hsp without the sandbox prefix is illegal
    CompressHapElfFactory badHsp("/data/local/tmp/guard.hsp", nullptr, 0x100, 0x100);
    ASSERT_EQ(badHsp.Create(), nullptr);
    // hqf without the sandbox prefix is illegal
    CompressHapElfFactory badHqf("/data/local/tmp/guard.hqf", nullptr, 0x100, 0x100);
    ASSERT_EQ(badHqf.Create(), nullptr);
    // hsp inside the sandbox prefix but pointing at a missing file
    CompressHapElfFactory missingHsp("/data/storage/el1/bundle/not_exist_guard.hsp", nullptr, 0x100, 0x100);
    ASSERT_EQ(missingHsp.Create(), nullptr);
    // hqf inside the sandbox prefix but pointing at a missing file
    CompressHapElfFactory missingHqf("/data/storage/el1/bundle/not_exist_guard.hqf", nullptr, 0x100, 0x100);
    ASSERT_EQ(missingHqf.Create(), nullptr);
    GTEST_LOG_(INFO) << "ElfFactoryTest020: end.";
}

/**
 * @tc.name: ElfFactoryTest021
 * @tc.desc: test CompressHapElfFactory loads the embedded elf of hsp and hqf files
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest021, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest021: start.";
    CraftedElfOptions opt;
    opt.withText = true;
    auto image = ElfCraftBuilder::Build(opt);
    std::vector<uint8_t> file(0x1000, 0x41); // 0x1000 : leading padding
    file.insert(file.end(), image.begin(), image.end());

    // the path must contain the sandbox prefix, carve it out under the temp dir
    if (!EnsureDirExists("/data/local/tmp/data") || !EnsureDirExists("/data/local/tmp/data/storage")) {
        GTEST_SKIP() << "sandbox-like temp dir not creatable";
    }
    const std::string sandboxDir = "/data/local/tmp/data/storage";
    std::string hspPath = WriteElfFileToDir(file, sandboxDir, ".hsp");
    std::string hqfPath = WriteElfFileToDir(file, sandboxDir, ".hqf");
    if (hspPath.empty() || hqfPath.empty()) {
        GTEST_SKIP() << "temp file not writable";
    }

    CompressHapElfFactory hspFactory(hspPath, nullptr, 0x1000, image.size());
    auto hspElf = hspFactory.Create();
    ASSERT_NE(hspElf, nullptr);
    EXPECT_TRUE(hspElf->IsValid());
    EXPECT_EQ(hspElf->GetBaseOffset(), 0x1000U);

    // prev map fallback: curOffset is zero, the elf sits at prevMap->offset
    auto prevMap = std::make_shared<DfxMap>(0x7000000, 0x7000000 + image.size(), 0x1000, PROT_READ, hqfPath);
    CompressHapElfFactory hqfFactory(hqfPath, prevMap, 0, 0);
    auto hqfElf = hqfFactory.Create();
    ASSERT_NE(hqfElf, nullptr);
    EXPECT_EQ(hqfElf->GetBaseOffset(), 0x1000U);

    unlink(hspPath.c_str());
    unlink(hqfPath.c_str());
    GTEST_LOG_(INFO) << "ElfFactoryTest021: end.";
}

/**
 * @tc.name: ElfFactoryTest022
 * @tc.desc: test ElfFactorySelector routes hsp and hqf sandbox maps like hap maps
 * @tc.type: FUNC
 */
HWTEST_F(ElfFactoryTest, ElfFactoryTest022, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ElfFactoryTest022: start.";
    auto prev = std::make_shared<DfxMap>(0x7000000, 0x7001000, 0x800, PROT_READ,
        "/data/storage/el1/bundle/test.hsp");

    // no rtti in this target: assert through the observable map offset side effects
    DfxMap hspMap(0x7001000, 0x7002000, 0x1000, PROT_READ, "/data/storage/el1/bundle/test.hsp");
    hspMap.prevMap = prev;
    auto hspFactory = ElfFactorySelector::Select(hspMap, getpid());
    ASSERT_NE(hspFactory, nullptr);
    EXPECT_EQ(hspMap.offset, 0x800U); // 0x800 : relative to the previous hsp map

    DfxMap hqfMap(0x7002000, 0x7003000, 0x1000, PROT_READ, "/data/storage/el1/bundle/patch/test.hqf");
    hqfMap.prevMap = prev;
    auto hqfFactory = ElfFactorySelector::Select(hqfMap, getpid());
    ASSERT_NE(hqfFactory, nullptr);
    EXPECT_EQ(hqfMap.offset, 0x800U); // 0x800 : relative to the previous hqf map

    // hsp outside the sandbox is not routed to the compressed hap path: no rebasing
    DfxMap sysHspMap(0x7003000, 0x7004000, 0x1000, PROT_READ, "/system/app/test/test.hsp");
    sysHspMap.prevMap = prev;
    auto sysHspFactory = ElfFactorySelector::Select(sysHspMap, getpid());
    ASSERT_NE(sysHspFactory, nullptr);
    EXPECT_EQ(sysHspMap.offset, 0x1000U);
    GTEST_LOG_(INFO) << "ElfFactoryTest022: end.";
}
}
}
