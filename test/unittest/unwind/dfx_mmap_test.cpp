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

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <vector>

#include "dfx_mmap.h"
#include "elf_factory.h"
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

class DfxMmapTest : public testing::Test {};

#if defined(ENABLE_MINIDEBUGINFO)
#ifndef __x86_64__
/**
 * @tc.name: DfxMmapTest001
 * @tc.desc: test InitPaged produces valid paged DfxMmap (AC-02)
 * @tc.type: FUNC
 */
HWTEST_F(DfxMmapTest, DfxMmapTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMmapTest001: start.";
    UnwinderConfig::SetEnableMiniDebugInfo(true);
    RegularElfFactory regularElfFactory(DUMPCATCHER_ELF_FILE);
    auto elf = regularElfFactory.Create();
    ASSERT_TRUE(elf->IsValid());
    auto hdr = elf->GetGnuDebugDataHdr();
    ASSERT_TRUE(hdr.size != 0);
    auto src = reinterpret_cast<const uint8_t *>(hdr.address);
    MiniDebugInfoFactory factory(hdr);
    ChunkIndex idx = factory.BuildChunkIndex(src, hdr.size);
    ASSERT_FALSE(idx.entries.empty());
    size_t totalSize = 0;
    for (const auto& blk : idx.entries) {
        totalSize += static_cast<size_t>(blk.unpackSize);
    }
    ASSERT_GT(totalSize, 0U);
    auto provider = std::make_shared<BlockProvider>(src, hdr.size, std::move(idx));
    auto mMap = std::make_shared<DfxMmap>();
    ASSERT_TRUE(mMap->InitPaged(provider, totalSize));
    EXPECT_EQ(mMap->Size(), totalSize);
    EXPECT_EQ(mMap->Get(), nullptr);
    ASSERT_TRUE(mMap->EnsureRangeResident(0, sizeof(uint8_t)));
    EXPECT_EQ(mMap->Get(), nullptr); // paged mode never exposes a forged base pointer (UB)
    EXPECT_NE(mMap->GetVirtualBase(), static_cast<uintptr_t>(0));
    EXPECT_NE(mMap->GetResidentPtr(0, sizeof(uint8_t)), nullptr);
    GTEST_LOG_(INFO) << "DfxMmapTest001: end.";
}

/**
 * @tc.name: DfxMmapTest002
 * @tc.desc: test EnsureRangeResident makes a mid-image range resident (AC-02)
 * @tc.type: FUNC
 */
HWTEST_F(DfxMmapTest, DfxMmapTest002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMmapTest002: start.";
    UnwinderConfig::SetEnableMiniDebugInfo(true);
    RegularElfFactory regularElfFactory(DUMPCATCHER_ELF_FILE);
    auto elf = regularElfFactory.Create();
    ASSERT_TRUE(elf->IsValid());
    auto hdr = elf->GetGnuDebugDataHdr();
    ASSERT_TRUE(hdr.size != 0);
    auto src = reinterpret_cast<const uint8_t *>(hdr.address);
    MiniDebugInfoFactory factory(hdr);
    ChunkIndex idx = factory.BuildChunkIndex(src, hdr.size);
    ASSERT_FALSE(idx.entries.empty());
    size_t totalSize = 0;
    for (const auto& blk : idx.entries) {
        totalSize += static_cast<size_t>(blk.unpackSize);
    }
    ASSERT_GT(totalSize, 0U);
    auto provider = std::make_shared<BlockProvider>(src, hdr.size, std::move(idx));
    auto mMap = std::make_shared<DfxMmap>();
    constexpr size_t readSize = 4096;
    ASSERT_TRUE(mMap->InitPaged(provider, totalSize));
    size_t off = totalSize / 2; // mid-offset
    size_t need = std::min<size_t>(readSize, totalSize - off);
    ASSERT_TRUE(mMap->EnsureRangeResident(static_cast<uintptr_t>(off), need));
    const uint8_t* base = mMap->GetResidentPtr(static_cast<uintptr_t>(off), need);
    ASSERT_NE(base, nullptr);
    GTEST_LOG_(INFO) << "DfxMmapTest002: end.";
}

/**
 * @tc.name: DfxMmapTest003
 * @tc.desc: test paged Read bytes match full decompression (AC-02)
 * @tc.type: FUNC
 */
HWTEST_F(DfxMmapTest, DfxMmapTest003, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMmapTest003: start.";
    UnwinderConfig::SetEnableMiniDebugInfo(true);
    RegularElfFactory regularElfFactory(DUMPCATCHER_ELF_FILE);
    auto elf = regularElfFactory.Create();
    ASSERT_TRUE(elf->IsValid());
    auto hdr = elf->GetGnuDebugDataHdr();
    ASSERT_TRUE(hdr.size != 0);
    auto src = reinterpret_cast<const uint8_t *>(hdr.address);
    size_t srcLen = hdr.size;
    MiniDebugInfoFactory factory(hdr);
    std::vector<uint8_t> fullOut;
    ASSERT_TRUE(factory.XzDecompress(src, srcLen, fullOut));
    ASSERT_FALSE(fullOut.empty());
    ChunkIndex idx = factory.BuildChunkIndex(src, srcLen);
    ASSERT_FALSE(idx.entries.empty());
    size_t totalSize = fullOut.size();
    auto provider = std::make_shared<BlockProvider>(src, srcLen, std::move(idx));
    auto mMap = std::make_shared<DfxMmap>();
    ASSERT_TRUE(mMap->InitPaged(provider, totalSize));
    constexpr size_t readSize = 256;
    std::vector<uint8_t> buf(readSize, 0);
    uintptr_t pos = 0;
    size_t got = mMap->Read(pos, buf.data(), readSize);
    size_t expect = std::min(readSize, totalSize);
    ASSERT_EQ(got, expect);
    EXPECT_EQ(memcmp(buf.data(), fullOut.data(), got), 0);
    if (totalSize > readSize) {
        pos = 100;
        got = mMap->Read(pos, buf.data(), readSize);
        expect = std::min(readSize, totalSize - 100);
        ASSERT_EQ(got, expect);
        EXPECT_EQ(memcmp(buf.data(), fullOut.data() + 100, got), 0);
    }
    GTEST_LOG_(INFO) << "DfxMmapTest003: end.";
}

namespace {
// Loads the real dumpcatcher minidebuginfo: full image bytes plus the block index.
// elf must be kept alive: it owns the mmap backing src, which the paged provider
// dereferences lazily during the tests.
struct PagedImage {
    std::shared_ptr<DfxElf> elf;
    const uint8_t *src = nullptr;
    size_t srcLen = 0;
    ChunkIndex idx;
    std::vector<uint8_t> fullOut;
};

bool LoadPagedImage(PagedImage &img)
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
    img.elf = elf;
    img.src = reinterpret_cast<const uint8_t *>(hdr.address);
    img.srcLen = static_cast<size_t>(hdr.size);
    MiniDebugInfoFactory factory(hdr);
    if (!factory.XzDecompress(img.src, img.srcLen, img.fullOut) || img.fullOut.empty()) {
        return false;
    }
    img.idx = factory.BuildChunkIndex(img.src, img.srcLen);
    return !img.idx.entries.empty();
}
} // namespace

/**
 * @tc.name: DfxMmapTest004
 * @tc.desc: test paged Read over the whole image walks every block and matches the
 *           full decompression, including repeated and overlapping reads (AC-02)
 * @tc.type: FUNC
 */
HWTEST_F(DfxMmapTest, DfxMmapTest004, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMmapTest004: start.";
    PagedImage img;
    ASSERT_TRUE(LoadPagedImage(img));
    auto provider = std::make_shared<BlockProvider>(img.src, img.srcLen, ChunkIndex{img.idx});
    auto mMap = std::make_shared<DfxMmap>();
    ASSERT_TRUE(mMap->InitPaged(provider, img.fullOut.size()));
    // one read spanning the whole image materializes every block, trailing block included
    std::vector<uint8_t> buf(img.fullOut.size(), 0);
    uintptr_t pos = 0;
    ASSERT_EQ(mMap->Read(pos, buf.data(), buf.size()), buf.size());
    EXPECT_EQ(memcmp(buf.data(), img.fullOut.data(), buf.size()), 0);
    // already-loaded blocks are reused: a repeated whole-image read stays consistent
    ASSERT_EQ(mMap->Read(pos, buf.data(), buf.size()), buf.size());
    EXPECT_EQ(memcmp(buf.data(), img.fullOut.data(), buf.size()), 0);
    // overlapping windowed reads over loaded blocks keep matching the full image
    constexpr size_t windowSize = 512;
    std::vector<uint8_t> win(windowSize, 0);
    for (uintptr_t off = 0; off + windowSize <= buf.size(); off += windowSize) {
        uintptr_t p = off;
        ASSERT_EQ(mMap->Read(p, win.data(), windowSize), windowSize);
        EXPECT_EQ(memcmp(win.data(), img.fullOut.data() + off, windowSize), 0);
    }
    GTEST_LOG_(INFO) << "DfxMmapTest004: end.";
}

/**
 * @tc.name: DfxMmapTest005
 * @tc.desc: test paged Read edge contract: end-of-image, clamped tail, incre cursor
 * @tc.type: FUNC
 */
HWTEST_F(DfxMmapTest, DfxMmapTest005, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMmapTest005: start.";
    PagedImage img;
    ASSERT_TRUE(LoadPagedImage(img));
    auto provider = std::make_shared<BlockProvider>(img.src, img.srcLen, ChunkIndex{img.idx});
    auto mMap = std::make_shared<DfxMmap>();
    ASSERT_TRUE(mMap->InitPaged(provider, img.fullOut.size()));
    // reading at or past the end yields nothing
    uintptr_t pos = img.fullOut.size();
    uint8_t byte = 0;
    EXPECT_EQ(mMap->Read(pos, &byte, sizeof(byte)), 0U);
    // a request crossing the end is clamped to the remaining bytes
    constexpr size_t tailSize = 16;
    ASSERT_GT(img.fullOut.size(), tailSize);
    std::vector<uint8_t> tail(tailSize * 2, 0); // deliberately overreads the image end
    pos = img.fullOut.size() - tailSize;
    EXPECT_EQ(mMap->Read(pos, tail.data(), tail.size()), tailSize);
    EXPECT_EQ(memcmp(tail.data(), img.fullOut.data() + pos, tailSize), 0);
    // sequential reads advance the cursor when incre is set (parser semantics)
    pos = 0;
    EXPECT_EQ(mMap->Read(pos, tail.data(), tailSize, true), tailSize);
    EXPECT_EQ(pos, static_cast<uintptr_t>(tailSize));
    EXPECT_EQ(memcmp(tail.data(), img.fullOut.data(), tailSize), 0);
    // residency for a range past the end is a graceful no-op
    EXPECT_TRUE(mMap->EnsureRangeResident(img.fullOut.size(), sizeof(uint8_t)));
    GTEST_LOG_(INFO) << "DfxMmapTest005: end.";
}

/**
 * @tc.name: DfxMmapTest006
 * @tc.desc: test GetResidentPtr bounds contract: refuses out-of-range ranges, serves
 *           bytes matching the full decompression for valid ones
 * @tc.type: FUNC
 */
HWTEST_F(DfxMmapTest, DfxMmapTest006, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMmapTest006: start.";
    PagedImage img;
    ASSERT_TRUE(LoadPagedImage(img));
    auto provider = std::make_shared<BlockProvider>(img.src, img.srcLen, ChunkIndex{img.idx});
    auto mMap = std::make_shared<DfxMmap>();
    ASSERT_TRUE(mMap->InitPaged(provider, img.fullOut.size()));
    const size_t total = img.fullOut.size();
    // out-of-range, empty and end-crossing requests never hand out a pointer
    EXPECT_EQ(mMap->GetResidentPtr(total, sizeof(uint8_t)), nullptr);
    EXPECT_EQ(mMap->GetResidentPtr(0, 0), nullptr);
    constexpr size_t probeSize = 16;
    ASSERT_GT(total, probeSize);
    EXPECT_EQ(mMap->GetResidentPtr(total - sizeof(uint8_t), probeSize), nullptr);
    // valid requests return bytes identical to the full decompression
    const uint8_t *head = mMap->GetResidentPtr(0, probeSize);
    ASSERT_NE(head, nullptr);
    EXPECT_EQ(memcmp(head, img.fullOut.data(), probeSize), 0);
    const size_t mid = total / 2; // mid-image probe: exercises a different block
    const uint8_t *body = mMap->GetResidentPtr(static_cast<uintptr_t>(mid), probeSize);
    ASSERT_NE(body, nullptr);
    EXPECT_EQ(memcmp(body, img.fullOut.data() + mid, probeSize), 0);
    GTEST_LOG_(INFO) << "DfxMmapTest006: end.";
}

/**
 * @tc.name: DfxMmapTest007
 * @tc.desc: test InitPaged guards and Clear releases the paged mapping
 * @tc.type: FUNC
 */
HWTEST_F(DfxMmapTest, DfxMmapTest007, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMmapTest007: start.";
    PagedImage img;
    ASSERT_TRUE(LoadPagedImage(img));
    auto provider = std::make_shared<BlockProvider>(img.src, img.srcLen, ChunkIndex{img.idx});
    auto mMap = std::make_shared<DfxMmap>();
    // an uninitialized mapping reports no base
    EXPECT_EQ(mMap->GetVirtualBase(), static_cast<uintptr_t>(0));
    // guards: missing provider, empty image and an absurd reservation are rejected
    EXPECT_FALSE(mMap->InitPaged(nullptr, img.fullOut.size()));
    EXPECT_FALSE(mMap->InitPaged(provider, 0));
    EXPECT_FALSE(mMap->InitPaged(provider, SIZE_MAX));
    // a valid reservation succeeds and is released by Clear
    ASSERT_TRUE(mMap->InitPaged(provider, img.fullOut.size()));
    EXPECT_EQ(mMap->Size(), img.fullOut.size());
    mMap->Clear();
    EXPECT_EQ(mMap->Size(), 0U);
    EXPECT_EQ(mMap->Get(), nullptr);
    uintptr_t pos = 0;
    uint8_t byte = 0;
    EXPECT_EQ(mMap->Read(pos, &byte, sizeof(byte)), 0U);
    EXPECT_EQ(mMap->GetResidentPtr(0, sizeof(byte)), nullptr);
    GTEST_LOG_(INFO) << "DfxMmapTest007: end.";
}

/**
 * @tc.name: DfxMmapTest008
 * @tc.desc: test paged reads degrade to zero on a tampered index instead of serving
 *           wrong bytes (index integrity propagation)
 * @tc.type: FUNC
 */
HWTEST_F(DfxMmapTest, DfxMmapTest008, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxMmapTest008: start.";
    PagedImage img;
    ASSERT_TRUE(LoadPagedImage(img));
    constexpr size_t probeSize = 16;
    std::vector<uint8_t> buf(probeSize, 0);
    // baseline: the intact index serves bytes from the same image
    auto validProvider = std::make_shared<BlockProvider>(img.src, img.srcLen, ChunkIndex{img.idx});
    auto validMap = std::make_shared<DfxMmap>();
    ASSERT_TRUE(validMap->InitPaged(validProvider, img.fullOut.size()));
    uintptr_t pos = 0;
    EXPECT_EQ(validMap->Read(pos, buf.data(), buf.size()), buf.size());
    // tampered index: the block decode is rejected and reads degrade to zero
    ChunkIndex tampered = img.idx;
    tampered.entries[0].packOff += 1;
    auto badProvider = std::make_shared<BlockProvider>(img.src, img.srcLen, ChunkIndex{tampered});
    auto badMap = std::make_shared<DfxMmap>();
    ASSERT_TRUE(badMap->InitPaged(badProvider, img.fullOut.size()));
    pos = 0;
    EXPECT_EQ(badMap->Read(pos, buf.data(), buf.size()), 0U);
    EXPECT_EQ(badMap->GetResidentPtr(0, buf.size()), nullptr);
    GTEST_LOG_(INFO) << "DfxMmapTest008: end.";
}
#endif //__x86_64__
#endif //ENABLE_MINIDEBUGINFO
} // namespace HiviewDFX
} // namespace OHOS
