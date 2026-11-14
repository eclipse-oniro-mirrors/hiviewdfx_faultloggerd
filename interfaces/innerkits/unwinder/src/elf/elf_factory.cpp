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

#include "elf_factory.h"

#include <string>
#include <algorithm>
#include <cstdlib>
#include <cstring>
#include <fcntl.h>
#include <securec.h>
#include <unistd.h>
#include <utility>
#include <sys/stat.h>
#include <sys/types.h>

#include "dfx_define.h"
#include "dfx_log.h"
#include "dfx_maps.h"
#include "dfx_trace_dlsym.h"
#include "dfx_util.h"
#include "smart_fd.h"
#if defined(ENABLE_MINIDEBUGINFO)
#include "7zCrc.h"
#include "unwinder_config.h"
#include "Xz.h"
#include "XzCrc64.h"
#endif

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "ElfFactory"

bool ComputeEmbeddedElfSize(const uint8_t* data, size_t& elfSize)
{
    elfSize = 0;
    uint8_t classType = data[EI_CLASS];
    uint64_t elfSizeRaw = 0;
    if (classType == ELFCLASS32) {
        const Elf32_Ehdr* ehdr = reinterpret_cast<const Elf32_Ehdr *>(data);
        uint64_t sectionSize = static_cast<uint64_t>(ehdr->e_shentsize) * ehdr->e_shnum;
        if (__builtin_add_overflow(static_cast<uint64_t>(ehdr->e_shoff), sectionSize, &elfSizeRaw)) {
            DFXLOGE("elf size overflow");
            return false;
        }
    } else if (classType == ELFCLASS64) {
        const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr *>(data);
        uint64_t sectionSize = static_cast<uint64_t>(ehdr->e_shentsize) * ehdr->e_shnum;
        if (__builtin_add_overflow(static_cast<uint64_t>(ehdr->e_shoff), sectionSize, &elfSizeRaw)) {
            DFXLOGE("elf size overflow");
            return false;
        }
    }
    elfSize = static_cast<size_t>(elfSizeRaw);
    return true;
}
}
#if defined(ENABLE_MINIDEBUGINFO)
std::shared_ptr<DfxElf> MiniDebugInfoFactory::Create()
{
    DFX_TRACE_SCOPED_DLSYM("CreateMiniDebugInfo");
    if (!UnwinderConfig::GetEnableMiniDebugInfo()) {
        return nullptr;
    }
    auto src = reinterpret_cast<const uint8_t *>(gnuDebugDataHdr_.address);
    size_t srcLen = gnuDebugDataHdr_.size;
    if (src == nullptr || srcLen == 0) {
        return nullptr;
    }
    ChunkIndex idx = BuildChunkIndex(src, srcLen);
    if (idx.entries.size() > 1) {
        DFXLOGU("Paged mini debuginfo, blocks: %{public}zu", idx.entries.size());
        size_t totalSize = 0;
        for (const auto& blk : idx.entries) {
            totalSize += static_cast<size_t>(blk.unpackSize);
        }
        auto provider = std::make_shared<BlockProvider>(src, srcLen, std::move(idx));
        auto pagedMap = std::make_shared<DfxMmap>();
        if (totalSize > 0 && pagedMap->InitPaged(provider, totalSize)) {
            auto paged = std::make_shared<DfxElf>(pagedMap);
            if (paged->IsValid()) {
                return paged;
            }
            DFXLOGW("Paged mini debuginfo invalid, fallback to full decompress.");
        }
    }
    std::vector<uint8_t> miniDebugInfoData;
    if (!XzDecompress(src, srcLen, miniDebugInfoData)) {
        DFXLOGU("Failed to decompressed .gnu_debugdata seciton.");
        return nullptr;
    }
    auto mMap = std::make_shared<DfxMmap>();
    if (!mMap->Init(std::move(miniDebugInfoData))) {
        DFXLOGE("Failed to init mmap_!");
        return nullptr;
    }
    auto miniDebugInfo = std::make_shared<DfxElf>(mMap);
    if (!miniDebugInfo->IsValid()) {
        DFXLOGE("Failed to parse mini debuginfo Elf.");
        return nullptr;
    }
    return miniDebugInfo;
}

static void* XzAlloc(ISzAllocPtr, size_t size)
{
    return malloc(size);
}

static void XzFree(ISzAllocPtr, void *address)
{
    free(address);
}

// Reads one xz variable-length integer (little-endian base-128) at *pos.

bool MiniDebugInfoFactory::XzDecompress(const uint8_t *src, size_t srcLen, std::vector<uint8_t>& out)
{
    if (src == nullptr || srcLen == 0) {
        DFXLOGU("invalid .gnu_debugdata input, src is null or empty");
        return false;
    }
    DFX_TRACE_SCOPED_DLSYM("XzDecompress");
    ISzAlloc alloc;
    CXzUnpacker state;
    alloc.Alloc = XzAlloc;
    alloc.Free = XzFree;
    XzUnpacker_Construct(&state, &alloc);
    CrcGenerateTable();
    Crc64GenerateTable();
    size_t srcOff = 0;
    size_t dstOff = 0;
    out.resize(srcLen);
    ECoderStatus status = CODER_STATUS_NOT_FINISHED;
    constexpr uint16_t expandFactor = 2;
    while (status == CODER_STATUS_NOT_FINISHED) {
        out.resize(out.size() * expandFactor);
        size_t srcRemain = srcLen - srcOff;
        size_t dstRemain = out.size() - dstOff;
        int res = XzUnpacker_Code(&state,
                                  reinterpret_cast<Byte*>(&out[dstOff]), &dstRemain,
                                  reinterpret_cast<const Byte*>(&src[srcOff]), &srcRemain,
                                  true, CODER_FINISH_ANY, &status);
        if (res != SZ_OK) {
            XzUnpacker_Free(&state);
            return false;
        }
        srcOff += srcRemain;
        dstOff += dstRemain;
    }
    XzUnpacker_Free(&state);
    if (!XzUnpacker_IsStreamWasFinished(&state)) {
        return false;
    }
    out.resize(dstOff);
    return true;
}

// Reads one xz variable-length integer (little-endian base-128) at *pos.
constexpr int XZ_VARINT_BITS_PER_BYTE = 7; // LEB128 carries 7 payload bits per byte
constexpr int XZ_VARINT_MAX_BITS = 64;     // more than 9 bytes exceeds the uint64_t width

static bool ReadXzVarInt(const uint8_t *buf, size_t len, size_t &pos, uint64_t &val)
{
    val = 0;
    int shift = 0;
    while (pos < len) {
        uint8_t byte = buf[pos++];
        val |= static_cast<uint64_t>(byte & 0x7F) << shift;
        if ((byte & 0x80) == 0) {
            return true;
        }
        shift += XZ_VARINT_BITS_PER_BYTE;
        if (shift >= XZ_VARINT_MAX_BITS) { // more than 9 bytes: malformed
            return false;
        }
    }
    return false;
}

// Validates the stream footer and locates the xz Stream Index at the tail of the stream:
// *index/*indexSize describe the range [src+srcLen-footerSize-indexSize, src+srcLen-footerSize).
// Requires src != nullptr; returns false on any inconsistency (also implies srcLen >=
// XZ_STREAM_HEADER_SIZE, keeping subsequent header reads in bounds).
static bool LocateXzStreamIndex(const uint8_t *src, size_t srcLen, uint64_t &indexSize,
    const uint8_t *&index)
{
    constexpr size_t footerSize = XZ_STREAM_FOOTER_SIZE;
    if (srcLen < XZ_STREAM_HEADER_SIZE + footerSize) {
        return false;
    }
    // Stream Footer: CRC32(4) | Backward Size(4) | Stream Flags(2) | "YZ"(2).
    constexpr size_t footerBackwardSizeOffset = XZ_STREAM_CRC_SIZE;
    constexpr size_t footerSigOffset = footerBackwardSizeOffset + 4 + XZ_STREAM_FLAGS_SIZE;
    const uint8_t *footer = src + srcLen - footerSize;
    if (footer[footerSigOffset] != XZ_FOOTER_SIG_0 || footer[footerSigOffset + 1] != XZ_FOOTER_SIG_1) {
        DFXLOGE("Invalid xz footer signature");
        return false;
    }
    uint32_t backwardSize = 0;
    if (memcpy_s(&backwardSize, sizeof(backwardSize), footer + footerBackwardSizeOffset,
        sizeof(backwardSize)) != 0) {
        DFXLOGE("Failed to read xz footer backward size");
        return false;
    }
    // Backward Size is stored as (realSize / 4) - 1.
    indexSize = (static_cast<uint64_t>(backwardSize) + 1) * 4;
    if (indexSize + footerSize > srcLen - XZ_STREAM_HEADER_SIZE) {
        DFXLOGE("Invalid xz index size: %{public}" PRIu64, indexSize);
        return false;
    }
    index = src + srcLen - footerSize - indexSize;
    return true;
}

// Reads the Index Indicator (must be 0x00) and the record count at the Stream Index head.
static bool ReadXzIndexHeader(const uint8_t *index, uint64_t indexSize, size_t &pos,
    uint64_t &recordCount)
{
    if (index[pos++] != 0) {
        DFXLOGE("Invalid xz index indicator");
        return false;
    }
    if (!ReadXzVarInt(index, static_cast<size_t>(indexSize), pos, recordCount) || recordCount == 0) {
        DFXLOGE("Invalid xz index record count");
        return false;
    }
    return true;
}

// Builds the chunk index straight from the xz Stream Index at the tail of the stream.
// The index already records every block's unpadded size and uncompressed size, so this
// needs no decompression at all. Decompressing each block just to learn its sizes would
// cost a full decompress of the image (hundreds of ms for a large .gnu_debugdata) and
// defeat the point of paged access.
ChunkIndex MiniDebugInfoFactory::BuildChunkIndex(const uint8_t *src, size_t srcLen)
{
    ChunkIndex idx;
    if (src == nullptr) {
        return idx;
    }
    uint64_t indexSize = 0;
    const uint8_t *index = nullptr;
    if (!LocateXzStreamIndex(src, srcLen, indexSize, index)) {
        return idx;
    }
    CXzStreamFlags flags;
    if (Xz_ParseHeader(&flags, src) != SZ_OK) {
        return idx;
    }
    idx.streamFlags = static_cast<uint16_t>(flags);
    size_t pos = 0;
    uint64_t recordCount = 0;
    if (!ReadXzIndexHeader(index, indexSize, pos, recordCount)) {
        return idx;
    }
    uint64_t packOff = XZ_STREAM_HEADER_SIZE;
    uint64_t dstOff = 0;
    for (uint64_t i = 0; i < recordCount; i++) {
        uint64_t unpaddedSize = 0;
        uint64_t unpackSize = 0;
        if (!ReadXzVarInt(index, indexSize, pos, unpaddedSize) ||
            !ReadXzVarInt(index, indexSize, pos, unpackSize)) {
            DFXLOGE("Truncated xz index record");
            return ChunkIndex{};
        }
        // Unpadded size covers block header + compressed data + check, but the block is
        // padded to a multiple of four bytes; the padding belongs to the block's span.
        uint64_t paddedSize = unpaddedSize + ((4 - (unpaddedSize & 3)) & 3);
        // A zero-size record would stall the resident-window walk; a record past the
        // stream end means a corrupted index.
        if (unpaddedSize == 0 || unpackSize == 0 || paddedSize > srcLen - packOff) {
            DFXLOGE("Invalid xz index record %{public}" PRIu64, i);
            return ChunkIndex{};
        }
        ChunkBlk blk;
        blk.dstOff = dstOff;
        blk.unpackSize = unpackSize;
        blk.packOff = packOff;
        blk.packSize = paddedSize;
        idx.entries.push_back(blk);
        dstOff += unpackSize;
        packOff += paddedSize;
    }
    return idx;
}
#endif

std::shared_ptr<DfxElf> RegularElfFactory::Create()
{
    std::shared_ptr<DfxElf> regularElf = std::make_shared<DfxElf>();
    if (filePath_.empty()) {
        DFXLOGE("file path is empty!");
        return regularElf;
    }
    DFXLOGU("file: %{public}s %{public}zu", filePath_.c_str(), filePath_.size());
#if defined(is_ohos) && is_ohos
    if (!DfxMaps::IsLegalMapItem(filePath_)) {
        DFXLOGD("Illegal map file, please check file: %{public}s", filePath_.c_str());
        return regularElf;
    }
#endif

#if defined(is_mingw) && is_mingw
    int fd = OHOS_TEMP_FAILURE_RETRY(open(filePath_.c_str(), O_RDONLY | O_BINARY));
#else
    int fd = OHOS_TEMP_FAILURE_RETRY(open(filePath_.c_str(), O_RDONLY));
#endif
    SmartFd smartFd(fd);
    if (!smartFd) {
        DFXLOGE("Failed to open file: %{public}s, errno(%{public}d)", filePath_.c_str(), errno);
        return regularElf;
    }
    auto mMap = std::make_shared<DfxMmap>();
    if (!mMap->Init(smartFd.GetFd(), static_cast<size_t>(GetFileSize(smartFd.GetFd())), 0)) {
        DFXLOGE("Failed to mmap init.");
        return regularElf;
    }
    regularElf->SetMmap(mMap);
    return regularElf;
}

std::shared_ptr<DfxElf> VdsoElfFactory::Create()
{
#if is_ohos && !is_mingw
    /*
     * Memory needs to be allocated to read the memory mapping endpoint of the vdso.
     * To avoid allocating too much memory, the memory allocation is temporarily limited to a size of 10MB.
     */
    constexpr size_t maxMapSize = 10 * 1024 * 1024;
    if (size_ >= maxMapSize) {
        DFXLOGE("Invalid data size %{public}zu", size_);
        return nullptr;
    }
    std::vector<uint8_t> shmmData(size_);
    size_t byte = ReadProcMemByPid(pid_, begin_, shmmData.data(), size_);
    if (byte != size_) {
        DFXLOGE("Failed to read shmm data");
        return nullptr;
    }

    auto mMap = std::make_shared<DfxMmap>();
    if (!mMap->Init(std::move(shmmData))) {
        DFXLOGE("Failed to init mmap_!");
        return nullptr;
    }
    auto vdsoElf = std::make_shared<DfxElf>(mMap);
    if (!vdsoElf->IsValid()) {
        DFXLOGE("Failed to parse Embedded Elf.");
        return nullptr;
    }
    return vdsoElf;
#endif
    return nullptr;
}


std::shared_ptr<DfxElf> CompressHapElfFactory::Create()
{
    /*
      elf header is in the first mmap area
      c3840000-c38a6000 r--p 00174000 /data/storage/el1/bundle/entry.hap <- program header
      c38a6000-c3945000 r-xp 001d9000 /data/storage/el1/bundle/entry.hap <- pc is in this region
      c3945000-c394b000 r--p 00277000 /data/storage/el1/bundle/entry.hap
      c394b000-c394c000 rw-p 0027c000 /data/storage/el1/bundle/entry.hap
    */
    if (prevMap_ == nullptr && curOffset_ == 0) {
        DFXLOGE("no offset available for embedded elf, file: %{public}s", filePath_.c_str());
        return nullptr;
    }
    // Do not use the Realpath function, the sandbox path Realpath function will return failure
    bool isHap = EndsWith(filePath_, ".hap");
    bool isApk = EndsWith(filePath_, ".apk");
    if ((isHap && filePath_.find(SANDBOX_FILE_PATH_PREFIX) == std::string::npos) || (!isHap && !isApk)) {
        DFXLOGD("Illegal file path, please check file: %{public}s", filePath_.c_str());
        return nullptr;
    }
    SmartFd smartFd(static_cast<int>(OHOS_TEMP_FAILURE_RETRY(open(filePath_.c_str(), O_RDONLY))));
    if (!smartFd) {
        DFXLOGE("Failed to open hap file, errno(%{public}d)", errno);
        return nullptr;
    }

    if (curOffset_ != 0) {
        auto elf = LoadEmbeddedElf(smartFd.GetFd(), curOffset_, curSize_);
        if (elf != nullptr) {
            return elf;
        }
    }
    if (prevMap_ != nullptr) {
        auto elf = LoadEmbeddedElf(smartFd.GetFd(), prevMap_->offset, prevMap_->end - prevMap_->begin);
        if (elf != nullptr) {
            return elf;
        }
    }
    return {};
}

std::shared_ptr<DfxElf> CompressHapElfFactory::LoadEmbeddedElf(int fd, uint64_t offset, uint64_t size)
{
    size_t mapSize = std::max<uint64_t>(size, sizeof(Elf64_Ehdr));
    auto mmap = std::make_shared<DfxMmap>();
    if (!mmap->Init(fd, mapSize, static_cast<off_t>(offset))) {
        DFXLOGE("Failed to mmap header at offset 0x%{public}" PRIx64, offset);
        return nullptr;
    }
    const uint8_t* data = static_cast<const uint8_t*>(mmap->Get());
    if (data == nullptr || memcmp(data, ELFMAG, SELFMAG) != 0) {
        return nullptr;
    }
    size_t elfSize = 0;
    if (!ComputeEmbeddedElfSize(data, elfSize)) {
        return nullptr;
    }
    if (elfSize == 0) {
        DFXLOGE("elf size equal zero, invalid elf at offset 0x%{public}" PRIx64, offset);
        return nullptr;
    }
    constexpr size_t maxElfSize = 1024 * 1024 * 1024;
    if (elfSize > maxElfSize) {
        DFXLOGE("elf size too large: %{public}zu", elfSize);
        return nullptr;
    }
    auto fileSize = GetFileSize(fd);
    if (fileSize <= 0) {
        DFXLOGE("file size can not less or equal zero!");
        return nullptr;
    }
    uint64_t totalSize = 0;
    if (__builtin_add_overflow(static_cast<uint64_t>(elfSize), offset, &totalSize) ||
        totalSize > static_cast<uint64_t>(fileSize)) {
        DFXLOGE("Invalid elf size? elf size: %{public}zu, file size: %{public}zu, offset: 0x%{public}" PRIx64,
            elfSize, static_cast<size_t>(fileSize), offset);
        return nullptr;
    }
    auto mMap = std::make_shared<DfxMmap>();
    if (!mMap->Init(fd, elfSize, static_cast<off_t>(offset))) {
        DFXLOGE("Failed to init mmap_ at offset 0x%{public}" PRIx64, offset);
        return nullptr;
    }
    std::shared_ptr<DfxElf> elf = std::make_shared<DfxElf>(mMap);
    elf->SetBaseOffset(offset);
    if (!elf->IsValid()) {
        DFXLOGE("Failed to parse embedded elf at offset 0x%{public}" PRIx64, offset);
        return nullptr;
    }
    return elf;
}
} // namespace HiviewDFX
} // namespace OHOS
