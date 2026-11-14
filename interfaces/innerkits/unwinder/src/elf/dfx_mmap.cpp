/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "dfx_mmap.h"

#include <fcntl.h>
#include <securec.h>

#include "dfx_define.h"
#include "dfx_log.h"
#include "dfx_util.h"
#if defined(ENABLE_MINIDEBUGINFO)
#include "7zCrc.h"
#include "Xz.h"
#include "XzCrc64.h"
#endif

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxMmap"
}

#if defined(ENABLE_MINIDEBUGINFO)
namespace {
constexpr size_t XZ_BLOCK_BUF_INIT_SIZE = 4096;
constexpr size_t XZ_BUF_GROW_FACTOR = 2;
constexpr size_t XZ_MIN_UNIFORM_BLOCK_COUNT = 2; // need >= 2 equal-size blocks to prove uniformity
constexpr size_t XZ_BISECT_DIVISOR = 2;

void* XzAlloc(ISzAllocPtr, size_t size)
{
    return malloc(size);
}

void XzFree(ISzAllocPtr, void *address)
{
    free(address);
}

// Decode one xz block starting at src[*srcOff] into out (grown on demand); *srcOff
// advances to the block end and packSize receives the block's packed size for the
// index. Returns false on corrupted input, an exhausted stream or a zero-progress
// decode (without the progress check a malformed block could loop forever).
bool DecodeXzBlock(const uint8_t *src, size_t srcLen, size_t &srcOff,
    uint16_t streamFlags, std::vector<uint8_t> &out, uint64_t &packSize)
{
    if (src == nullptr || srcOff >= srcLen) {
        DFXLOGE("Invalid xz block offset: %{public}zu, srcLen: %{public}zu", srcOff, srcLen);
        return false;
    }
    // The xz block check (CRC32/CRC64) is verified against g_CrcTable/g_Crc64Table,
    // which start zeroed; without generating them every block decode fails with
    // SZ_ERROR_CRC on a fresh process (XzDecompress generates them likewise).
    CrcGenerateTable();
    Crc64GenerateTable();
    ISzAlloc alloc;
    alloc.Alloc = XzAlloc;
    alloc.Free = XzFree;
    CXzUnpacker state;
    XzUnpacker_Construct(&state, &alloc);
    XzUnpacker_Init(&state);
    state.streamFlags = static_cast<CXzStreamFlags>(streamFlags);
    XzUnpacker_PrepareToRandomBlockDecoding(&state);
    out.clear();
    size_t dstOff = 0;
    size_t blockStart = srcOff;
    ECoderStatus status = CODER_STATUS_NOT_FINISHED;
    int res = SZ_OK;
    do {
        size_t srcRemain = srcLen - srcOff;
        if (srcRemain == 0) {
            break;
        }
        size_t dstRemain = out.size() - dstOff;
        if (dstRemain == 0) {
            out.resize(out.empty() ? XZ_BLOCK_BUF_INIT_SIZE : out.size() * XZ_BUF_GROW_FACTOR);
            dstRemain = out.size() - dstOff;
        }
        size_t prevSrcOff = srcOff;
        size_t prevDstOff = dstOff;
        // CODER_FINISH_ANY: the output buffer is grown on demand, so a single call must be
        // allowed to stop when the buffer is full. CODER_FINISH_END would fail with SZ_ERROR
        // as soon as the buffer fills, before the block is complete.
        res = XzUnpacker_Code(&state, out.data() + dstOff, &dstRemain,
            src + srcOff, &srcRemain, false, CODER_FINISH_ANY, &status);
        srcOff += srcRemain;
        dstOff += dstRemain;
        if (res == SZ_OK && srcOff == prevSrcOff && dstOff == prevDstOff) {
            break;
        }
    } while (res == SZ_OK && !XzUnpacker_IsBlockFinished(&state));
    bool finished = (res == SZ_OK) && XzUnpacker_IsBlockFinished(&state);
    if (finished) {
        // Use the bytes actually consumed (header + data + 4-byte alignment padding + check);
        // XzUnpacker_GetPackSizeForIndex omits the alignment padding, which would misalign
        // the next block's packOff in the chunk index.
        packSize = srcOff - blockStart;
    }
    XzUnpacker_Free(&state);
    out.resize(dstOff);
    return finished;
}
} // namespace
#endif

#if defined(ENABLE_MINIDEBUGINFO)
BlockProvider::BlockProvider(const uint8_t *src, size_t srcLen, ChunkIndex index)
    : src_(src), srcLen_(srcLen), index_(std::move(index))
{
    DetectUniformBlockSize();
}

void BlockProvider::DetectUniformBlockSize()
{
    blockShift_ = 0;
    if (index_.entries.size() < XZ_MIN_UNIFORM_BLOCK_COUNT) {
        return;
    }
    size_t firstSize = static_cast<size_t>(index_.entries.front().unpackSize);
    if (firstSize == 0 || (firstSize & (firstSize - 1)) != 0) {
        return;
    }
    size_t shift = 0;
    while ((static_cast<size_t>(1) << shift) < firstSize) {
        shift++;
    }
    for (size_t i = 0; i + 1 < index_.entries.size(); i++) {
        const ChunkBlk& blk = index_.entries[i];
        if (blk.unpackSize != firstSize || blk.dstOff != static_cast<uint64_t>(i) * firstSize) {
            return;
        }
    }
    // The trailing block may be shorter, but it must not overrun the uniform grid.
    const ChunkBlk& last = index_.entries.back();
    if (last.unpackSize == 0 || last.unpackSize > firstSize) {
        return;
    }
    blockShift_ = shift;
}

const ChunkBlk* BlockProvider::FindBlock(uintptr_t dstOff) const
{
    size_t index = FindBlockIndex(dstOff);
    return index < index_.entries.size() ? &index_.entries[index] : nullptr;
}

size_t BlockProvider::FindBlockIndex(uintptr_t dstOff) const
{
    if (index_.entries.empty()) {
        return 0;
    }
    if (blockShift_ != 0) {
        size_t index = static_cast<size_t>(dstOff) >> blockShift_;
        if (index >= index_.entries.size()) {
            return index_.entries.size();
        }
        const ChunkBlk& blk = index_.entries[index];
        if (dstOff >= blk.dstOff && dstOff - blk.dstOff < blk.unpackSize) {
            return index;
        }
        return index_.entries.size();
    }
    size_t lo = 0;
    size_t hi = index_.entries.size();
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / XZ_BISECT_DIVISOR;
        const ChunkBlk& blk = index_.entries[mid];
        if (dstOff < blk.dstOff) {
            hi = mid;
        } else if (dstOff >= blk.dstOff + blk.unpackSize) {
            lo = mid + 1;
        } else {
            return mid;
        }
    }
    return index_.entries.size();
}

size_t BlockProvider::TotalUnpackSize() const
{
    if (index_.entries.empty()) {
        return 0;
    }
    const ChunkBlk& last = index_.entries.back();
    return static_cast<size_t>(last.dstOff + last.unpackSize);
}

bool BlockProvider::DecompressBlock(const ChunkBlk& blk, std::vector<uint8_t>& out)
{
    if (src_ == nullptr || blk.packOff > srcLen_ || blk.packSize > srcLen_ - blk.packOff) {
        return false;
    }
    size_t srcOff = static_cast<size_t>(blk.packOff);
    uint64_t packSize = 0;
    if (!DecodeXzBlock(src_, srcLen_, srcOff, index_.streamFlags, out, packSize)) {
        return false;
    }
    // Index consistency check: the decoded block must match the recorded sizes,
    // otherwise a corrupted index would misalign subsequent block reads.
    return packSize == blk.packSize && out.size() == static_cast<size_t>(blk.unpackSize);
}

bool BlockProvider::DecompressBlockInto(const ChunkBlk& blk, uint8_t* dst)
{
    if (dst == nullptr) {
        return false;
    }
    std::vector<uint8_t> out;
    if (!DecompressBlock(blk, out)) {
        return false;
    }
    if (memcpy_s(dst, static_cast<size_t>(blk.unpackSize), out.data(), out.size()) != 0) {
        DFXLOGE("Failed to copy decompressed block");
        return false;
    }
    return true;
}
#endif

bool DfxMmap::Init(const int fd, const size_t size, const off_t offset)
{
    Clear();

    if (fd < 0) {
        return false;
    }
    mmap_ = mmap(nullptr, size, PROT_READ, MAP_PRIVATE, fd, offset);
    if (mmap_ == MAP_FAILED) {
        DFXLOGE("Failed to mmap, errno(%{public}d)", errno);
        size_ = 0;
        return false;
    }
    needUnmap_ = true;
    size_ = size;
    DFXLOGD("mmap size %{public}zu", size_);
    return true;
}

bool DfxMmap::Init(std::vector<uint8_t>&& data)
{
    if (data.size() == 0) {
        return false;
    }

    data_ = std::move(data);
    mmap_ = data_.data();
    size_ = data_.size();
    needUnmap_ = false;
    return true;
}

void DfxMmap::Clear()
{
    if ((mmap_ != MAP_FAILED) && (needUnmap_)) {
        munmap(mmap_, size_);
        mmap_ = MAP_FAILED;
    }
#if defined(ENABLE_MINIDEBUGINFO)
    if (provider_ != nullptr) {
        provider_.reset();
        blockLoaded_.clear();
        size_ = 0;
    }
#endif
}

size_t DfxMmap::Read(uintptr_t& addr, void* val, size_t size, bool incre)
{
    if (val == nullptr) {
        return 0;
    }
    size_t ptr = static_cast<size_t>(addr);
    if (ptr >= size_) {
        DFXLOGU("pos: %{public}zu, size: %{public}zu", ptr, size_);
        return 0;
    }
    size_t actualLen = std::min(size_ - ptr, size);
#if defined(ENABLE_MINIDEBUGINFO)
    if (provider_ != nullptr) {
        if (!EnsureBlocksResident(addr, actualLen)) {
            DFXLOGE("Failed to ensure blocks resident");
            return 0;
        }
        const uint8_t* base = static_cast<const uint8_t*>(mmap_) + ptr;
        if (memcpy_s(val, size, base, actualLen) != 0) {
            DFXLOGE("Failed to memcpy_s");
            return 0;
        }
        if (incre) {
            addr += actualLen;
        }
        return actualLen;
    }
#endif
    if (mmap_ == MAP_FAILED) {
        return 0;
    }
    const uint8_t* actualBase = static_cast<const uint8_t*>(mmap_) + ptr;
    if (memcpy_s(val, size, actualBase, actualLen) != 0) {
        DFXLOGE("Failed to memcpy_s");
        return 0;
    }
    if (incre) {
        addr += actualLen;
    }
    return actualLen;
}
bool DfxMmap::EnsureRangeResident(uintptr_t off, size_t size)
{
#if defined(ENABLE_MINIDEBUGINFO)
    if (provider_ == nullptr) {
        return true;
    }
    return EnsureBlocksResident(off, size);
#else
    return true;
#endif
}

#if defined(ENABLE_MINIDEBUGINFO)
bool DfxMmap::EnsureBlocksResident(uintptr_t off, size_t size)
{
    size_t offSize = static_cast<size_t>(off);
    if (offSize >= size_ || size == 0) {
        return true;
    }
    size_t needEnd = (size > size_ - offSize) ? size_ : (offSize + size);
    // Decompress every block overlapped by [off, needEnd) that is not loaded yet. Blocks
    // are written straight into their final position in the reserved image and never
    // evicted, so a block is decompressed at most once for the lifetime of the mapping.
    size_t index = provider_->FindBlockIndex(off);
    const std::vector<ChunkBlk>& blocks = provider_->Blocks();
    while (index < blocks.size() && static_cast<size_t>(blocks[index].dstOff) < needEnd) {
        const ChunkBlk& blk = blocks[index];
        if (!blockLoaded_[index]) {
            uint8_t* dst = static_cast<uint8_t*>(mmap_) + static_cast<size_t>(blk.dstOff);
            if (!provider_->DecompressBlockInto(blk, dst)) {
                DFXLOGE("Failed to decompress block %{public}zu", index);
                return false;
            }
            blockLoaded_[index] = true;
        }
        index++;
    }
    return true;
}
#endif

const uint8_t* DfxMmap::GetResidentPtr(uintptr_t off, size_t size)
{
    size_t offSize = static_cast<size_t>(off);
    if (offSize >= size_ || size == 0 || size > size_ - offSize) {
        return nullptr;
    }
#if defined(ENABLE_MINIDEBUGINFO)
    if (provider_ != nullptr) {
        if (!EnsureBlocksResident(off, size)) {
            return nullptr;
        }
        return static_cast<const uint8_t*>(mmap_) + offSize;
    }
#endif
    if (mmap_ == MAP_FAILED) {
        return nullptr;
    }
    return static_cast<const uint8_t*>(mmap_) + offSize;
}

uintptr_t DfxMmap::GetVirtualBase()
{
    if (mmap_ == MAP_FAILED) {
        return 0;
    }
    return reinterpret_cast<uintptr_t>(mmap_);
}

#if defined(ENABLE_MINIDEBUGINFO)
bool DfxMmap::InitPaged(std::shared_ptr<BlockProvider> provider, size_t totalSize)
{
    Clear();
    if (provider == nullptr || totalSize == 0) {
        return false;
    }
    // Reserve the full decompressed image as anonymous memory. Pages stay unbacked until
    // a block is decompressed into them, so untouched regions cost no physical memory.
    void* base = mmap(nullptr, totalSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (base == MAP_FAILED) {
        DFXLOGE("Failed to reserve paged mini debuginfo, size: %{public}zu, errno: %{public}d",
            totalSize, errno);
        return false;
    }
    provider_ = std::move(provider);
    blockLoaded_.assign(provider_->Blocks().size(), false);
    mmap_ = base;
    size_ = totalSize;
    needUnmap_ = true;
    return true;
}
#endif
} // namespace HiviewDFX
} // namespace OHOS
