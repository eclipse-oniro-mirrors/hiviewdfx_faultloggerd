/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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
#ifndef DFX_MMAP_H
#define DFX_MMAP_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>
#if !is_mingw
#include <sys/mman.h>
#else
#include "dfx_nonlinux_define.h"
#endif
#include "dfx_memory.h"

namespace OHOS {
namespace HiviewDFX {
#if defined(ENABLE_MINIDEBUGINFO)
// One compressed block of the .gnu_debugdata xz stream, in decompressed-image
// coordinates (dstOff/unpackSize) and stream coordinates (packOff/packSize,
// including the 4-byte alignment padding).
struct ChunkBlk {
    uint64_t dstOff = 0;
    uint64_t packOff = 0;
    uint64_t unpackSize = 0;
    uint64_t packSize = 0;
};

struct ChunkIndex {
    std::vector<ChunkBlk> entries;
    uint16_t streamFlags = 0;
};

// Decompresses single xz blocks of a .gnu_debugdata stream on demand. Owned by the
// paged DfxMmap, which decompresses each block straight into its final place.
class BlockProvider {
public:
    BlockProvider(const uint8_t *src, size_t srcLen, ChunkIndex index);
    ~BlockProvider() = default;
    // Decompresses one block straight into dst, which must hold blk.unpackSize bytes.
    // The caller owns dst and keeps the result resident, so each block is decompressed
    // at most once over the lifetime of the mapping.
    bool DecompressBlockInto(const ChunkBlk& blk, uint8_t* dst);
    bool DecompressBlock(const ChunkBlk& blk, std::vector<uint8_t>& out);
    const ChunkBlk* FindBlock(uintptr_t dstOff) const;
    // Index of the block containing dstOff, or Blocks().size() when out of range.
    size_t FindBlockIndex(uintptr_t dstOff) const;
    size_t TotalUnpackSize() const;
    const std::vector<ChunkBlk>& Blocks() const { return index_.entries; }
private:
    // Uniform blocks (all but the last equal to the first) let a block be located by
    // shifting the offset instead of a binary search. Every block of a .gnu_debugdata
    // produced by the standard toolchain is 1 MiB, so this is the common case.
    void DetectUniformBlockSize();
    const uint8_t *src_ = nullptr;
    size_t srcLen_ = 0;
    ChunkIndex index_;
    size_t blockShift_ = 0; // log2 of the uniform block size, 0 when blocks are not uniform
};
#endif
class DfxMmap : public DfxMemory {
public:
    DfxMmap() = default;
    virtual ~DfxMmap() { Clear(); }

    bool Init(const int fd, const size_t size, const off_t offset = 0);
    bool Init(std::vector<uint8_t>&& data);
    void Clear();

    // Paged mode keeps Get() returning nullptr: the reserved image is only valid once a
    // block has been decompressed into it, so raw pointer arithmetic would read zero-filled
    // pages. Use GetResidentPtr/Read for data access and GetVirtualBase for offset math.
    inline void* Get()
    {
#if defined(ENABLE_MINIDEBUGINFO)
        if (provider_ != nullptr) {
            return nullptr;
        }
#endif
        if (mmap_ != MAP_FAILED) {
            return mmap_;
        }
        return nullptr;
    }
    inline size_t Size() { return size_; }

    size_t Read(uintptr_t& addr, void* val, size_t size, bool incre = false) override;
    bool EnsureRangeResident(uintptr_t off, size_t size);
    const uint8_t* GetResidentPtr(uintptr_t off, size_t size);
    uintptr_t GetVirtualBase();
#if defined(ENABLE_MINIDEBUGINFO)
    // Paged mode: the whole decompressed image is reserved up front as anonymous memory
    // (untouched pages cost no RSS) and each block is decompressed into its final place
    // on first access. Once loaded a block is never evicted, so the linear symbol scan
    // decompresses every block at most once instead of re-decompressing on each frame.
    bool InitPaged(std::shared_ptr<BlockProvider> provider, size_t totalSize);
#endif

private:
    void *mmap_ = MAP_FAILED;
    size_t size_ = 0;
    std::vector<uint8_t> data_;
    bool needUnmap_ = true;
#if defined(ENABLE_MINIDEBUGINFO)
    bool EnsureBlocksResident(uintptr_t off, size_t size);
    std::shared_ptr<BlockProvider> provider_ = nullptr;
    std::vector<bool> blockLoaded_;
#endif
};
} // namespace HiviewDFX
} // namespace OHOS
#endif
