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
#include <fcntl.h>
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
}
#if defined(ENABLE_MINIDEBUGINFO)
std::shared_ptr<DfxElf> MiniDebugInfoFactory::Create()
{
    DFX_TRACE_SCOPED_DLSYM("CreateMiniDebugInfo");
    if (!UnwinderConfig::GetEnableMiniDebugInfo()) {
        return nullptr;
    }

    std::vector<uint8_t> miniDebugInfoData;
    if (!XzDecompress(reinterpret_cast<uint8_t *>(gnuDebugDataHdr_.address),
        gnuDebugDataHdr_.size, miniDebugInfoData)) {
        DFXLOGU("Failed to decompressed .gnu_debugdata seciton.");
        return nullptr;
    }
    // miniDebugInfoData store the decompressed bytes.
    // use these bytes to construct an elf.
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

bool MiniDebugInfoFactory::XzDecompress(const uint8_t *src, size_t srcLen, std::vector<uint8_t>& out)
{
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
    // P14:ART 的 dex2oat 原子改名顶掉该路径后(base.odex.tmp),目标
    // 进程可能仍映射着旧 inode。拿着新文件按旧映射解析会让所有回溯表
    // 错位、伪造错误帧,所以拒绝读取:返回未初始化 elf(与打开失败
    // 路径一致),让该模块退化为"无回溯信息"。匿名/未知身份(全 0)
    // 维持旧行为。
    if (devMajor_ != 0 && inode_ != 0) { // 两者齐全(真实文件)才校验,否则跳过
        struct stat st = {};
        if (fstat(smartFd.GetFd(), &st) != 0) {
            DFXLOGE("fstat failed, cannot verify identity: %{public}s, errno(%{public}d)",
                filePath_.c_str(), errno);
            return regularElf; // 未能核验:不锁存,可重试(旧行为)
        }
        // 内联解码 st_dev(与 musl/内核用户态编码一致),不用 major()/
        // minor() 宏:免去 <sys/sysmacros.h> 依赖,各目标(设备、linux
        // 宿主、mingw)都能编。
        const uint64_t dv = static_cast<uint64_t>(st.st_dev);
        const uint64_t stMajor = ((dv >> 32) & 0xfffff000ull) | ((dv >> 8) & 0xfffull);
        const uint64_t stMinor = ((dv >> 12) & 0xffffff00ull) | (dv & 0xffull);
        if (stMajor != devMajor_ || stMinor != devMinor_ ||
            static_cast<ino_t>(st.st_ino) != inode_) {
            DFXLOGE("Module file replaced (TOCTOU), skip reading: %{public}s", filePath_.c_str());
            return nullptr; // 与打开失败不同:此返回会被 DfxMap::GetElf 锁存
        }
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
      包裹文件内嵌 elf 的两种布局:
      1) apk:.so 的 ELF 头就在当前(r-xp)映射自身偏移处
         5fa116d000-5fa72f5000 r-xp 00aa3000 /system/app/X/X.apk  <- pc 在此,ELF 头位于该偏移
      2) hap:ELF 头位于前一个只读映射
         c3840000-c38a6000 r--p 00174000 /data/storage/.../entry.hap <- program header(前一映射)
         c38a6000-c3945000 r-xp 001d9000 /data/storage/.../entry.hap <- pc 在此
      先试当前映射自身偏移,再退回前一只读映射的偏移(对齐 libunwindstack
      MapInfo::CreateFileMemory)。
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
        // 暂态失败(fd 耗尽、时序):返回无效 elf(而非 nullptr),
        // DfxMap::GetElf 便不会锁存——保持与 RegularElfFactory 一致的
        // 每帧重试语义。
        return std::make_shared<DfxElf>();
    }

    // 1) apk:.so 的 ELF 头通常就在当前映射自身偏移处。
    if (curOffset_ != 0) {
        auto elf = LoadEmbeddedElf(smartFd.GetFd(), curOffset_, curSize_);
        if (elf != nullptr) {
            return elf;
        }
    }
    // 2) hap/兜底:ELF 头位于前一个只读映射。
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
        // 该偏移处不是 ELF 头,调用方会试下一个候选。
        return nullptr;
    }
    uint8_t classType = data[EI_CLASS];
    size_t elfSize = 0;
    uint64_t elfSizeRaw = 0;
    if (classType == ELFCLASS32) {
        const Elf32_Ehdr* ehdr = reinterpret_cast<const Elf32_Ehdr *>(data);
        uint64_t sectionSize = static_cast<uint64_t>(ehdr->e_shentsize) * ehdr->e_shnum;
        if (__builtin_add_overflow(static_cast<uint64_t>(ehdr->e_shoff), sectionSize, &elfSizeRaw)) {
            DFXLOGE("elf size overflow");
            return nullptr;
        }
    } else if (classType == ELFCLASS64) {
        const Elf64_Ehdr* ehdr = reinterpret_cast<const Elf64_Ehdr *>(data);
        uint64_t sectionSize = static_cast<uint64_t>(ehdr->e_shentsize) * ehdr->e_shnum;
        if (__builtin_add_overflow(static_cast<uint64_t>(ehdr->e_shoff), sectionSize, &elfSizeRaw)) {
            DFXLOGE("elf size overflow");
            return nullptr;
        }
    }
    elfSize = static_cast<size_t>(elfSizeRaw);
    if (elfSize == 0) {
        DFXLOGE("elf size equal zero, invalid elf at offset 0x%{public}" PRIx64, offset);
        return nullptr;
    }
    constexpr size_t maxElfSize = 1024 * 1024 * 1024; // 内嵌 ELF 的常规大小上限 1GB
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
