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

#ifndef ELF_FACTORY_H
#define ELF_FACTORY_H

#include <memory>
#include <mutex>
#include "dfx_define.h"
#include "dfx_elf.h"
#include "dfx_map.h"

namespace OHOS {
namespace HiviewDFX {
class ElfFactory {
public:
    virtual ~ElfFactory() = default;
    virtual std::shared_ptr<DfxElf> Create() = 0;
};

class RegularElfFactory : public ElfFactory {
public:
    explicit RegularElfFactory(const std::string& filePath,
        uint64_t devMajor = 0, uint64_t devMinor = 0, ino_t inode = 0)
        : filePath_(filePath), devMajor_(devMajor), devMinor_(devMinor), inode_(inode) {}
    ~RegularElfFactory() override = default;
    std::shared_ptr<DfxElf> Create() override;
private:
    std::string filePath_;
    // P14:目标进程实际映射的文件身份(取自 /proc/pid/maps),
    // 用于检测"先改名再替换"导致的 TOCTOU。
    uint64_t devMajor_ = 0;
    uint64_t devMinor_ = 0;
    ino_t inode_ = 0;
};

#if defined(ENABLE_MINIDEBUGINFO)
class MiniDebugInfoFactory : public ElfFactory {
public:
    explicit MiniDebugInfoFactory(const GnuDebugDataHdr& gnuDebugDataHdr) : gnuDebugDataHdr_(gnuDebugDataHdr) {}
    ~MiniDebugInfoFactory() override = default;
    std::shared_ptr<DfxElf> Create() override;
private:
    bool XzDecompress(const uint8_t *src, size_t srcLen, std::vector<uint8_t>& out);
    GnuDebugDataHdr gnuDebugDataHdr_{};
};
#endif

class CompressHapElfFactory : public ElfFactory {
public:
    // curOffset/curSize:当前映射自身的文件偏移与大小——apk 布局里内嵌
    // .so 的 ELF 头通常就在当前偏移处,先按它加载;prevMap 是 hap 布局
    // 的回退入口(ELF 头在前一只读映射)。两种布局详见 .cpp 的 Create()。
    explicit CompressHapElfFactory(std::string filePath, std::shared_ptr<DfxMap> prevMap,
                                   uint64_t curOffset = 0, uint64_t curSize = 0)
        : filePath_(std::move(filePath)), prevMap_(prevMap), curOffset_(curOffset), curSize_(curSize) {}
    ~CompressHapElfFactory() override = default;
    std::shared_ptr<DfxElf> Create() override;
private:
    // 从包文件的 (offset, size) 处加载内嵌 ELF:先按头大小 mmap 验证
    // ELF 魔数,由 e_shoff + 节头表大小推出 ELF 总长并做溢出/上限/文件
    // 边界校验,再整段 mmap、构造 DfxElf 且 baseOffset=offset。失败
    // 返回 nullptr,调用方换下一个候选偏移重试。
    std::shared_ptr<DfxElf> LoadEmbeddedElf(int fd, uint64_t offset, uint64_t size);
    const std::string filePath_;
    std::shared_ptr<DfxMap> prevMap_;
    uint64_t curOffset_ = 0;
    uint64_t curSize_ = 0;
};

class VdsoElfFactory : public ElfFactory {
public:
    explicit VdsoElfFactory(uint64_t begin, size_t size, pid_t pid) : begin_(begin), size_(size), pid_(pid) {}
    ~VdsoElfFactory() override = default;
    std::shared_ptr<DfxElf> Create() override;
private:
    VdsoElfFactory() = delete;
    MAYBE_UNUSED uint64_t begin_ = 0;
    MAYBE_UNUSED size_t size_ = 0;
    MAYBE_UNUSED pid_t pid_ = 0;
};
} // namespace HiviewDFX
} // namespace OHOS
#endif
