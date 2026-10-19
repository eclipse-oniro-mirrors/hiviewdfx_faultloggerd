/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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
#ifndef DFX_ELF_PARSER_H
#define DFX_ELF_PARSER_H

#include <cstddef>
#if is_mingw
#include "dfx_nonlinux_define.h"
#else
#include <elf.h>
#include <link.h>
#endif
#include <map>
#include <memory>
#include <stdint.h>
#include <string>
#include <sys/stat.h>
#include <sys/types.h>
#include <set>
#include <unistd.h>
#include <unordered_map>
#include <vector>

#include "dfx_define.h"
#include "dfx_elf_define.h"
#include "dfx_mmap.h"
#include "dfx_symbol.h"
#include "unwind_context.h"

namespace OHOS {
namespace HiviewDFX {
class ElfParser {
public:
    ElfParser(const std::shared_ptr<DfxMmap>& mmap) : mmap_(mmap) {}
    virtual ~ElfParser() = default;

    virtual bool InitHeaders() = 0;
    virtual ArchType GetArchType() { return archType_; }
    virtual uint64_t GetElfSize();
    virtual int64_t GetLoadBias() { return loadBias_; }
    virtual uint64_t GetStartVaddr() { return startVaddr_; }
    virtual uint64_t GetEndVaddr() { return endVaddr_; }
    virtual uint64_t GetStartOffset() { return startOffset_; }
    virtual std::string GetElfName() = 0;
    virtual uintptr_t GetGlobalPointer() = 0;
    virtual const std::set<ElfSymbol>& GetFuncSymbols() = 0;
    virtual bool GetSectionInfo(ShdrInfo& shdr, const uint32_t idx);
    virtual bool GetSectionInfo(ShdrInfo& shdr, const std::string& secName);
    virtual bool GetSectionData(unsigned char *buf, uint64_t size, std::string secName);
    virtual bool GetFuncSymbolByAddr(uint64_t addr, ElfSymbol& elfSymbol) = 0;
    // 按名字在符号表中线性查找符号,命中填充并返回 ElfSymbol
    // (value=st_value、size=st_size、name/nameStr)。遍历解析期收集的
    // 全部符号表 section(symShdrs_,.symtab 与 .dynsym 都在):每个
    // section 先经 shdr.link 取关联字符串表(.strtab/.dynstr),再按
    // size/entSize 逐项读 SymType;跳过未定义表项(SHN_UNDEF,导入
    // 符号在本文件内无地址)、st_value==0 及 st_name 越界者,名字用
    // strnlen 界定后做精确比对,首个命中即返回。新增原因:既有按名查找
    // (FindFuncSymbolByName)遍历的 funcSymbols_ 集合只收 STT_FUNC/
    // STT_GNU_IFUNC 函数符号,按名查全局变量(如 libart 的
    // __jit_debug_descriptor)查不到,只能直扫原始符号表(完整对比见
    // DfxElf::FindGlobalVariableByName)。不区分符号类型(函数/变量均可
    // 命中;变量查找入口即 FindGlobalVariableByName)。
    // 模板按 Elf32_Sym/Elf64_Sym 显式实例化,调用方先 64 后 32 尝试。
    template <typename SymType>
    bool FindSymbolByName(const std::string& name, ElfSymbol& elfSymbol);
    const std::unordered_map<uint64_t, ElfLoadInfo>& GetPtLoads() {return ptLoads_;}
    bool Read(uintptr_t pos, void *buf, size_t size);
    const GnuDebugDataHdr& GetGnuDebugDataHdr() const;
    std::string GetBuildId();
    static std::string ParseHexBuildId(uint64_t noteAddr, uint64_t noteSize);
    std::string GetAdltOriginSoNameByRelPc(uint64_t relPc) const;
    std::string GetNameByNameOffset(uint32_t nameOffset) const;
    const std::string& GetAdltStrtab() const { return adltStrtab_; }
    const std::vector<AdltMapInfo>& GetAdltMap() const { return adltMap_; }
    bool IsAdlt() { return ptAdlt; }

protected:
    size_t MmapSize();
    void GetAdltStrTabSectionInfo(uint64_t shOffset, uint64_t shSize);
    void GetAdltMapSectionInfo(uint64_t shOffset, uint64_t shSize);
    template <typename EhdrType, typename PhdrType, typename ShdrType>
    bool ParseAllHeaders();
    template <typename EhdrType>
    bool ParseElfHeaders(const EhdrType& ehdr);
    template <typename PhdrType>
    void UpdateVaddrAndOffset(const PhdrType& phdr);
    template <typename EhdrType, typename PhdrType>
    bool ParseProgramHeaders(const EhdrType& ehdr);
    template <typename ShdrType>
    void ExtractSymSectionHeadersInfo(const ShdrType& shdr);
    template <typename EhdrType, typename ShdrType>
    bool ExtractSectionHeadersInfo(const EhdrType& ehdr, ShdrType& shdr);
    template <typename EhdrType, typename ShdrType>
    bool ParseSectionHeaders(const EhdrType& ehdr);
    template <typename SymType>
    bool IsFunc(const SymType sym);
    template <typename SymType>
    bool ParseFuncSymbols();
    template <typename SymType>
    bool ParseFuncSymbols(const ElfShdr& shdr);
    template <typename SymType>
    bool ParseFuncSymbolName(const ShdrInfo& linkShdr, SymType sym, std::string& nameStr);
    template <typename SymType>
    bool ParseFuncSymbolByAddr(uint64_t addr, ElfSymbol& elfSymbol);
    template <typename DynType>
    bool ParseElfDynamic();
    template <typename DynType>
    bool ParseElfName();
    bool ParseStrTab(std::string& nameStr, const uint64_t offset, const uint64_t size);
    bool GetSectionNameByIndex(std::string& nameStr, const uint32_t name);
    template <typename SymType>
    bool ReadSymType(const ElfShdr& shdr, const uint32_t idx, SymType& sym);
    std::string ToReadableBuildId(const std::string& buildIdHex);

protected:
    std::set<ElfSymbol> funcSymbols_;
    uint64_t dynamicOffset_ = 0;
    uintptr_t dtPltGotAddr_ = 0;
    uintptr_t dtStrtabAddr_ = 0;
    uintptr_t dtStrtabSize_ = 0;
    uintptr_t dtSonameOffset_ = 0;
    std::string soname_ = "";
    GnuDebugDataHdr gnuDebugDataHdr_;

private:
    std::shared_ptr<DfxMmap> mmap_;
    ArchType archType_ = ARCH_UNKNOWN;
    uint64_t elfSize_ = 0;
    int64_t loadBias_ = 0;
    uint64_t startVaddr_ = static_cast<uint64_t>(-1);
    uint64_t startOffset_ = 0;
    uint64_t endVaddr_ = 0;
    std::vector<ElfShdr> symShdrs_;
    std::map<std::pair<uint32_t, const std::string>, ShdrInfo> shdrInfoPairs_;
    std::unordered_map<uint64_t, ElfLoadInfo> ptLoads_;
    std::string sectionNames_;
    bool ptAdlt = false;
    std::string adltStrtab_;
    std::vector<AdltMapInfo> adltMap_;
};

class ElfParser32 : public ElfParser {
public:
    ElfParser32(const std::shared_ptr<DfxMmap>& mmap) : ElfParser(mmap) {}
    virtual ~ElfParser32() = default;
    bool InitHeaders() override;
    std::string GetElfName() override;
    uintptr_t GetGlobalPointer() override;
    const std::set<ElfSymbol>& GetFuncSymbols() override;
    bool GetFuncSymbolByAddr(uint64_t addr, ElfSymbol& elfSymbol) override;
};

class ElfParser64 : public ElfParser {
public:
    ElfParser64(const std::shared_ptr<DfxMmap>& mmap) : ElfParser(mmap) {}
    virtual ~ElfParser64() = default;
    bool InitHeaders() override;
    std::string GetElfName() override;
    uintptr_t GetGlobalPointer() override;
    const std::set<ElfSymbol>& GetFuncSymbols() override;
    bool GetFuncSymbolByAddr(uint64_t addr, ElfSymbol& elfSymbol) override;
};

} // namespace HiviewDFX
} // namespace OHOS
#endif
