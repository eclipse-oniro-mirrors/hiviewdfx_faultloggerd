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

#ifndef DFX_ELF_H
#define DFX_ELF_H

#include <functional>
#include <memory>
#include <mutex>
#include <set>
#include "dfx_elf_parser.h"
#include "dfx_map.h"

namespace OHOS {
namespace HiviewDFX {
struct DlCbData {
    uintptr_t pc;
    UnwindTableInfo uti;
    bool singleFde = false;
};

class DfxElf final {
public:
    DfxElf() { Init(); }
    explicit DfxElf (const std::shared_ptr<DfxMmap>& mmap) : mmap_(mmap) { Init(); }
    ~DfxElf() { Clear(); }

    void SetMmap(const std::shared_ptr<DfxMmap>& mmap) { mmap_ = mmap; }
    std::shared_ptr<DfxMmap> GetMmap() { return mmap_; }
    bool IsValid();
    uint8_t GetClassType();
    ArchType GetArchType();
    uint64_t GetElfSize();
    std::string GetElfName();
    std::string GetBuildId();
    void SetBuildId(const std::string& buildId);
    static std::string GetBuildId(uint64_t noteAddr, uint64_t noteSize);
    GnuDebugDataHdr GetGnuDebugDataHdr();
    uintptr_t GetGlobalPointer();
    int64_t GetLoadBias();
    uint64_t GetLoadBase(uint64_t mapStart, uint64_t mapOffset);
    void SetLoadBase(uint64_t base);
    uint64_t GetStartPc();
    uint64_t GetEndPc();
    uint64_t GetStartVaddr();
    uint64_t GetEndVaddr();
    // 判定运行时 pc 是否落在本 ELF 的代码区间内。与 /proc 映射无关,按
    // ELF 自身内容判定,三级策略:①SetRuntimeRange 设过运行时区间
    // (JIT ELF 专用)则直接比对;②用 PT_LOAD 段 [p_vaddr + loadBase,
    // + p_memsz) 匹配,任一段覆盖即真(对齐 libunwindstack
    // ElfInterface::IsValidPc);③无程序头时退回节区 vaddr 范围。
    // 主要调用方 DfxJitDebug:遍历 JIT 表项时判断 pc 属于哪个 JIT ELF——
    // JIT 代码在匿名映射里,DfxMaps 查不到,只能按 ELF 内容自证归属。
    bool IsValidPc(uint64_t pc);
    // JIT ELF 专用:记录 .text/符号的绝对运行时地址区间(ART JIT ELF 的
    // sh_addr/st_value 本就是运行时地址)。设置后 IsValidPc 与
    // FindUnwindTableInfo 按该区间判定,不再叠加 loadBase。
    void SetRuntimeRange(uint64_t start, uint64_t end)
    {
        runtimeStart_ = start;
        runtimeEnd_ = end;
    }
    uint64_t GetRuntimeStart() const { return runtimeStart_; }
    uint64_t GetRuntimeEnd() const { return runtimeEnd_; }
    bool HasRuntimeRange() const { return runtimeStart_ != static_cast<uint64_t>(-1) && runtimeEnd_ != 0; }
    void SetBaseOffset(uint64_t offset);
    uint64_t GetBaseOffset();
    uint64_t GetStartOffset();
    uint64_t GetRelPc(uint64_t pc, uint64_t mapStart, uint64_t mapOffset);
    const uint8_t* GetMmapPtr();
    size_t GetMmapSize();
    bool Read(uintptr_t pos, void* buf, size_t size);
    const std::unordered_map<uint64_t, ElfLoadInfo>& GetPtLoads();
    const std::set<ElfSymbol>& GetFuncSymbols();
    bool GetFuncInfo(uint64_t addr, ElfSymbol& elfSymbol);
    bool GetSectionInfo(ShdrInfo& shdr, const std::string secName);
    bool GetSectionData(unsigned char* buf, uint64_t size, std::string secName);
    int FindUnwindTableInfo(uintptr_t pc, std::shared_ptr<DfxMap> map, struct UnwindTableInfo& uti);
    static int FindUnwindTableLocal(uintptr_t pc, struct UnwindTableInfo& uti);
    bool IsAdlt();
    const std::vector<AdltMapInfo>& GetAdltMap() const;
    const std::string& GetAdltStrtab() const;
    std::string GetAdltOriginSoNameByRelPc(uint64_t relPc) const;
    bool FindFuncSymbolByName(std::string funcName, ElfSymbol& elfSymbol);
    // 按名字查找全局变量符号:遍历已解析的符号表(.symtab 与 .dynsym),
    // 跳过未定义/零值表项,在关联 .strtab 中比对名字,命中返回 st_value
    // (节内 vaddr)等。当前唯一调用方是 DfxJitDebug::FindJitDescriptor——
    // 在 libart.so/libartd.so 里定位 __jit_debug_descriptor(JIT 代码
    // 注册表头),st_value + 映射基址即其运行时地址。
    // 为何不复用既有查找:FindFuncSymbolByName 遍历的是解析期收集的
    // funcSymbols_ 集合,该集合只收 STT_FUNC/STT_GNU_IFUNC 函数符号,
    // __jit_debug_descriptor 这类 STT_OBJECT 数据符号不在其中,且其
    // 比对前还做一层 C++ Demangle;GetFuncSymbolByAddr 则是按地址反查,
    // 方向不对。按名查变量只能直扫原始符号表,故新增此路径。
    bool FindGlobalVariableByName(const std::string& name, ElfSymbol& elfSymbol);
    // 从 OAT 头解析 executable_offset,返回可执行代码段起始处的 vaddr;
    // 非 OAT 文件(不以后缀 .odex/.oat 结尾,或 'oat\n' 魔数不符)返回 0。
    // 用途:speed-profile 编译的 odex 主 ELF 无 .eh_frame,其 miniDebugInfo
    // (.gnu_debugdata 解压)的 .debug_frame 中 FDE 区间相对"代码段起点"
    // (= OatHeader + executable_offset)起算;DwarfEntryParser 须以
    // checkPc = pc - segbase - 本返回值 换算后才能与 FDE 区间比对,
    // 不减则 odex 代码等于无回溯信息。
    // 实现要点:①OatHeader 定位兼容两种容器形态——平铺 OAT(文件偏移 0
    // 即魔数,vaddr 0)与 ELF 包裹(应用 base.odex / boot.oat,OatHeader
    // 位于 .oatdata 节起始,取 shdr.offset/shdr.addr);②字段位置随 OAT
    // 版本变化(读偏移 +4 的 ASCII 版本号):≥225(android-13+)在 +32,
    // ≥195(android-12)在 +28,更老在 +24;③返回 oatHdrVaddr +
    // executableOffset,保持 vaddr 量纲与被减的 pc 一致;值非 0 且小于
    // 文件大小才算有效。
    uintptr_t GetOatExecutableOffset(std::shared_ptr<DfxMap> map, std::shared_ptr<DfxMmap> mmap);

protected:
    void Init();
    void Clear();
    bool InitHeaders();
    bool IsMiniDebugInfoValid();
#if is_ohos && !is_mingw
    static int DlPhdrCb(struct dl_phdr_info* info, size_t size, void* data);
    static void ParsePhdr(struct dl_phdr_info* info, const ElfW(Phdr)* (&pHdrSections)[4], const uintptr_t pc);
    static bool ProcessDynamic(const ElfW(Phdr)* pDynamic, ElfW(Addr) loadBase, UnwindTableInfo* uti);
    static struct DwarfEhFrameHdr* InitHdr(struct DwarfEhFrameHdr& synthHdr,
        struct dl_phdr_info* info, const ElfW(Phdr)* pEhHdr);
    static bool FindSection(struct dl_phdr_info* info, const std::string secName, ShdrInfo& shdr);
    static bool FillUnwindTableByEhhdrLocal(struct DwarfEhFrameHdr* hdr, struct UnwindTableInfo* uti);
#endif
    bool FillUnwindTableByEhhdr(struct DwarfEhFrameHdr* hdr, uintptr_t shdrBase, struct UnwindTableInfo* uti);
    static bool IsValidSectionOffset(const ShdrInfo& shdr, uint64_t mmapSize, uint64_t minSize);
    bool FillUnwindTableByEhFrame(ShdrInfo& shdr, uintptr_t loadBase, const std::string& mapName,
        struct UnwindTableInfo& uti);
    static bool FillUnwindTableByExidx(ShdrInfo shdr, uintptr_t loadBase, struct UnwindTableInfo* uti);
    bool FindFuncSymbol(uint64_t addr, const std::set<ElfSymbol>& symbols, ElfSymbol& elfSymbol);
    bool IsValidElf(const void* ptr, size_t size);
    bool GetFuncInfoLazily(uint64_t addr, ElfSymbol& elfSymbol);

private:
    bool valid_ = false;
    uint8_t classType_ = 0;
    int64_t loadBias_ = 0;
    uint64_t loadBase_ = static_cast<uint64_t>(-1);
    uint64_t startPc_ = static_cast<uint64_t>(-1);
    uint64_t endPc_ = 0;
    uint64_t baseOffset_ = 0; // use for so in hap
    uint64_t runtimeStart_ = static_cast<uint64_t>(-1);
    uint64_t runtimeEnd_ = 0;
    std::string buildId_ = "";
    struct UnwindTableInfo uti_;
    bool hasTableInfo_ = false;
    std::shared_ptr<DfxMmap> mmap_ = nullptr;
    std::unique_ptr<ElfParser> elfParse_ = nullptr;
    std::set<ElfSymbol> funcSymbols_ {};
    std::shared_ptr<DfxElf> miniDebugInfo_ = nullptr;
};
} // namespace HiviewDFX
} // namespace OHOS
#endif
