/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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
#ifndef ELF_CRAFT_BUILDER_H
#define ELF_CRAFT_BUILDER_H

#include <cstdint>
#include <elf.h>
#include <algorithm>
#include <string>
#include <type_traits>
#include <vector>

namespace OHOS {
namespace HiviewDFX {
/*
 * Build a small in-memory ELF image for unit tests. The image is intentionally
 * minimal but valid for ElfParser32/ElfParser64: one optional PT_LOAD, an
 * optional .text section, and an optional symbol table with function/object
 * symbols. It is used to drive DfxElf/DfxJitDebug paths (IsValidPc /
 * GetSectionInfo / GetFuncSymbols / FindGlobalVariableByName / LoadJitElf /
 * FindUnwindTableInfo) without any file on disk.
 */
struct CraftedElfOptions {
    bool withText = true;
    uint64_t textVaddr = 0x1000;
    uint64_t textSize = 0x100;
    bool withFuncSym = false;
    uint64_t funcVaddr = 0x2000;
    uint64_t funcSize = 0x80;
    bool withObjectSym = false;
    uint64_t objectVaddr = 0x4000;
    std::string objectName = "__jit_debug_descriptor";
    bool withLoad = true;
    uint64_t loadVaddr = 0x3000;
    uint64_t loadMemSize = 0x40;
    uint64_t loadAlign = 0x1000;
    bool elfClass32 = false;         // build an ELF32 image instead of ELF64
    bool withBadObjectSyms = false;  // symbols hitting the FindSymbolByName reject paths
    bool badPhentsize = false;       // e_phentsize below the struct size
    bool badPhoff = false;           // e_phoff beyond the image
    bool withSoname = false;         // add PT_DYNAMIC + DT_SONAME + .dynstr + .dynamic
    std::string soname = "libcrafted.z.so";
    // extra named sections appended after the built-in ones (.eh_frame_hdr / .eh_frame / ...)
    struct ExtraSection {
        std::string name;
        uint64_t addr = 0;
        std::vector<uint8_t> data;
        bool bogusOffset = false; // sh_offset points beyond the image on purpose
    };
    std::vector<ExtraSection> extraSections;
};

class ElfCraftBuilder {
public:
    static std::vector<uint8_t> Build(const CraftedElfOptions& opt)
    {
        if (opt.elfClass32) {
            return BuildT<Elf32_Ehdr, Elf32_Phdr, Elf32_Shdr, Elf32_Sym>(opt);
        }
        return BuildT<Elf64_Ehdr, Elf64_Phdr, Elf64_Shdr, Elf64_Sym>(opt);
    }

    // build a buffer which is definitely not an ELF
    static std::vector<uint8_t> BuildGarbage(size_t size)
    {
        std::vector<uint8_t> data(size, 0x41);
        return data;
    }

private:
    /* layout, names and collected data shared by the build steps */
    template <typename EhdrType, typename PhdrType, typename ShdrType, typename SymType>
    struct CraftedLayout {
        std::string shstrtab;
        std::string strtab;
        std::string dynstr;
        std::vector<SymType> syms;
        std::vector<uint32_t> nameExtras;
        std::vector<uint64_t> extraOffsets;
        uint32_t nameShstrtab = 0;
        uint32_t nameText = 0;
        uint32_t nameSymtab = 0;
        uint32_t nameStrtab = 0;
        uint32_t nameDynstr = 0;
        uint32_t nameDynamic = 0;
        uint32_t funcNameOff = 0;
        uint32_t objectNameOff = 0;
        uint32_t badUndefOff = 0;
        uint16_t shnum = 2; // 2 : null section and .shstrtab
        uint16_t idxText = 0;
        uint16_t idxSymtab = 0;
        uint16_t idxStrtab = 0;
        uint16_t idxDynstr = 0;
        uint16_t idxDynamic = 0;
        uint16_t idxExtraBase = 0;
        uint16_t loadNum = 0;
        uint16_t dynNum = 0;
        uint16_t phnum = 0;
        uint64_t textOffset = 0;
        uint64_t symtabOffset = 0;
        uint64_t strtabOffset = 0;
        uint64_t dynstrOffset = 0;
        uint64_t dynOffset = 0;
        uint64_t shstrtabOffset = 0;
        uint64_t shoff = 0;
        uint64_t total = 0;
        size_t dynEntSize = 0;
        size_t dynCount = 0;
    };

    template <typename SymType>
    static SymType MakeSym(uint32_t name, uint8_t type, uint16_t shndx, uint64_t value, uint64_t size)
    {
        SymType sym {};
        sym.st_name = name;
        sym.st_info = ELF32_ST_INFO(STB_GLOBAL, type);
        sym.st_shndx = shndx;
        if constexpr (sizeof(sym.st_value) == sizeof(uint64_t)) { // 64 bit value field
            sym.st_value = value;
            sym.st_size = size;
        } else {
            sym.st_value = static_cast<uint32_t>(value);
            sym.st_size = static_cast<uint32_t>(size);
        }
        return sym;
    }

    /* collect the section name table, the symbol name table and the dynstr */
    template <typename EhdrType, typename PhdrType, typename ShdrType, typename SymType>
    static void CollectStrings(CraftedLayout<EhdrType, PhdrType, ShdrType, SymType>& lay,
        const CraftedElfOptions& opt, bool withSym)
    {
        lay.shstrtab.push_back('\0'); // leading null name for the null section
        auto addShstr = [&lay](const char* name) {
            uint32_t off = static_cast<uint32_t>(lay.shstrtab.size());
            lay.shstrtab.append(name);
            lay.shstrtab.push_back('\0');
            return off;
        };
        lay.nameShstrtab = addShstr(".shstrtab");
        if (opt.withText) {
            lay.nameText = addShstr(".text");
        }
        if (withSym) {
            lay.nameSymtab = addShstr(".symtab");
            lay.nameStrtab = addShstr(".strtab");
        }
        for (const auto& extra : opt.extraSections) {
            lay.nameExtras.push_back(addShstr(extra.name.c_str()));
        }
        if (opt.withSoname) {
            lay.nameDynstr = addShstr(".dynstr");
            lay.nameDynamic = addShstr(".dynamic");
            lay.dynstr.push_back('\0');
            lay.dynstr.append(opt.soname);
            lay.dynstr.push_back('\0');
        }
        lay.strtab.push_back('\0');
        if (opt.withFuncSym) {
            lay.funcNameOff = static_cast<uint32_t>(lay.strtab.size());
            lay.strtab.append("JitFunc");
            lay.strtab.push_back('\0');
        }
        if (opt.withObjectSym) {
            lay.objectNameOff = static_cast<uint32_t>(lay.strtab.size());
            lay.strtab.append(opt.objectName);
            lay.strtab.push_back('\0');
        }
        if (opt.withBadObjectSyms) {
            lay.badUndefOff = static_cast<uint32_t>(lay.strtab.size());
            lay.strtab.append("bad_undef"); // skipped because of SHN_UNDEF even with a valid value
            lay.strtab.push_back('\0');
            lay.strtab.append("bad_name_off"); // name offset variant is not referenced directly
            lay.strtab.push_back('\0');
            lay.strtab.append("X"); // unterminated tail: strnlen hits the strtab end
        }
    }

    /* build the symbol table content following the test options */
    template <typename EhdrType, typename PhdrType, typename ShdrType, typename SymType>
    static void CollectSymbols(CraftedLayout<EhdrType, PhdrType, ShdrType, SymType>& lay,
        const CraftedElfOptions& opt, bool withSym)
    {
        if (!withSym) {
            return;
        }
        lay.syms.push_back(SymType {}); // null symbol
        uint16_t symShndx = opt.withText ? lay.idxText : 1; // 1 : the .shstrtab index
        if (opt.withFuncSym) {
            lay.syms.push_back(MakeSym<SymType>(lay.funcNameOff, STT_FUNC, symShndx,
                opt.funcVaddr, opt.funcSize));
        }
        if (opt.withObjectSym) {
            lay.syms.push_back(MakeSym<SymType>(lay.objectNameOff, STT_OBJECT, symShndx,
                opt.objectVaddr, sizeof(uint64_t)));
        }
        if (opt.withBadObjectSyms) {
            // shndx UNDEF: skipped even with a valid value
            lay.syms.push_back(MakeSym<SymType>(lay.badUndefOff, STT_OBJECT, SHN_UNDEF,
                0x9000, sizeof(uint64_t)));
            // st_name beyond the strtab: skipped
            constexpr uint32_t nameOffsetBeyond = sizeof(uint64_t); // safely past the strtab end
            lay.syms.push_back(MakeSym<SymType>(static_cast<uint32_t>(lay.strtab.size() + nameOffsetBeyond),
                STT_OBJECT, symShndx, 0x9100, sizeof(uint64_t)));
            // name runs into the unterminated strtab tail: skipped
            lay.syms.push_back(MakeSym<SymType>(static_cast<uint32_t>(lay.strtab.size() - 1), // last char, no NUL
                STT_OBJECT, symShndx, 0x9200, sizeof(uint64_t)));
        }
    }

    /* assign the section indices and program header counts */
    template <typename EhdrType, typename PhdrType, typename ShdrType, typename SymType>
    static void ComputeIndices(CraftedLayout<EhdrType, PhdrType, ShdrType, SymType>& lay,
        const CraftedElfOptions& opt, bool withSym)
    {
        if (opt.withText) {
            lay.idxText = lay.shnum;
            lay.shnum++;
        }
        if (withSym) {
            lay.idxSymtab = lay.shnum;
            lay.shnum++;
            lay.idxStrtab = lay.shnum;
            lay.shnum++;
        }
        if (opt.withSoname) {
            lay.idxDynstr = lay.shnum;
            lay.shnum++;
            lay.idxDynamic = lay.shnum;
            lay.shnum++;
        }
        lay.idxExtraBase = lay.shnum;
        lay.shnum = static_cast<uint16_t>(lay.shnum + opt.extraSections.size());

        lay.loadNum = (opt.withLoad && !opt.badPhoff) ? 1 : 0;
        lay.dynNum = opt.withSoname ? 1 : 0;
        lay.phnum = static_cast<uint16_t>(lay.loadNum + lay.dynNum);
    }

    /* compute the byte offsets of every blob, needs the collected symbols */
    template <typename EhdrType, typename PhdrType, typename ShdrType, typename SymType>
    static void ComputeLayout(CraftedLayout<EhdrType, PhdrType, ShdrType, SymType>& lay,
        const CraftedElfOptions& opt, bool withSym)
    {
        uint64_t offset = sizeof(EhdrType) + (opt.badPhoff ? 0 : lay.phnum * sizeof(PhdrType));
        lay.textOffset = offset;
        if (opt.withText) {
            offset += opt.textSize;
        }
        lay.symtabOffset = offset;
        offset += lay.syms.size() * sizeof(SymType);
        lay.strtabOffset = offset;
        if (withSym) {
            offset += lay.strtab.size();
        }
        lay.dynstrOffset = offset;
        if (opt.withSoname) {
            offset += lay.dynstr.size();
        }
        using DynType = typename std::conditional<sizeof(EhdrType) == sizeof(Elf64_Ehdr),
            Elf64_Dyn, Elf32_Dyn>::type;
        lay.dynEntSize = sizeof(DynType);
        lay.dynCount = 4; // 4 : STRTAB, SONAME, STRSZ, NULL
        if (opt.withSoname) {
            const uint64_t dynAlign = (sizeof(EhdrType) == sizeof(Elf64_Ehdr)) ? 8 : 4; // 8 : Elf64_Dyn align
            offset = (offset + dynAlign - 1) & ~(dynAlign - 1);
        }
        lay.dynOffset = offset;
        offset += lay.dynCount * lay.dynEntSize;
        for (const auto& extra : opt.extraSections) {
            lay.extraOffsets.push_back(offset);
            offset += extra.data.size();
        }
        lay.shstrtabOffset = offset;
        offset += lay.shstrtab.size();
        const uint64_t shdrAlign = (sizeof(ShdrType) == sizeof(Elf64_Shdr)) ? 8 : 4; // 8 : Elf64_Shdr align
        lay.shoff = (offset + shdrAlign - 1) & ~(shdrAlign - 1);
        lay.total = lay.shoff + lay.shnum * sizeof(ShdrType);
    }

    /* write the elf header */
    template <typename EhdrType, typename PhdrType, typename ShdrType, typename SymType>
    static void WriteEhdr(std::vector<uint8_t>& image, const CraftedElfOptions& opt,
        const CraftedLayout<EhdrType, PhdrType, ShdrType, SymType>& lay)
    {
        EhdrType ehdr {};
        ehdr.e_ident[EI_MAG0] = ELFMAG0;
        ehdr.e_ident[EI_MAG1] = ELFMAG1;
        ehdr.e_ident[EI_MAG2] = ELFMAG2;
        ehdr.e_ident[EI_MAG3] = ELFMAG3;
        ehdr.e_ident[EI_CLASS] = (sizeof(EhdrType) == sizeof(Elf64_Ehdr)) ? ELFCLASS64 : ELFCLASS32;
        ehdr.e_ident[EI_DATA] = ELFDATA2LSB;
        ehdr.e_ident[EI_VERSION] = EV_CURRENT;
        ehdr.e_type = ET_DYN;
        ehdr.e_machine = (sizeof(EhdrType) == sizeof(Elf64_Ehdr)) ? EM_AARCH64 : EM_ARM;
        ehdr.e_version = EV_CURRENT;
        if (opt.badPhoff) {
            ehdr.e_phoff = lay.total + 0x1000; // 0x1000 : beyond the image
            ehdr.e_phnum = 1;
            ehdr.e_phentsize = static_cast<decltype(ehdr.e_phentsize)>(opt.badPhentsize ?
                sizeof(PhdrType) / 2 : sizeof(PhdrType)); // 2 : invalid half size
        } else {
            ehdr.e_phoff = (lay.phnum != 0) ? sizeof(EhdrType) : 0;
            ehdr.e_phnum = lay.phnum;
            ehdr.e_phentsize = static_cast<decltype(ehdr.e_phentsize)>(opt.badPhentsize ?
                sizeof(PhdrType) / 2 : sizeof(PhdrType)); // 2 : invalid half size
        }
        ehdr.e_shoff = lay.shoff;
        ehdr.e_ehsize = sizeof(EhdrType);
        ehdr.e_shentsize = sizeof(ShdrType);
        ehdr.e_shnum = lay.shnum;
        ehdr.e_shstrndx = 1; // 1 : the .shstrtab index
        PutObject(image, 0, ehdr);
    }

    /* write the load and dynamic program headers plus the dynamic entries */
    template <typename EhdrType, typename PhdrType, typename ShdrType, typename SymType>
    static void WritePhdrs(std::vector<uint8_t>& image, const CraftedElfOptions& opt,
        const CraftedLayout<EhdrType, PhdrType, ShdrType, SymType>& lay)
    {
        if (lay.loadNum != 0) {
            PhdrType phdr {};
            phdr.p_type = PT_LOAD;
            phdr.p_flags = PF_R | PF_X;
            if constexpr (sizeof(phdr.p_offset) == sizeof(uint64_t)) { // 64 bit address fields
                phdr.p_offset = 0;
                phdr.p_vaddr = opt.loadVaddr;
                phdr.p_paddr = opt.loadVaddr;
                phdr.p_filesz = 0; // 0 : gABI allows zero file size; the pc range comes from memsz
                phdr.p_memsz = opt.loadMemSize;
                phdr.p_align = opt.loadAlign;
            } else {
                phdr.p_offset = 0;
                phdr.p_vaddr = static_cast<uint32_t>(opt.loadVaddr);
                phdr.p_paddr = static_cast<uint32_t>(opt.loadVaddr);
                phdr.p_filesz = 0;
                phdr.p_memsz = static_cast<uint32_t>(opt.loadMemSize);
                phdr.p_align = static_cast<uint32_t>(opt.loadAlign);
            }
            PutObject(image, sizeof(EhdrType), phdr);
        }
        if (lay.dynNum == 0) {
            return;
        }
        PhdrType phdr {};
        phdr.p_type = PT_DYNAMIC;
        phdr.p_flags = PF_R;
        if constexpr (sizeof(phdr.p_offset) == sizeof(uint64_t)) { // 64 bit address fields
            phdr.p_offset = lay.dynOffset;
            phdr.p_vaddr = lay.dynOffset;
            phdr.p_filesz = lay.dynCount * lay.dynEntSize;
            phdr.p_memsz = lay.dynCount * lay.dynEntSize;
            phdr.p_align = 8; // 8 : alignment
        } else {
            phdr.p_offset = static_cast<uint32_t>(lay.dynOffset);
            phdr.p_vaddr = static_cast<uint32_t>(lay.dynOffset);
            phdr.p_filesz = static_cast<uint32_t>(lay.dynCount * lay.dynEntSize);
            phdr.p_memsz = static_cast<uint32_t>(lay.dynCount * lay.dynEntSize);
            phdr.p_align = 4; // 4 : alignment
        }
        PutObject(image, sizeof(EhdrType) + lay.loadNum * sizeof(PhdrType), phdr);

        using DynType = typename std::conditional<sizeof(EhdrType) == sizeof(Elf64_Ehdr),
            Elf64_Dyn, Elf32_Dyn>::type;
        auto makeDyn = [](uint64_t tag, uint64_t val) {
            DynType dyn {};
            if constexpr (sizeof(dyn.d_tag) == sizeof(uint64_t)) { // 64 bit tag field
                dyn.d_tag = static_cast<int64_t>(tag);
                dyn.d_un.d_val = val;
            } else {
                dyn.d_tag = static_cast<int32_t>(tag);
                dyn.d_un.d_val = static_cast<uint32_t>(val);
            }
            return dyn;
        };
        PutObject(image, lay.dynOffset, makeDyn(DT_STRTAB, lay.dynstrOffset));
        PutObject(image, lay.dynOffset + lay.dynEntSize, makeDyn(DT_SONAME, 1)); // 1 : soname offset in dynstr
        PutObject(image, lay.dynOffset + 2 * lay.dynEntSize, makeDyn(DT_STRSZ, lay.dynstr.size())); // 2 : third entry
        PutObject(image, lay.dynOffset + 3 * lay.dynEntSize, makeDyn(DT_NULL, 0)); // 3 : last entry
        PutBytes(image, lay.dynstrOffset, lay.dynstr);
    }

    /* write the symbol table and its strtab section headers and payload */
    template <typename EhdrType, typename PhdrType, typename ShdrType, typename SymType>
    static void WriteSymbolSections(std::vector<uint8_t>& image,
        const CraftedLayout<EhdrType, PhdrType, ShdrType, SymType>& lay, bool withSym)
    {
        if (!withSym) {
            return;
        }
        ShdrType symShdr {};
        symShdr.sh_name = lay.nameSymtab;
        symShdr.sh_type = SHT_SYMTAB;
        symShdr.sh_offset = static_cast<decltype(symShdr.sh_offset)>(lay.symtabOffset);
        symShdr.sh_size = lay.syms.size() * sizeof(SymType);
        symShdr.sh_link = lay.idxStrtab;
        symShdr.sh_info = 1; // 1 : first non-local symbol
        symShdr.sh_addralign = (sizeof(SymType) == sizeof(Elf64_Sym)) ? 0x8 : 0x4; // 0x8 : Elf64_Sym align
        symShdr.sh_entsize = sizeof(SymType);
        PutObject(image, lay.shoff + lay.idxSymtab * sizeof(ShdrType), symShdr);

        ShdrType strShdr {};
        strShdr.sh_name = lay.nameStrtab;
        strShdr.sh_type = SHT_STRTAB;
        strShdr.sh_offset = static_cast<decltype(strShdr.sh_offset)>(lay.strtabOffset);
        strShdr.sh_size = lay.strtab.size();
        strShdr.sh_addralign = 0x1;
        PutObject(image, lay.shoff + lay.idxStrtab * sizeof(ShdrType), strShdr);

        for (size_t i = 0; i < lay.syms.size(); i++) {
            PutObject(image, lay.symtabOffset + i * sizeof(SymType), lay.syms[i]);
        }
        PutBytes(image, lay.strtabOffset, lay.strtab);
    }

    /* write the remaining named sections: text, dynstr, extras and shstrtab */
    template <typename EhdrType, typename PhdrType, typename ShdrType, typename SymType>
    static void WriteNamedSections(std::vector<uint8_t>& image, const CraftedElfOptions& opt,
        const CraftedLayout<EhdrType, PhdrType, ShdrType, SymType>& lay)
    {
        if (opt.withText) {
            ShdrType shdr {};
            shdr.sh_name = lay.nameText;
            shdr.sh_type = SHT_PROGBITS;
            shdr.sh_flags = SHF_ALLOC | SHF_EXECINSTR;
            if constexpr (sizeof(shdr.sh_addr) == sizeof(uint64_t)) { // 64 bit address fields
                shdr.sh_addr = opt.textVaddr;
                shdr.sh_offset = lay.textOffset;
                shdr.sh_size = opt.textSize;
            } else {
                shdr.sh_addr = static_cast<uint32_t>(opt.textVaddr);
                shdr.sh_offset = static_cast<uint32_t>(lay.textOffset);
                shdr.sh_size = static_cast<uint32_t>(opt.textSize);
            }
            shdr.sh_addralign = 0x4;
            PutObject(image, lay.shoff + lay.idxText * sizeof(ShdrType), shdr);
        }
        if (opt.withSoname) {
            ShdrType dynstrShdr {};
            dynstrShdr.sh_name = lay.nameDynstr;
            dynstrShdr.sh_type = SHT_STRTAB;
            dynstrShdr.sh_offset = static_cast<decltype(dynstrShdr.sh_offset)>(lay.dynstrOffset);
            dynstrShdr.sh_size = lay.dynstr.size();
            dynstrShdr.sh_addralign = 0x1;
            PutObject(image, lay.shoff + lay.idxDynstr * sizeof(ShdrType), dynstrShdr);

            ShdrType dynShdr {};
            dynShdr.sh_name = lay.nameDynamic;
            dynShdr.sh_type = SHT_DYNAMIC;
            dynShdr.sh_flags = SHF_ALLOC;
            dynShdr.sh_addr = static_cast<decltype(dynShdr.sh_addr)>(lay.dynOffset); // flat image: vaddr == offset
            dynShdr.sh_offset = static_cast<decltype(dynShdr.sh_offset)>(lay.dynOffset);
            dynShdr.sh_size = static_cast<decltype(dynShdr.sh_size)>(lay.dynCount * lay.dynEntSize);
            dynShdr.sh_link = lay.idxDynstr;
            dynShdr.sh_addralign = (sizeof(ShdrType) == sizeof(Elf64_Shdr)) ? 8 : 4; // 8 : Elf64_Dyn align
            dynShdr.sh_entsize = static_cast<decltype(dynShdr.sh_entsize)>(lay.dynEntSize);
            PutObject(image, lay.shoff + lay.idxDynamic * sizeof(ShdrType), dynShdr);
        }
        for (size_t i = 0; i < opt.extraSections.size(); i++) {
            const auto& extra = opt.extraSections[i];
            ShdrType shdr {};
            shdr.sh_name = lay.nameExtras[i];
            shdr.sh_type = SHT_PROGBITS;
            shdr.sh_flags = SHF_ALLOC;
            if constexpr (sizeof(shdr.sh_addr) == sizeof(uint64_t)) { // 64 bit address fields
                shdr.sh_addr = extra.addr;
                shdr.sh_offset = extra.bogusOffset ? (lay.total + 0x1000) : lay.extraOffsets[i]; // 0x1000 : beyond
                shdr.sh_size = extra.data.size();
            } else {
                shdr.sh_addr = static_cast<uint32_t>(extra.addr);
                shdr.sh_offset = static_cast<uint32_t>(extra.bogusOffset ? (lay.total + 0x1000)
                    : lay.extraOffsets[i]);
                shdr.sh_size = static_cast<uint32_t>(extra.data.size());
            }
            shdr.sh_addralign = 0x1;
            PutObject(image, lay.shoff + (lay.idxExtraBase + i) * sizeof(ShdrType), shdr);
            std::copy(extra.data.begin(), extra.data.end(),
                image.begin() + static_cast<long>(lay.extraOffsets[i]));
        }
        ShdrType shstrShdr {};
        shstrShdr.sh_name = lay.nameShstrtab;
        shstrShdr.sh_type = SHT_STRTAB;
        shstrShdr.sh_offset = static_cast<decltype(shstrShdr.sh_offset)>(lay.shstrtabOffset);
        shstrShdr.sh_size = lay.shstrtab.size();
        shstrShdr.sh_addralign = 0x1;
        PutObject(image, lay.shoff + 1 * sizeof(ShdrType), shstrShdr); // 1 : the .shstrtab index
        PutBytes(image, lay.shstrtabOffset, lay.shstrtab);
    }

    template <typename EhdrType, typename PhdrType, typename ShdrType, typename SymType>
    static std::vector<uint8_t> BuildT(const CraftedElfOptions& opt)
    {
        CraftedLayout<EhdrType, PhdrType, ShdrType, SymType> lay;
        const bool withSym = opt.withFuncSym || opt.withObjectSym || opt.withBadObjectSyms;
        CollectStrings(lay, opt, withSym);
        ComputeIndices(lay, opt, withSym);
        CollectSymbols(lay, opt, withSym);
        ComputeLayout(lay, opt, withSym);

        std::vector<uint8_t> image(lay.total, 0);
        WriteEhdr(image, opt, lay);
        WritePhdrs(image, opt, lay);
        WriteSymbolSections(image, lay, withSym);
        WriteNamedSections(image, opt, lay);
        return image;
    }

    template <typename T>
    static void PutObject(std::vector<uint8_t>& image, uint64_t offset, const T& obj)
    {
        const uint8_t* src = reinterpret_cast<const uint8_t*>(&obj);
        std::copy(src, src + sizeof(T), image.begin() + static_cast<long>(offset));
    }

    static void PutBytes(std::vector<uint8_t>& image, uint64_t offset, const std::string& bytes)
    {
        std::copy(bytes.begin(), bytes.end(), image.begin() + static_cast<long>(offset));
    }
};
} // namespace HiviewDFX
} // namespace OHOS
#endif // ELF_CRAFT_BUILDER_H
