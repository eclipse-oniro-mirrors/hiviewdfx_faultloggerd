/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#ifndef DFX_ELF_DEFINE_H
#define DFX_ELF_DEFINE_H

#include <cinttypes>
#include <string>
#if !is_mingw
#include <elf.h>
#include <link.h>
#endif

namespace OHOS {
namespace HiviewDFX {
static const std::string NOTE_GNU_BUILD_ID = ".note.gnu.build-id";
static const std::string NOTES = ".notes";
static const std::string GNU_DEBUGDATA = ".gnu_debugdata";
static const std::string EH_FRAME_HDR = ".eh_frame_hdr";
static const std::string EH_FRAME = ".eh_frame";
static const std::string ARM_EXIDX = ".ARM.exidx";
static const std::string ARM_EXTAB = ".ARM.extab";
static const std::string SHSTRTAB = ".shstrtab";
static const std::string STRTAB = ".strtab";
static const std::string SYMTAB = ".symtab";
static const std::string DYNSYM = ".dynsym";
static const std::string DYNSTR = ".dynstr";
static const std::string PLT = ".plt";

struct ElfLoadInfo {
    uint64_t offset = 0;
    uint64_t tableVaddr = 0;
    size_t tableSize = 0;
    uint64_t align = 0;
    uint64_t mmapLen = 0;
};

struct ElfSymbol {
    std::string nameStr = "";
    uint32_t name = 0;
    unsigned char info = 0;
    unsigned char other = 0;
    uint16_t shndx = 0;
    uint64_t value = 0;
    uint64_t size = 0;
};

struct ElfShdr {
    uint32_t	name = 0;       // Section name (string tbl index)
    uint32_t	type = 0;       // Section type
    uint64_t	flags = 0;      // Section flags
    uint64_t	addr = 0;       // Section virtual addr at execution
    uint64_t	offset = 0;     // Section file offset
    uint64_t	size = 0;       // Section size in bytes
    uint32_t	link = 0;       // Link to another section
    uint32_t	info = 0;       // Additional section information
    uint64_t	addrAlign = 0;  // Section alignment
    uint64_t	entSize = 0;    // Entry size if section holds table
};

struct ShdrInfo {
    uint64_t addr = 0;
    uint64_t entSize = 0;
    uint64_t offset = 0;
    uint64_t size = 0;
};

struct __attribute__((packed)) DwarfEhFrameHdr {
    unsigned char version = 0;
    unsigned char ehFramePtrEnc = 0;
    unsigned char fdeCountEnc = 0;
    unsigned char tableEnc = 0;
    ElfW(Addr) ehFrame;
};

struct MiniDebugInfo {
    uint64_t offset = 0;
    uintptr_t size = 0;
};

} // namespace HiviewDFX
} // namespace OHOS
#endif
