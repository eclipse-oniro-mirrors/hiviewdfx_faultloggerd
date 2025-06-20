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
#ifndef DFX_COREDUMP_WRITER_H
#define DFX_COREDUMP_WRITER_H
#if defined(__aarch64__)

#include <elf.h>
#include <sys/procfs.h>

#include "dfx_coredump_common.h"
#include "dfx_regs.h"
#include "securec.h"

namespace OHOS {
namespace HiviewDFX {
class Writer {
public:
    Writer(char* mappedMemory, char* currentPointer) : mappedMemory_(mappedMemory),
        currentPointer_(currentPointer) {}
    virtual ~Writer() = default;
    virtual char* Write() = 0;
protected:
    bool CopyAndAdvance(const void* src, size_t size)
    {
        if (memcpy_s(currentPointer_, size, src, size) != EOK) {
            return false;
        }
        currentPointer_ += size;
        return true;
    }
    char* mappedMemory_;
    char* currentPointer_;
};

class ProgramSegmentHeaderWriter : public Writer {
public:
    ProgramSegmentHeaderWriter(char* mappedMemory, char* currentPointer, Elf64_Half* ePhnum,
        std::vector<DumpMemoryRegions>& maps) : Writer(mappedMemory, currentPointer), ePhnum_(ePhnum), maps_(maps) {}
    char* Write() override;
private:
    void ProgramSegmentHeaderFill(Elf64_Phdr *ph, Elf64_Word pType, Elf64_Word pFlags, struct DumpMemoryRegions region);
    void PtLoadFill(Elf64_Phdr *ph, struct DumpMemoryRegions region);
    void PtNoteFill(Elf64_Phdr *ph);
    Elf64_Half* ePhnum_;
    std::vector<DumpMemoryRegions> maps_;
};

class SegmentWriter : public Writer {
public:
    SegmentWriter(char* mappedMemory, char* currentPointer, pid_t pid, Elf64_Half ePhnum)
        : Writer(mappedMemory, currentPointer), pid_(pid), ePhnum_(ePhnum) {}
    char* Write() override;
private:
    void ReadProcessVmmem(Elf64_Phdr *ptLoad);
    pid_t pid_;
    Elf64_Half ePhnum_;
};

class NoteWriter : public Writer {
public:
    NoteWriter(char* mappedMemory, char* currentPointer, CoreDumpThread& coreDumpThread,
        std::vector<DumpMemoryRegions>& maps, std::shared_ptr<DfxRegs> regs) : Writer(mappedMemory, currentPointer),
        pid_(coreDumpThread.targetPid), targetTid_(coreDumpThread.targetTid), maps_(maps), keyRegs_(regs) {}
    char* Write() override;

private:
    bool PrpsinfoWrite();
    bool NoteWrite(uint32_t noteType, size_t descSize, const char* noteName);
    void FillPrpsinfo(struct elf_prpsinfo *ntPrpsinfo);
    void ReadProcessStat(struct elf_prpsinfo *ntPrpsinfo);
    void ReadProcessStatus(struct elf_prpsinfo *ntPrpsinfo);
    void ReadProcessComm(struct elf_prpsinfo *ntPrpsinfo);
    void ReadProcessCmdline(struct elf_prpsinfo *ntPrpsinfo);
    void MultiThreadNoteWrite();
    void ThreadNoteWrite(pid_t tid);
    bool PrstatusWrite(pid_t tid);
    bool ArmPacMaskWrite(pid_t tid);
    bool FpregsetWrite(pid_t tid);
    bool SiginfoWrite(pid_t tid);
    bool ArmTaggedAddrCtrlWrite();
    void GetPrStatus(struct elf_prstatus *ntPrstatus, pid_t tid);
    void GetPrReg(struct elf_prstatus *ntPrstatus, pid_t tid);
    bool AuxvWrite();
    void ReadProcessAuxv(Elf64_Nhdr *note);
    bool FileWrite();
    bool WriteAddrRelated();
    bool WriteFilePath(Elf64_Half *lineNumber);
    pid_t pid_;
    pid_t targetTid_;
    std::vector<DumpMemoryRegions> maps_;
    std::shared_ptr<DfxRegs> keyRegs_;
};

class SectionHeaderTableWriter : public Writer {
public:
    SectionHeaderTableWriter(char* mappedMemory, char* currentPointer)
        : Writer(mappedMemory, currentPointer) {}
    char* Write() override;
private:
    void SectionHeaderFill(Elf64_Shdr *sectionHeader, Elf64_Word shType, Elf64_Xword shFlag, Elf64_Phdr *programHeader);
    void AdjustOffset(uint8_t remain);
};

} // namespace HiviewDFX
} // namespace OHOS
#endif
#endif