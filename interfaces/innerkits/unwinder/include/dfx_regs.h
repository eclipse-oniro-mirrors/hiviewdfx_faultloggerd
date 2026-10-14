/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#ifndef DFX_REGS_H
#define DFX_REGS_H

#include <cstdint>
#include <string>
#include <memory>
#include <sys/types.h>
#include <ucontext.h>
#include <vector>
#include "dfx_define.h"
#include "dfx_elf.h"
#include "dfx_memory.h"
#include "unwind_define.h"

namespace OHOS {
namespace HiviewDFX {
class DfxRegs {
public:
    explicit DfxRegs() : regsData_(REG_LAST) {}
    virtual ~DfxRegs() = default;

    static std::shared_ptr<DfxRegs> Create();
    static std::shared_ptr<DfxRegs> CreateFromUcontext(const ucontext_t& context);
    static std::shared_ptr<DfxRegs> CreateFromRegs(const UnwindMode mode, const uintptr_t* regs,
                                                   size_t size);
    static std::shared_ptr<DfxRegs> CreateRemoteRegs(pid_t pid);
    virtual void SetFromUcontext(const ucontext_t& context) = 0;
    virtual void SetFromFpMiniRegs(const uintptr_t* regs, const size_t size) = 0;
    virtual void SetFromQutMiniRegs(const uintptr_t* regs, const size_t size) = 0;
    virtual std::string PrintRegs() const = 0;
    virtual bool SetPcFromReturnAddress(std::shared_ptr<DfxMemory> memory) = 0;
    virtual bool StepIfSignalFrame(uintptr_t pc, std::shared_ptr<DfxMemory> memory) = 0;

    inline uintptr_t& operator[](size_t idx) { return regsData_[idx]; }

    void* RawData() { return regsData_.data(); }
    size_t RegsSize() const { return regsData_.size(); }
    std::vector<uintptr_t> GetRegsData() const;
    void SetRegsData(const std::vector<uintptr_t>& regsData);
    void SetRegsData(const uintptr_t* regs, const size_t size);
    uintptr_t* GetReg(size_t idx);
    void SetReg(const int idx, const uintptr_t* val);

    virtual uintptr_t GetSp() const;
    virtual void SetSp(uintptr_t sp);
    virtual uintptr_t GetPc() const;
    virtual void SetPc(uintptr_t pc);
    virtual uintptr_t GetFp() const;
    virtual void SetFp(uintptr_t fp);
    virtual void GetSpecialRegs(uintptr_t& fp, uintptr_t& lr, uintptr_t& sp, uintptr_t& pc) const;
    virtual void SetSpecialRegs(uintptr_t fp, uintptr_t lr, uintptr_t sp, uintptr_t pc);
    std::string GetSpecialRegsName(uintptr_t val) const;
    std::string GetSpecialRegsNameByIndex(int index) const;
    std::string PrintSpecialRegs() const;

    // dex_pc pseudo-register (AOSP16 libunwindstack style). Set by DWARF
    // expression evaluation when a register's CFI uses the DEX1 magic marker.
    // The unwinder reads it at the start of each step to inject a virtual
    // DEX frame representing the interpreted Java method's current PC.
    uintptr_t DexPc() const { return dex_pc_; }
    void SetDexPc(uintptr_t pc) { dex_pc_ = pc; }
    // dexPcSeen tracks whether the DEX1 magic marker fired during the current
    // DWARF Apply, independently of the evaluated dex_pc value. ART's CFI for
    // nterp_helper is the only emitter of the DEX1 magic, so the flag alone is
    // proof of an nterp frame even when the dex_pc value is 0/unmapped (e.g.
    // the live x22 register was clobbered to 0 by intermediate compiled/JNI
    // frames before the thread reached a syscall). StepNterp uses this flag to
    // decide whether to run the callee-saves frame recovery; using DexPc()!=0
    // instead would miss nterp frames whose dex_pc evaluated to 0 and stop the
    // unwind at nterp_helper.
    bool DexPcSeen() const { return dexPcSeen_; }
    void SetDexPcSeen(bool seen) { dexPcSeen_ = seen; }
    void ClearDexPc()
    {
        dex_pc_ = 0;
        dexPcSeen_ = false;
    }

protected:
    std::vector<uintptr_t> regsData_ {};
    uintptr_t dex_pc_ = 0;
    bool dexPcSeen_ = false;
};

#if defined(__arm__)
class DfxRegsArm : public DfxRegs {
public:
    DfxRegsArm() = default;
    ~DfxRegsArm() = default;
    void SetFromUcontext(const ucontext_t& context) override;
    void SetFromFpMiniRegs(const uintptr_t* regs, const size_t size) override;
    void SetFromQutMiniRegs(const uintptr_t* regs, const size_t size) override;
    std::string PrintRegs() const override;
    bool SetPcFromReturnAddress(std::shared_ptr<DfxMemory> memory) override;
    bool StepIfSignalFrame(uintptr_t pc, std::shared_ptr<DfxMemory> memory) override;
};
#endif

#if defined(__aarch64__)
class DfxRegsArm64 : public DfxRegs {
public:
    DfxRegsArm64() = default;
    ~DfxRegsArm64() = default;
    void SetFromUcontext(const ucontext_t& context) override;
    void SetFromFpMiniRegs(const uintptr_t* regs, const size_t size) override;
    void SetFromQutMiniRegs(const uintptr_t* regs, const size_t size) override;
    std::string PrintRegs() const override;
    bool SetPcFromReturnAddress(std::shared_ptr<DfxMemory> memory) override;
    bool StepIfSignalFrame(uintptr_t pc, std::shared_ptr<DfxMemory> memory) override;
};
#endif

#if defined(__riscv) && defined(__riscv_xlen) && __riscv_xlen == 64
class DfxRegsRiscv64 : public DfxRegs {
public:
    DfxRegsRiscv64() = default;
    ~DfxRegsRiscv64() = default;
    void SetFromUcontext(const ucontext_t& context) override;
    void SetFromFpMiniRegs(const uintptr_t* regs, const size_t size) override;
    void SetFromQutMiniRegs(const uintptr_t* regs, const size_t size) override;
    std::string PrintRegs() const override;
    bool SetPcFromReturnAddress(std::shared_ptr<DfxMemory> memory) override;
    bool StepIfSignalFrame(uintptr_t pc, std::shared_ptr<DfxMemory> memory) override;
};
#endif

#if defined(__x86_64__)
class DfxRegsX86_64 : public DfxRegs {
public:
    DfxRegsX86_64() = default;
    ~DfxRegsX86_64() = default;
    void SetFromUcontext(const ucontext_t& context) override;
    void SetFromFpMiniRegs(const uintptr_t* regs, const size_t size) override;
    void SetFromQutMiniRegs(const uintptr_t* regs, const size_t size) override;
    std::string PrintRegs() const override;
    bool SetPcFromReturnAddress(std::shared_ptr<DfxMemory> memory) override;
    bool StepIfSignalFrame(uintptr_t pc, std::shared_ptr<DfxMemory> memory) override;
};
#endif

#if defined(__loongarch_lp64)
class DfxRegsLoongArch64 : public DfxRegs {
public:
    DfxRegsLoongArch64() = default;
    ~DfxRegsLoongArch64() = default;
    void SetFromUcontext(const ucontext_t& context) override;
    void SetFromFpMiniRegs(const uintptr_t* regs, const size_t size) override;
    void SetFromQutMiniRegs(const uintptr_t* regs, const size_t size) override;
    std::string PrintRegs() const override;
    bool SetPcFromReturnAddress(std::shared_ptr<DfxMemory> memory) override;
    bool StepIfSignalFrame(uintptr_t pc, std::shared_ptr<DfxMemory> memory) override;
};
#endif

} // namespace HiviewDFX
} // namespace OHOS
#endif
