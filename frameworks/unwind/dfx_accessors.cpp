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

#include "dfx_accessors.h"
#include <algorithm>
#include <elf.h>
#include <securec.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include "dfx_define.h"
#include "dfx_log.h"
#include "dfx_regs.h"
#include "dfx_unwind_table.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxAccessors"
}

int DfxAccessorsLocal::AccessMem(uintptr_t addr, uintptr_t *val, int write, void *arg)
{
    if (write) {
        LOGD("val: %llx", *val);
        *(uintptr_t *) addr = *val;
    } else {
        *val = *(uintptr_t *) addr;
        LOGD("val: %llx", *val);
    }
    return UNW_ERROR_NONE;
}

int DfxAccessorsLocal::AccessReg(int reg, uintptr_t *val, int write, void *arg)
{
    UnwindLocalContext* ctx = reinterpret_cast<UnwindLocalContext *>(arg);
    if (ctx == nullptr || ctx->regs == nullptr) {
        return UNW_ERROR_INVALID_CONTEXT;
    }
    if (reg < 0 || reg >= ctx->regsSize) {
        return UNW_ERROR_INVALID_REGS;
    }
    uintptr_t *addr = &(ctx->regs[reg]);

    if (write) {
        LOGD("val: %llx", *val);
        *(uintptr_t *) addr = *val;
    } else {
        *val = *(uintptr_t *) addr;
        LOGD("val: %llx", *val);
    }
    return UNW_ERROR_NONE;
}

int DfxAccessorsLocal::FindProcInfo(uintptr_t pc, UnwindDynInfo *di, int needUnwindInfo, void *arg)
{
    UnwindLocalContext *ctx = reinterpret_cast<UnwindLocalContext *>(arg);
    if (ctx == nullptr) {
        LOGE("ctx is null");
        return UNW_ERROR_INVALID_CONTEXT;
    }

    int ret = UNW_ERROR_NONE;
    if ((ret = DfxUnwindTable::FindUnwindTable2(&(ctx->edi), pc)) != UNW_ERROR_NONE) {
        return ret;
    }

    if(ctx->edi.diCache.format != -1) {
        *di = ctx->edi.diCache;
#if defined(__arm__)
    } else if(ctx->edi.diArm.format != -1) {
        *di = ctx->edi.diArm;
#endif
    } else if(ctx->edi.diDebug.format != -1) {
        *di = ctx->edi.diDebug;
    } else {
        return UNW_ERROR_NO_UNWIND_INFO;
    }
    return ret;
}

int DfxAccessorsRemote::AccessMem(uintptr_t addr, uintptr_t *val, int write, void *arg)
{
    UnwindRemoteContext *ctx = reinterpret_cast<UnwindRemoteContext *>(arg);
    if (ctx == nullptr) {
        return UNW_ERROR_INVALID_CONTEXT;
    }
    pid_t pid = ctx->pid;
    int i, end;
    if (sizeof(long) == 4 && sizeof(uintptr_t) == 8) {
        end = 2;
    } else {
        end = 1;
    }

    uintptr_t tmpVal;
    for (i = 0; i < end; i++) {
        uintptr_t tmpAddr = ((i == 0) ? addr : addr + 4);
        uint64_t valp = static_cast<uint64_t>(*val);
        errno = 0;
        if (write) {
#if __BYTE_ORDER == __LITTLE_ENDIAN
            tmpVal = (uintptr_t)(i == 0 ? valp : valp >> 32);
#else
            tmpVal = (uintptr_t)(i == 0 && end == 2 ? valp >> 32 : valp);
#endif
            LOGU("mem[%lx] <- %lx\n", (long) tmpAddr, (long) tmpVal);
            ptrace(PTRACE_POKEDATA, pid, tmpAddr, tmpVal);
            if (errno) {
                return UNW_ERROR_ILLEGAL_VALUE;
            }
        } else {
            tmpVal = (unsigned long) ptrace(PTRACE_PEEKDATA, pid, tmpAddr, nullptr);
            if (i == 0) {
                *val = 0;
            }

#if __BYTE_ORDER == __LITTLE_ENDIAN
            *val |= tmpVal << (i * 32);
#else
            *val |= (i == 0 && end == 2 ? tmpVal << 32 : tmpVal);
#endif
            if (errno) {
                return UNW_ERROR_ILLEGAL_VALUE;
            }
            LOGU("mem[%lx] -> %lx\n", (long) tmpAddr, (long) tmpVal);
        }
    }
    return UNW_ERROR_NONE;
}

int DfxAccessorsRemote::AccessReg(int reg, uintptr_t *val, int write, void *arg)
{
    UnwindRemoteContext *ctx = reinterpret_cast<UnwindRemoteContext *>(arg);
    if (ctx == nullptr) {
        return UNW_ERROR_INVALID_CONTEXT;
    }
    if (reg >= REG_LAST) {
        return UNW_ERROR_INVALID_REGS;
    }

    pid_t pid = ctx->pid;
    if (ctx->regs == nullptr ) {
        ctx->regs = DfxRegs::CreateRemoteRegs(pid);
        if (ctx->regs == nullptr ) {
            return UNW_ERROR_INVALID_REGS;
        }
    }

    if (write) {
        (*(ctx->regs))[reg] = *val;
        struct iovec iov;
        iov.iov_base = ctx->regs->RawData();
        iov.iov_len = ctx->regs->RegsSize() * sizeof(uintptr_t);
        if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
            return UNW_ERROR_ILLEGAL_VALUE;
        }
    } else {
        *val = (*(ctx->regs))[reg];
    }
    return UNW_ERROR_NONE;
}

int DfxAccessorsRemote::FindProcInfo(uintptr_t pc, UnwindDynInfo *di, int needUnwindInfo, void *arg)
{
    UnwindRemoteContext *ctx = reinterpret_cast<UnwindRemoteContext *>(arg);
    if (ctx == nullptr) {
        return UNW_ERROR_INVALID_CONTEXT;
    }

    int ret = UNW_ERROR_NONE;
    if ((ret = DfxUnwindTable::FindUnwindTable(&(ctx->edi), pc, ctx->elf)) != UNW_ERROR_NONE) {
        return ret;
    }

    if(ctx->edi.diCache.format != -1) {
        *di = ctx->edi.diCache;
#if defined(__arm__)
    } else if(ctx->edi.diArm.format != -1) {
        *di = ctx->edi.diArm;
#endif
    } else if(ctx->edi.diDebug.format != -1) {
        *di = ctx->edi.diDebug;
    } else {
        return UNW_ERROR_NO_UNWIND_INFO;
    }
    return ret;
}

int DfxAccessorsCustomize::AccessMem(uintptr_t addr, uintptr_t *val, int write, void *arg)
{
    if (accessors_ == nullptr) {
        return -1;
    }
    return accessors_->AccessMem(addr, val, write, arg);
}

int DfxAccessorsCustomize::AccessReg(int reg, uintptr_t *val, int write, void *arg)
{
    if (accessors_ == nullptr) {
        return -1;
    }
    return accessors_->AccessReg(reg, val, write, arg);
}

int DfxAccessorsCustomize::FindProcInfo(uintptr_t pc, UnwindDynInfo *di, int needUnwindInfo, void *arg)
{
    if (accessors_ == nullptr) {
        return -1;
    }
    return accessors_->FindProcInfo(pc, di, needUnwindInfo, arg);
}
} // namespace HiviewDFX
} // namespace OHOS
