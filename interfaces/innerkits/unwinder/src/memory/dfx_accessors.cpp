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
#include <fcntl.h>
#include <sys/ptrace.h>
#include <sys/syscall.h>
#include "dfx_define.h"
#include "dfx_errors.h"
#include "dfx_log.h"
#include "dfx_regs.h"
#include "dfx_trace_dlsym.h"
#include "dfx_elf.h"
#include "dfx_maps.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxAccessors"

static const int FOUR_BYTES = 4;
static const int EIGHT_BYTES = 8;
static const int THIRTY_TWO_BITS = 32;
}

bool DfxAccessors::GetMapByPcAndCtx(uintptr_t pc, std::shared_ptr<DfxMap>& map, void *arg)
{
    if (arg == nullptr) {
        return false;
    }
    UnwindContext* ctx = reinterpret_cast<UnwindContext *>(arg);
    if (ctx->map != nullptr && ctx->map->Contain(static_cast<uint64_t>(pc))) {
        map = ctx->map;
        DFXLOGU("map had matched by ctx, map name: %{public}s", map->name.c_str());
        return true;
    }

    if (ctx->maps == nullptr || !ctx->maps->FindMapByAddr(pc, map) || (map == nullptr)) {
        ctx->map = nullptr;
        return false;
    }
    ctx->map = map;
    return true;
}

bool DfxAccessorsLocal::CreatePipe()
{
    if (initPipe_) {
        return true;
    }

    std::lock_guard<std::mutex> lock(mutex_);
    if (!initPipe_ && syscall(SYS_pipe2, pfd_, O_CLOEXEC | O_NONBLOCK) == 0) {
        initPipe_ = true;
    }
    uint64_t ownerTag = fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN);
    fdsan_exchange_owner_tag(pfd_[PIPE_WRITE], 0, ownerTag);
    fdsan_exchange_owner_tag(pfd_[PIPE_READ], 0, ownerTag);
    return initPipe_;
}

DfxAccessorsLocal::~DfxAccessorsLocal(void)
{
    if (initPipe_) {
        uint64_t ownerTag = fdsan_create_owner_tag(FDSAN_OWNER_TYPE_FILE, LOG_DOMAIN);
        fdsan_close_with_tag(pfd_[PIPE_WRITE], ownerTag);
        fdsan_close_with_tag(pfd_[PIPE_READ], ownerTag);
        initPipe_ = false;
    }
}

NO_SANITIZE int DfxAccessorsLocal::AccessMem(uintptr_t addr, uintptr_t *val, void *arg)
{
    if (val == nullptr) {
        return UNW_ERROR_INVALID_MEMORY;
    }
    UnwindContext* ctx = reinterpret_cast<UnwindContext *>(arg);
    if (ctx == nullptr || ctx->stackCheck == false) {
        *val = *reinterpret_cast<uintptr_t *>(addr);
        return UNW_ERROR_NONE;
    }
    if (UNLIKELY(ctx->stackTop < ctx->stackBottom)) {
        DFXLOGU("Failed to access addr, the stackTop smaller than stackBottom");
        return UNW_ERROR_INVALID_MEMORY;
    }
    if ((addr >= ctx->stackBottom) && (addr + sizeof(uintptr_t) < ctx->stackTop)) {
        *val = *reinterpret_cast<uintptr_t *>(addr);
        return UNW_ERROR_NONE;
    }
    if (!CreatePipe()) {
        DFXLOGU("Failed to access addr, the pipe create fail, errno:%{public}d", errno);
        return UNW_ERROR_INVALID_MEMORY;
    }
    if (OHOS_TEMP_FAILURE_RETRY(syscall(SYS_write, pfd_[PIPE_WRITE], addr, sizeof(uintptr_t))) == -1) {
        DFXLOGU("Failed to access addr, the pipe write fail, errno:%{public}d", errno);
        return UNW_ERROR_INVALID_MEMORY;
    }
    if (OHOS_TEMP_FAILURE_RETRY(syscall(SYS_read, pfd_[PIPE_READ], val, sizeof(uintptr_t))) == -1) {
        DFXLOGU("Failed to access addr, the pipe read fail, errno:%{public}d", errno);
        return UNW_ERROR_INVALID_MEMORY;
    }
    return UNW_ERROR_NONE;
}

int DfxAccessorsLocal::AccessReg(int reg, uintptr_t *val, void *arg)
{
    UnwindContext* ctx = reinterpret_cast<UnwindContext *>(arg);
    if (ctx == nullptr) {
        return UNW_ERROR_INVALID_CONTEXT;
    }
    if (ctx->regs == nullptr || reg < 0 || reg >= (int)ctx->regs->RegsSize()) {
        return UNW_ERROR_INVALID_REGS;
    }

    *val = static_cast<uintptr_t>((*(ctx->regs))[reg]);
    return UNW_ERROR_NONE;
}

int DfxAccessorsLocal::FindUnwindTable(uintptr_t pc, UnwindTableInfo& uti, void *arg)
{
    UnwindContext *ctx = reinterpret_cast<UnwindContext *>(arg);
    if (ctx == nullptr) {
        return UNW_ERROR_INVALID_CONTEXT;
    }

    int ret = UNW_ERROR_INVALID_ELF;
    if (ctx->map != nullptr && ctx->map->IsVdsoMap()) {
        auto elf = ctx->map->GetElf(getpid());
        if (elf == nullptr) {
            DFXLOGU("FindUnwindTable elf is null");
            return ret;
        }
        ret = elf->FindUnwindTableInfo(pc, ctx->map, uti);
    } else {
        ret = DfxElf::FindUnwindTableLocal(pc, uti);
    }
    if (ret == UNW_ERROR_NONE) {
        ctx->di = uti;
    }
    return ret;
}

int DfxAccessorsLocal::GetMapByPc(uintptr_t pc, std::shared_ptr<DfxMap>& map, void *arg)
{
    if (!DfxAccessors::GetMapByPcAndCtx(pc, map, arg)) {
        return UNW_ERROR_INVALID_MAP;
    }
    return UNW_ERROR_NONE;
}

int DfxAccessorsRemote::AccessMem(uintptr_t addr, uintptr_t *val, void *arg)
{
#if !defined(__LP64__)
    // Cannot read an address greater than 32 bits in a 32 bit context.
    if (addr > UINT32_MAX) {
        return UNW_ERROR_ILLEGAL_VALUE;
    }
#endif
    UnwindContext *ctx = reinterpret_cast<UnwindContext *>(arg);
    if ((ctx == nullptr) || (ctx->pid <= 0)) {
        return UNW_ERROR_INVALID_CONTEXT;
    }

    if (ctx->map != nullptr && ctx->map->elf != nullptr) {
        uintptr_t pos = ctx->map->GetRelPc(addr);
        if (ctx->map->elf->Read(pos, val, sizeof(uintptr_t))) {
            DFXLOGU("Read elf mmap pos: %{public}p", (void *)pos);
            return UNW_ERROR_NONE;
        }
    }

    int i, end;
    if (sizeof(long) == FOUR_BYTES && sizeof(uintptr_t) == EIGHT_BYTES) {
        end = 2; // 2 : read two times
    } else {
        end = 1;
    }

    uintptr_t tmpVal;
    for (i = 0; i < end; i++) {
        uintptr_t tmpAddr = ((i == 0) ? addr : addr + FOUR_BYTES);
        errno = 0;

        tmpVal = (unsigned long) ptrace(PTRACE_PEEKDATA, ctx->pid, tmpAddr, nullptr);
        if (i == 0) {
            *val = 0;
        }

#if __BYTE_ORDER == __LITTLE_ENDIAN
        *val |= tmpVal << (i * THIRTY_TWO_BITS);
#else
        *val |= (i == 0 && end == 2 ? tmpVal << THIRTY_TWO_BITS : tmpVal); // 2 : read two times
#endif
        if (errno) {
            DFXLOGU("errno: %{public}d", errno);
            return UNW_ERROR_ILLEGAL_VALUE;
        }
    }
    return UNW_ERROR_NONE;
}

int DfxAccessorsRemote::AccessReg(int reg, uintptr_t *val, void *arg)
{
    UnwindContext *ctx = reinterpret_cast<UnwindContext *>(arg);
    if (ctx == nullptr) {
        return UNW_ERROR_INVALID_CONTEXT;
    }
    if (ctx->regs == nullptr || reg < 0 || reg >= (int)ctx->regs->RegsSize()) {
        return UNW_ERROR_INVALID_REGS;
    }

    *val = static_cast<uintptr_t>((*(ctx->regs))[reg]);
    return UNW_ERROR_NONE;
}

int DfxAccessorsRemote::FindUnwindTable(uintptr_t pc, UnwindTableInfo& uti, void *arg)
{
    DFX_TRACE_SCOPED_DLSYM("FindUnwindTable");
    UnwindContext *ctx = reinterpret_cast<UnwindContext *>(arg);
    if (ctx == nullptr || ctx->map == nullptr) {
        return UNW_ERROR_INVALID_CONTEXT;
    }
    if (pc >= ctx->di.startPc && pc < ctx->di.endPc) {
        DFXLOGU("FindUnwindTable had pc matched");
        uti = ctx->di;
        return UNW_ERROR_NONE;
    }

    auto elf = ctx->map->GetElf(ctx->pid);
    if (elf == nullptr) {
        DFXLOGU("FindUnwindTable elf is null");
        return UNW_ERROR_INVALID_ELF;
    }
    int ret = elf->FindUnwindTableInfo(pc, ctx->map, uti);
    if (ret == UNW_ERROR_NONE) {
        ctx->di = uti;
    }
    return ret;
}

int DfxAccessorsRemote::GetMapByPc(uintptr_t pc, std::shared_ptr<DfxMap>& map, void *arg)
{
    if (!DfxAccessors::GetMapByPcAndCtx(pc, map, arg)) {
        return UNW_ERROR_INVALID_MAP;
    }
    return UNW_ERROR_NONE;
}

int DfxAccessorsCustomize::AccessMem(uintptr_t addr, uintptr_t *val, void *arg)
{
    if (accessors_ == nullptr || accessors_->AccessMem == nullptr) {
        return -1;
    }
    return accessors_->AccessMem(addr, val, arg);
}

int DfxAccessorsCustomize::AccessReg(int reg, uintptr_t *val, void *arg)
{
    if (accessors_ == nullptr || accessors_->AccessReg == nullptr) {
        return -1;
    }
    return accessors_->AccessReg(reg, val, arg);
}

int DfxAccessorsCustomize::FindUnwindTable(uintptr_t pc, UnwindTableInfo& uti, void *arg)
{
    if (accessors_ == nullptr || accessors_->FindUnwindTable == nullptr) {
        return -1;
    }
    return accessors_->FindUnwindTable(pc, uti, arg);
}

int DfxAccessorsCustomize::GetMapByPc(uintptr_t pc, std::shared_ptr<DfxMap>& map, void *arg)
{
    if (accessors_ == nullptr || accessors_->GetMapByPc == nullptr) {
        return -1;
    }
    return accessors_->GetMapByPc(pc, map, arg);
}
} // namespace HiviewDFX
} // namespace OHOS
