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

#ifndef DFX_ACCESSORS_H
#define DFX_ACCESSORS_H

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>
#include <vector>
#include "dfx_define.h"
#include "smart_fd.h"
#include "unwind_context.h"

#if is_mingw
#ifndef UNWIND_BYTE_ORDER
#define UNWIND_BYTE_ORDER -1 // unknown
#endif
#endif

namespace OHOS {
namespace HiviewDFX {
class DfxMap;

class DfxAccessors {
public:
    DfxAccessors(int bigEndian = UNWIND_BYTE_ORDER) : bigEndian_(bigEndian) {}
    virtual ~DfxAccessors() = default;
    static bool GetMapByPcAndCtx(uintptr_t pc, std::shared_ptr<DfxMap>& map, void *arg);

    virtual int AccessMem(uintptr_t addr, uintptr_t *val, void *arg) = 0;
    virtual int AccessReg(int regIdx, uintptr_t *val, void *arg) = 0;
    virtual int FindUnwindTable(uintptr_t pc, UnwindTableInfo& uti, void *arg) = 0;
    virtual int GetMapByPc(uintptr_t pc, std::shared_ptr<DfxMap>& map, void *arg) = 0;

    int bigEndian_ = UNWIND_BYTE_ORDER;
};

class DfxAccessorsLocal : public DfxAccessors {
public:
    DfxAccessorsLocal() = default;
    ~DfxAccessorsLocal() override = default;

    int AccessMem(uintptr_t addr, uintptr_t *val, void *arg) override;
    int AccessReg(int regIdx, uintptr_t *val, void *arg) override;
    int FindUnwindTable(uintptr_t pc, UnwindTableInfo& uti, void *arg) override;
    int GetMapByPc(uintptr_t pc, std::shared_ptr<DfxMap>& map, void *arg) override;
private:
    DfxAccessorsLocal(const DfxAccessorsLocal&) = delete;
    DfxAccessorsLocal& operator= (const DfxAccessorsLocal&) = delete;
    bool CreatePipe();

    std::mutex mutex_;
    std::atomic<bool> pipeReady_{false};
    SmartFd readFd_;
    SmartFd writeFd_;
};

class DfxAccessorsRemote : public DfxAccessors {
public:
    DfxAccessorsRemote() = default;
    virtual ~DfxAccessorsRemote() = default;

    int AccessMem(uintptr_t addr, uintptr_t *val, void *arg) override;
    int AccessReg(int regIdx, uintptr_t *val, void *arg) override;
    int FindUnwindTable(uintptr_t pc, UnwindTableInfo& uti, void *arg) override;
    int GetMapByPc(uintptr_t pc, std::shared_ptr<DfxMap>& map, void *arg) override;
private:
    // 栈读取优先走带页缓存的 process_vm_readv,再退回 ptrace PEEKDATA。
    // 第一个成功的方法会被锁定(对齐 AOSP MemoryRemote::Read 语义),
    // 之后每次读取不再重复探测。
    enum class ReadMethod : uint8_t {
        READ_METHOD_UNDECIDED,
        READ_METHOD_VM_READV,
        READ_METHOD_PTRACE_PEEK,
    };
    // process_vm_readv 读取路径:直接映射式 8 槽页缓存,整页预取一次
    // 系统调用;跨页尾的非对齐访问与页尾未映射的重试退化为单字直读。
    bool ReadByVmReadv(uintptr_t addr, uintptr_t *val, pid_t pid);
    // ptrace PEEKDATA 读取路径:32 位宿主上分两次 4 字节拼出 64 位值。
    bool ReadByPtrace(uintptr_t addr, uintptr_t *val, pid_t pid);

    // 页缓存槽:页基址 + 有效长度 + 整页数据;槽位按页号直接映射
    // ((页基址/页大小) % 槽数)定位。
    struct PageSlot {
        uintptr_t base = 0;
        size_t validLen = 0;
        std::vector<uint8_t> data;
    };
    std::mutex cacheMutex_;
    std::vector<PageSlot> pageCache_;
    size_t pageSize_ = 0;
    ReadMethod method_ = ReadMethod::READ_METHOD_UNDECIDED;
};

class DfxAccessorsCustomize : public DfxAccessors {
public:
    DfxAccessorsCustomize(std::shared_ptr<UnwindAccessors> accessors) : accessors_(accessors) {}
    virtual ~DfxAccessorsCustomize() = default;

    int AccessMem(uintptr_t addr, uintptr_t *val, void *arg) override;
    int AccessReg(int regIdx, uintptr_t *val, void *arg) override;
    int FindUnwindTable(uintptr_t pc, UnwindTableInfo& uti, void *arg) override;
    int GetMapByPc(uintptr_t pc, std::shared_ptr<DfxMap>& map, void *arg) override;
private:
    std::shared_ptr<UnwindAccessors> accessors_;
};
} // namespace HiviewDFX
} // namespace OHOS
#endif
