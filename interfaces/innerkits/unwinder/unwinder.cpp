/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include <atomic>
#include "unwinder.h"

#include <sys/uio.h>
#include <unordered_map>
#include <link.h>

#include "dfx_ark.h"
#include "dfx_define.h"
#include "dfx_errors.h"
#include "dfx_frame_formatter.h"
#include "dfx_hap.h"
#include "dfx_instructions.h"
#include "dfx_jit_debug.h"
#include "dfx_jsvm.h"
#include "dfx_log.h"
#include "dfx_memory.h"
#include "dfx_param.h"
#include "dfx_regs_get.h"
#include "dfx_symbols.h"
#include "dfx_trace_dlsym.h"
#include "dfx_util.h"
#include "elapsed_time.h"
#include "fp_unwinder.h"
#include "stack_utils.h"
#include "string_printf.h"
#include "string_util.h"
#include "thread_context.h"
#include "unwind_entry_parser_factory.h"

namespace OHOS {
namespace HiviewDFX {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxUnwinder"
#if defined(__x86_64__)
const size_t X86_FP_SP_OFFSET = 16;
#endif

#if defined(__aarch64__) || defined(__x86_64__)
// 兜底栈扫描(StepByScan):限定扫描窗口和每次回溯最多采纳的扫描帧数,
// 防止坏栈导致无界开销。
constexpr size_t SCAN_WINDOW_WORDS = 64; // 64 个字 = sp 上方 512 字节
constexpr uint8_t MAX_SCAN_STEPS = 2;
#endif

// JIT 编译代码只存在于匿名或 memfd 映射;落在有名文件映射(.so / .oat /
// .apk)里的 pc 不可能命中 __jit_debug_descriptor 表项,可直接跳过 JIT
// 注册表扫描。
static bool IsFileBackedMapName(std::string name)
{
    // 先剥掉 "/proc/<pid>/root" 沙箱前缀(DfxMap::FormatMapName 添加):
    // 否则 "[shmm]"、"[anon:dalvik-...]" 这类伪表项会以 '/' 开头被误判为
    // 文件路径,导致 ART JIT 缓存等匿名可执行区被跳过 JIT 查找。
    if (name.rfind("/proc/", 0) == 0) {
        size_t pos = name.find("/root");
        if (pos != std::string::npos) {
            name = name.substr(pos + static_cast<size_t>(sizeof("/root")) - 1);
        }
    }
    return !name.empty() && name[0] == '/' && name.find("/memfd:") == std::string::npos;
}

class Unwinder::Impl {
public:
    // for local
    Impl(bool needMaps) : pid_(UNWIND_TYPE_LOCAL)
    {
        if (needMaps) {
            maps_ = DfxMaps::Create();
        }
        enableFpCheckMapExec_ = true;
        memory_ = std::make_shared<DfxMemory>(UNWIND_TYPE_LOCAL);
        Init();
    }

    // for remote
    Impl(int pid, bool crash, std::shared_ptr<DfxMaps> maps) : pid_(pid)
    {
        if (pid <= 0) {
            DFXLOGE("pid(%{public}d) error", pid);
            return;
        }
        DfxEnableTraceDlsym(true);
        maps_ = maps == nullptr ? DfxMaps::Create(pid, crash) : maps;
        enableFpCheckMapExec_ = true;
        memory_ = std::make_shared<DfxMemory>(UNWIND_TYPE_REMOTE);
        Init();
    }

    Impl(int pid, int nspid, bool crash, std::shared_ptr<DfxMaps> maps) : pid_(nspid)
    {
        if (pid <= 0 || nspid <= 0) {
            DFXLOGE("pid(%{public}d) or nspid(%{public}d) error", pid, nspid);
            return;
        }
        DfxEnableTraceDlsym(true);
        maps_ = maps == nullptr ? DfxMaps::Create(pid, crash, false) : maps;
        enableFpCheckMapExec_ = true;
        isCrash_ = crash;
        memory_ = std::make_shared<DfxMemory>(UNWIND_TYPE_REMOTE);
        Init();
    }

    // for customized
    Impl(const std::shared_ptr<UnwindAccessors> &accessors, bool local)
    {
        UnwindType unwindType = local ? UNWIND_TYPE_CUSTOMIZE_LOCAL : UNWIND_TYPE_CUSTOMIZE;
        pid_ = unwindType;
        enableFpCheckMapExec_ = false;
        enableFillFrames_ = false;
    #if defined(__aarch64__)
        pacMask_ = pacMaskDefault_;
    #endif
        memory_ = std::make_shared<DfxMemory>(unwindType, accessors);
        Init();
    }

    ~Impl()
    {
        DfxEnableTraceDlsym(false);
        Destroy();
#if defined(ENABLE_MIXSTACK)
        if (isArkCreateLocal_) {
            if (DfxArk::Instance().ArkDestroyLocal() < 0) {
                DFXLOGU("Failed to ark destroy local.");
            }
        }
#endif
#if defined(__aarch64__) || defined(__loongarch_lp64) || defined(__x86_64__)
        if (pid_ == UNWIND_TYPE_LOCAL) {
            LocalThreadContext::GetInstance().CleanUp();
        }
#endif
        if (arkwebJsExtractorptr_ != 0) {
            DfxJsvm::Instance().JsvmDestroyJsSymbolExtractor(arkwebJsExtractorptr_);
        }
        DfxJsvm::Instance().Clear();
    }

    inline void EnableUnwindCache(bool enableCache)
    {
        enableCache_ = enableCache;
    }
    inline void EnableFpCheckMapExec(bool enableFpCheckMapExec)
    {
        enableFpCheckMapExec_ = enableFpCheckMapExec;
    }
    inline void EnableFillFrames(bool enableFillFrames)
    {
        enableFillFrames_ = enableFillFrames;
    }
    inline void EnableParseNativeSymbol(bool enableParseNativeSymbol)
    {
        enableParseNativeSymbol_ = enableParseNativeSymbol;
    }
    inline void EnableJsvmstack(bool enableJsvmstack)
    {
        enableJsvmstack_ = enableJsvmstack;
    }
    inline void IgnoreMixstack(bool ignoreMixstack)
    {
        ignoreMixstack_ = ignoreMixstack;
    }

    inline void SetRegs(const std::shared_ptr<DfxRegs> &regs)
    {
        if (regs == nullptr) {
            return;
        }
        regs_ = regs;
        firstFrameSp_ = regs_->GetSp();
    }

    inline void SetMaps(const std::shared_ptr<DfxMaps> &maps)
    {
        if (maps == nullptr) {
            return;
        }
        maps_ = maps;
    }

    inline void SetPid(pid_t pid)
    {
        // 同一 Unwinder 换用另一个 pid 时,不能保留前一个 pid 的
        // JIT 描述符/表项缓存。
        if (pid > 0 && pid != pid_) {
            pid_ = pid;
            jitDebug_.Clear();
        }
    }

    void SetEnableScanStep(bool enable)
    {
        enableScanStep_ = enable;
    }

    inline const std::shared_ptr<DfxRegs>& GetRegs() const
    {
        return regs_;
    }

    inline const std::shared_ptr<DfxMaps>& GetMaps() const
    {
        return maps_;
    }

    inline uint16_t GetLastErrorCode()
    {
        return lastErrorData_.GetCode();
    }
    inline uint64_t GetLastErrorAddr()
    {
        return lastErrorData_.GetAddr();
    }

    bool GetStackRange(uintptr_t& stackBottom, uintptr_t& stackTop);

    bool UnwindLocalWithContext(const ucontext_t& context, size_t maxFrameNum, size_t skipFrameNum);
    bool UnwindLocalWithTid(pid_t tid, size_t maxFrameNum, size_t skipFrameNum);
    bool UnwindLocalByOtherTid(pid_t tid, bool fast, size_t maxFrameNum, size_t skipFrameNum);
    bool UnwindLocal(bool withRegs, bool fpUnwind, size_t maxFrameNum, size_t skipFrameNum, bool enableArk = false);
    bool UnwindRemote(pid_t tid, bool withRegs, size_t maxFrameNum, size_t skipFrameNum);
    bool Unwind(void *ctx, size_t maxFrameNum, size_t skipFrameNum);
    bool UnwindByFp(void *ctx, size_t maxFrameNum, size_t skipFrameNum, bool enableArk);

    bool Step(uintptr_t& pc, uintptr_t& sp, void *ctx);
    bool FpStep(uintptr_t& fp, uintptr_t& pc, void *ctx);

    void AddFrame(DfxFrame& frame);
    const std::vector<DfxFrame>& GetFrames();
    inline const std::vector<uintptr_t>& GetPcs() const
    {
        return pcs_;
    }
    void FillFrames(std::vector<DfxFrame>& frames);
    void FillFrame(DfxFrame& frame, bool needSymParse = true);
    void FillDexFrame(DfxFrame& frame);
    void ParseFrameSymbol(DfxFrame& frame);
    void FillJsFrame(DfxFrame& frame);
    void FillArkwebJsFrame(DfxFrame& frame);
    bool GetFrameByPc(uintptr_t pc, std::shared_ptr<DfxMaps> maps, DfxFrame& frame);
    void GetFramesByPcs(std::vector<DfxFrame>& frames, std::vector<uintptr_t> pcs);
    inline void SetIsJitCrashFlag(bool isCrash)
    {
        isJitCrash_ = isCrash;
    }
    int ArkWriteJitCodeToFile(int fd);
    bool GetLockInfo(int32_t tid, char* buf, size_t sz);
    void SetFrames(const std::vector<DfxFrame>& frames)
    {
        frames_ = frames;
    }
    inline const std::vector<uintptr_t>& GetJitCache(void) const
    {
        return jitCache_;
    }
    static int DlPhdrCallback(struct dl_phdr_info *info, size_t size, void *data);
private:
    bool FillJsFrameLocal(DfxFrame& frame, JsFunction* jsFunction);

private:
    struct StepFrame {
        uintptr_t pc = 0;
        uintptr_t sp = 0;
        uintptr_t fp = 0;
        bool isJsFrame {false};
        FrameType frameType {FrameType::NATIVE_FRAME};
    };
    struct StepCache {
        std::shared_ptr<DfxMap> map = nullptr;
        std::shared_ptr<RegLocState> rs = nullptr;
    };
    struct ArkMapRange {
        uintptr_t arkMapStart = 0;
        uintptr_t arkMapEnd = 0;
        uintptr_t staticArkMapStart = 0;
        uintptr_t staticArkMapEnd = 0;
    };
    void Init();
    void Clear();
    void Destroy();
    void InitParam()
    {
#if defined(ENABLE_MIXSTACK)
        enableMixstack_ = DfxParam::IsEnableMixstack();
#endif
    }
    bool GetMainStackRangeInner(uintptr_t& stackBottom, uintptr_t& stackTop);
    bool GetArkStackRangeInner(uintptr_t& arkMapStart, uintptr_t& arkMapEnd);
    bool GetStaticArkStackRange(uintptr_t& arkMapStart, uintptr_t& arkMapEnd);
    bool CheckAndReset(void* ctx);
    void DoPcAdjust(uintptr_t& pc);
    void AddFrame(const StepFrame& frame, std::shared_ptr<DfxMap> map);
    bool FindCache(uintptr_t pc, std::shared_ptr<DfxMap>& map, std::shared_ptr<RegLocState>& rs);
    bool AddFrameMap(const StepFrame& frame, std::shared_ptr<DfxMap>& map);
    bool UnwindArkFrame(StepFrame& frame, const std::shared_ptr<DfxMap>& map, bool& stopUnwind);
    bool ParseUnwindTable(uintptr_t pc, std::shared_ptr<RegLocState>& rs);
    void StepToNextFpIfNeed();
    void UpdateRegsState(StepFrame& frame, void* ctx, bool& unwinderResult, std::shared_ptr<RegLocState>& rs,
        const std::shared_ptr<DfxMap>& frameMap);
    bool CheckFrameValid(const StepFrame& frame, const std::shared_ptr<DfxMap>& map, uintptr_t prevSp);
    bool GetCrashLastFrame(StepFrame& frame);
    void UpdateCache(uintptr_t pc, bool hasRegLocState, const std::shared_ptr<RegLocState>& rs,
        const std::shared_ptr<DfxMap>& map);
    bool StepInner(const bool isSigFrame, StepFrame& frame, void *ctx);
    bool Apply(std::shared_ptr<DfxRegs> regs, std::shared_ptr<RegLocState> rs, uint16_t& errCode);
    bool UnwindFrame(void *ctx, StepFrame& frame, bool& needAdjustPc);
    bool TryJitStep(uintptr_t pc, void *ctx);
    bool StepByScan(uintptr_t sp, uintptr_t currentPc);
    bool StepNterp(uintptr_t pc, uintptr_t origSp, uintptr_t origDexPc, uintptr_t origXRefs);
    // Unwind() 入口从 perf 采样捕获的 x25(xREFS)
#if defined(__aarch64__)
    uintptr_t sampleXRefs_ = 0;
#endif
    // Unwind() 入口的 x29(FP)——采样真值,不受 CFI/兜底链污染
    // (speed-profile 文档 §7 修复)。所有平台都声明(FpTailUnwind 调用点
    // 无条件读取);仅 aarch64 赋值,其他平台恒为 0,尾部回溯不会触发。
    uintptr_t sampleX29_ = 0;
#if defined(__aarch64__)
    // libart.so 加载基址,供 StepBridge 做符号偏移核对(按 unwinder 实例
    // 即按目标 pid 保存;各进程 ASLR 不同)。
    uintptr_t libartBase_ = 0;
    bool libartBaseFound_ = false;
    // StepManaged 默认关闭(评审 R6):实测活链路几乎无增益,却让每条断链
    // 多付一次 process_vm_readv;待 hiperf 开始在采样时附带受管栈快照后再开。
    bool enableManagedWalk_ = false;
#endif
    // FpTailUnwind:从采样 x29 起走纯 FP 链收尾(锚点续走法)。
    void FpTailUnwind(void* ctx, size_t maxFrameNum);
    // StepBridge:确定性地跳出 art_quick_to_interpreter_bridge。反汇编
    // (容器 libart)实证:该桥把调用者 x29/x30 存在 [sp+208]/[sp+216]——
    // 并非标准帧记录槽位——DWARF(无 CFI)和普通 FP 走链都找不到;采样栈
    // 已捕获它们,所以这次跳转无需活读。跳出后 quick 链恢复标准帧记录,
    // 正常续走。
    void StepBridge(size_t maxFrameNum);
    // StepManaged(M3):从 art::Thread(x28 SELF)出发的活受管栈走链。偏移
    // 经容器 libart 反汇编实证:Thread+168 是内嵌 ManagedStack 三元组
    // {quick@0, link@+8, shadow@+16}(见 managed_walker设计_偏移实锤_
    // 20261017.md)。走的是活的 quick 链——深层帧在延迟回溯窗口内稳定
    // (与 JIT 描述符冻结同一依据,K5);锚点用物理栈地址,即使链头已移动
    // 续走仍然有效。
    void StepManaged(void* ctx, size_t maxFrameNum);
    // K12:线程根候选映射(libc/ld-musl)的 map 指针缓存。落在这两类映射
    // 里的帧先廉价分类,只有它们才付出符号查询。查询失败(strip/不可达)
    // 时不写缓存 = 维持旧行为。
    std::unordered_map<const DfxMap *, bool> rootMapCache_ {};
    const DfxMaps *rootMapGen_ = nullptr; // maps_ 代数,用于缓存失效
    bool IsThreadRootFrame();
    // AOSP16 风格 DEX 帧注入:每次 StepInner 迭代开头调用。若上一次
    // DWARF Step 已设置 dex_pc 伪寄存器(经 libart.so CFI 的 DEX1 魔数
    // 标记),则在加入当前本机帧之前,先为解释执行的 Java 方法注入一个
    // 虚拟 DEX 帧。由此得到规范的栈序:
    //   ... | nterp_helper | <DEX 帧> | nterp_helper 的调用者 | ...
    void InjectDexFrameFromDwarf();
    void TryJitSymbolLookup(DfxFrame& frame);
#if defined(ENABLE_MIXSTACK)
    bool StepArkJsFrame(StepFrame& frame, uint64_t frameIndex = 0);
    int UnwindArkFrameByFp(StepFrame& frame, const ArkMapRange& arkMapRange, uint64_t& frameIndex);
#endif
    bool StepV8Frame(StepFrame& frame, const std::shared_ptr<DfxMap>& map, bool& stopUnwind);
    inline void SetLocalStackCheck(void* ctx, bool check) const
    {
        if ((pid_ == UNWIND_TYPE_LOCAL) && (ctx != nullptr)) {
            UnwindContext* uctx = reinterpret_cast<UnwindContext *>(ctx);
            uctx->stackCheck = check;
        }
    }
    inline void SetBytecodePcAndInterruptPc()
    {
        interruptPc_ = regs_->GetPc();
    #if defined(__arm__)
        bytecodePc_ = *regs_->GetReg(REG_ARM_R4);
    #elif defined(__aarch64__)
        bytecodePc_ = *regs_->GetReg(REG_AARCH64_X20);
    #elif defined(__x86_64__)
        bytecodePc_ = *regs_->GetReg(REG_X86_64_R10);
    #endif
    }

#if defined(__aarch64__)
    MAYBE_UNUSED const uintptr_t pacMaskDefault_ = static_cast<uintptr_t>(0xFFFFFF8000000000);
#endif
    bool enableCache_ = true;
    bool enableFillFrames_ = true;
    bool enableParseNativeSymbol_ = true;
    bool enableLrFallback_ = true;
    bool enableFpCheckMapExec_ = false;
    bool isCrash_ = false;
    bool isFpStep_ = false;
    bool isArkCreateLocal_ = false;
    bool isResetFrames_ = false;
    bool enableJsvmstack_ = false;
    MAYBE_UNUSED bool enableMixstack_ = true;
    MAYBE_UNUSED bool ignoreMixstack_ = false;
    MAYBE_UNUSED bool stopWhenArkFrame_ = false;
    MAYBE_UNUSED bool isJitCrash_ = false;
    uintptr_t arkwebJsExtractorptr_ = 0;
    // LR 兜底最近一次产出的 pc(见 UpdateRegsState)。LR 只在 DWARF Apply
    // 成功时经 x30 规则刷新;对已消费过的 LR 值再兜底永远无法推进回溯。
    uintptr_t lastLrFallbackPc_ = 0;
    // 兜底栈扫描(默认关闭,经 SetEnableScanStep 开启)。
    bool enableScanStep_ = false;
    uint8_t scanUsedCount_ = 0;

    int32_t pid_ = 0;
    uintptr_t pacMask_ = 0;
    std::vector<uintptr_t> jitCache_ = {};
    std::shared_ptr<DfxMemory> memory_ = nullptr;
    std::unordered_map<uintptr_t, StepCache> stepCache_ {};
    std::shared_ptr<DfxRegs> regs_ = nullptr;
    std::shared_ptr<DfxMaps> maps_ = nullptr;
    DfxJitDebug jitDebug_ {};
    std::vector<uintptr_t> pcs_ {};
    std::vector<DfxFrame> frames_ {};
    UnwindErrorData lastErrorData_ {};
    std::shared_ptr<UnwindEntryParser> unwindEntryParser_ = nullptr;
    uintptr_t firstFrameSp_ {0};
    UnwindContext context_;
    uintptr_t interruptPc_ {0};
    uintptr_t bytecodePc_ {0};
};

// for local
Unwinder::Unwinder(bool needMaps) : impl_(std::make_shared<Impl>(needMaps))
{
}

// for remote
Unwinder::Unwinder(int pid, bool crash, std::shared_ptr<DfxMaps> maps)
    : impl_(std::make_shared<Impl>(pid, crash, maps))
{
}

Unwinder::Unwinder(int pid, int nspid, bool crash, std::shared_ptr<DfxMaps> maps)
    : impl_(std::make_shared<Impl>(pid, nspid, crash, maps))
{
}

// for customized
Unwinder::Unwinder(std::shared_ptr<UnwindAccessors> accessors, bool local)
    : impl_(std::make_shared<Impl>(accessors, local))
{
}

void Unwinder::EnableUnwindCache(bool enableCache)
{
    impl_->EnableUnwindCache(enableCache);
}

void Unwinder::EnableFpCheckMapExec(bool enableFpCheckMapExec)
{
    impl_->EnableFpCheckMapExec(enableFpCheckMapExec);
}

void Unwinder::EnableFillFrames(bool enableFillFrames)
{
    impl_->EnableFillFrames(enableFillFrames);
}

void Unwinder::EnableParseNativeSymbol(bool enableParseNativeSymbol)
{
    impl_->EnableParseNativeSymbol(enableParseNativeSymbol);
}

void Unwinder::EnableJsvmstack(bool enableJsvmstack)
{
    impl_->EnableJsvmstack(enableJsvmstack);
}

void Unwinder::IgnoreMixstack(bool ignoreMixstack)
{
    impl_->IgnoreMixstack(ignoreMixstack);
}

void Unwinder::SetRegs(std::shared_ptr<DfxRegs> regs)
{
    impl_->SetRegs(regs);
}

void Unwinder::SetMaps(std::shared_ptr<DfxMaps> maps)
{
    impl_->SetMaps(maps);
}

void Unwinder::SetPid(pid_t pid)
{
    impl_->SetPid(pid);
}

void Unwinder::SetEnableScanStep(bool enable)
{
    impl_->SetEnableScanStep(enable);
}

const std::shared_ptr<DfxRegs>& Unwinder::GetRegs() const
{
    return impl_->GetRegs();
}

const std::shared_ptr<DfxMaps>& Unwinder::GetMaps() const
{
    return impl_->GetMaps();
}

uint16_t Unwinder::GetLastErrorCode() const
{
    return impl_->GetLastErrorCode();
}

uint64_t Unwinder::GetLastErrorAddr() const
{
    return impl_->GetLastErrorAddr();
}

bool Unwinder::GetStackRange(uintptr_t& stackBottom, uintptr_t& stackTop)
{
    return impl_->GetStackRange(stackBottom, stackTop);
}

bool Unwinder::UnwindLocalWithContext(const ucontext_t& context, size_t maxFrameNum, size_t skipFrameNum)
{
    return impl_->UnwindLocalWithContext(context, maxFrameNum, skipFrameNum);
}

bool Unwinder::UnwindLocalWithTid(pid_t tid, size_t maxFrameNum, size_t skipFrameNum)
{
    return impl_->UnwindLocalWithTid(tid, maxFrameNum, skipFrameNum);
}

bool Unwinder::UnwindLocalByOtherTid(pid_t tid, bool fast, size_t maxFrameNum, size_t skipFrameNum)
{
    return impl_->UnwindLocalByOtherTid(tid, fast, maxFrameNum, skipFrameNum);
}

bool __attribute__((optnone)) Unwinder::UnwindLocal(bool withRegs, bool fpUnwind, size_t maxFrameNum,
    size_t skipFrameNum, bool enableArk)
{
    return impl_->UnwindLocal(withRegs, fpUnwind, maxFrameNum, skipFrameNum + 1, enableArk);
}

bool Unwinder::UnwindRemote(pid_t tid, bool withRegs, size_t maxFrameNum, size_t skipFrameNum)
{
    return impl_->UnwindRemote(tid, withRegs, maxFrameNum, skipFrameNum);
}

bool Unwinder::Unwind(void *ctx, size_t maxFrameNum, size_t skipFrameNum)
{
    return impl_->Unwind(ctx, maxFrameNum, skipFrameNum);
}

bool Unwinder::UnwindByFp(void *ctx, size_t maxFrameNum, size_t skipFrameNum, bool enableArk)
{
    return impl_->UnwindByFp(ctx, maxFrameNum, skipFrameNum, enableArk);
}

bool Unwinder::Step(uintptr_t& pc, uintptr_t& sp, void *ctx)
{
    return impl_->Step(pc, sp, ctx);
}

bool Unwinder::FpStep(uintptr_t& fp, uintptr_t& pc, void *ctx)
{
    return impl_->FpStep(fp, pc, ctx);
}

void Unwinder::AddFrame(DfxFrame& frame)
{
    impl_->AddFrame(frame);
}

const std::vector<DfxFrame>& Unwinder::GetFrames() const
{
    return impl_->GetFrames();
}

const std::vector<uintptr_t>& Unwinder::GetPcs() const
{
    return impl_->GetPcs();
}

void Unwinder::FillFrames(std::vector<DfxFrame>& frames)
{
    impl_->FillFrames(frames);
}

void Unwinder::FillFrame(DfxFrame& frame, bool needSymParse)
{
    impl_->FillFrame(frame, needSymParse);
}

void Unwinder::ParseFrameSymbol(DfxFrame& frame)
{
    impl_->ParseFrameSymbol(frame);
}

void Unwinder::FillJsFrame(DfxFrame& frame)
{
    impl_->FillJsFrame(frame);
}

bool Unwinder::GetFrameByPc(uintptr_t pc, std::shared_ptr<DfxMaps> maps, DfxFrame& frame)
{
    return impl_->GetFrameByPc(pc, maps, frame);
}

void Unwinder::GetFramesByPcs(std::vector<DfxFrame>& frames, std::vector<uintptr_t> pcs)
{
    impl_->GetFramesByPcs(frames, pcs);
}

void Unwinder::SetIsJitCrashFlag(bool isCrash)
{
    impl_->SetIsJitCrashFlag(isCrash);
}

int Unwinder::ArkWriteJitCodeToFile(int fd)
{
    return impl_->ArkWriteJitCodeToFile(fd);
}

const std::vector<uintptr_t>& Unwinder::GetJitCache()
{
    return impl_->GetJitCache();
}

bool Unwinder::GetLockInfo(int32_t tid, char* buf, size_t sz)
{
    return impl_->GetLockInfo(tid, buf, sz);
}

void Unwinder::SetFrames(std::vector<DfxFrame>& frames)
{
    impl_->SetFrames(frames);
}

void Unwinder::Impl::Init()
{
    Destroy();
    unwindEntryParser_ = UnwindEntryParserFactory::CreateUnwindEntryParser(memory_);
    InitParam();
#if defined(ENABLE_MIXSTACK)
    DFXLOGD("Unwinder mixstack enable: %{public}d", enableMixstack_);
#else
    DFXLOGD("Unwinder init");
#endif
}

void Unwinder::Impl::Clear()
{
    isFpStep_ = false;
    scanUsedCount_ = 0;
    enableMixstack_ = true;
    pcs_.clear();
    frames_.clear();
    lastErrorData_ = {};
}

void Unwinder::Impl::Destroy()
{
    Clear();
    stepCache_.clear();
}

bool Unwinder::Impl::CheckAndReset(void* ctx)
{
    if ((ctx == nullptr) || (memory_ == nullptr)) {
        return false;
    }
    memory_->SetCtx(ctx);
    return true;
}

bool Unwinder::Impl::GetMainStackRangeInner(uintptr_t& stackBottom, uintptr_t& stackTop)
{
    if (maps_ != nullptr && !maps_->GetStackRange(stackBottom, stackTop)) {
        return false;
    } else if (maps_ == nullptr && !StackUtils::Instance().GetMainStackRange(stackBottom, stackTop)) {
        return false;
    }
    return true;
}

bool Unwinder::Impl::GetArkStackRangeInner(uintptr_t& arkMapStart, uintptr_t& arkMapEnd)
{
    if (maps_ != nullptr && !maps_->GetArkStackRange(arkMapStart, arkMapEnd)) {
        return false;
    } else if (maps_ == nullptr && !StackUtils::Instance().GetArkStackRange(arkMapStart, arkMapEnd)) {
        return false;
    }
    return true;
}

bool Unwinder::Impl::GetStaticArkStackRange(uintptr_t& arkMapStart, uintptr_t& arkMapEnd)
{
    if (maps_ == nullptr || !maps_->GetStaticArkRange(arkMapStart, arkMapEnd)) {
        return false;
    }
    return true;
}

bool Unwinder::Impl::GetStackRange(uintptr_t& stackBottom, uintptr_t& stackTop)
{
    if (gettid() == getpid()) {
        return GetMainStackRangeInner(stackBottom, stackTop);
    }
    return StackUtils::GetSelfStackRange(stackBottom, stackTop);
}

bool Unwinder::Impl::UnwindLocalWithTid(const pid_t tid, size_t maxFrameNum, size_t skipFrameNum)
{
#if defined(__aarch64__) || defined(__loongarch_lp64) || defined(__x86_64__)
    if (tid < 0 || tid == gettid()) {
        lastErrorData_.SetCode(UNW_ERROR_NOT_SUPPORT);
        DFXLOGE("params is nullptr, tid: %{public}d", tid);
        return false;
    }
    DFXLOGD("UnwindLocalWithTid:: tid: %{public}d", tid);
    auto threadContext = LocalThreadContext::GetInstance().CollectThreadContext(tid);
    if (threadContext != nullptr && threadContext->frameSz > 0) {
        pcs_.clear();
        size_t frameSize = std::min(threadContext->frameSz.load(), skipFrameNum + maxFrameNum);
        for (size_t i = skipFrameNum; i < frameSize; i++) {
            pcs_.emplace_back(threadContext->pcs[i]);
        }
        firstFrameSp_ = threadContext->firstFrameSp;
        return true;
    }
    return false;
#else
    return false;
#endif
}

bool Unwinder::Impl::UnwindLocalWithContext(const ucontext_t& context, size_t maxFrameNum, size_t skipFrameNum)
{
    if (regs_ == nullptr) {
        regs_ = DfxRegs::CreateFromUcontext(context);
    } else {
        regs_->SetFromUcontext(context);
    }
    return UnwindLocal(true, false, maxFrameNum, skipFrameNum);
}

bool Unwinder::Impl::UnwindLocal(bool withRegs, bool fpUnwind, size_t maxFrameNum, size_t skipFrameNum, bool enableArk)
{
    DFXLOGI("UnwindLocal:: fpUnwind: %{public}d", fpUnwind);
    uintptr_t stackBottom = 1;
    uintptr_t stackTop = static_cast<uintptr_t>(-1);
    if (!GetStackRange(stackBottom, stackTop)) {
        DFXLOGE("Get stack range error");
        return false;
    }

    if (!withRegs) {
#if defined(__aarch64__) || defined(__x86_64__)
        if (fpUnwind) {
            uintptr_t miniRegs[FP_MINI_REGS_SIZE] = {0};
            GetFramePointerMiniRegs(miniRegs, sizeof(miniRegs) / sizeof(miniRegs[0]));
            regs_ = DfxRegs::CreateFromRegs(UnwindMode::FRAMEPOINTER_UNWIND, miniRegs,
                                            sizeof(miniRegs) / sizeof(miniRegs[0]));
            withRegs = true;
        }
#endif
        if (!withRegs) {
            regs_ = DfxRegs::Create();
            auto regsData = regs_->RawData();
            if (regsData == nullptr) {
                DFXLOGE("[%{public}d]: params is nullptr", __LINE__);
                return false;
            }
            GetLocalRegs(regsData);
        }
    }
    SetBytecodePcAndInterruptPc();
    context_.pid = UNWIND_TYPE_LOCAL;
    context_.regs = regs_;
    context_.maps = maps_;
    context_.stackCheck = true;
    context_.stackBottom = stackBottom;
    context_.stackTop = stackTop;
#if defined(__aarch64__) || defined(__x86_64__)
    if (fpUnwind) {
        return UnwindByFp(&context_, maxFrameNum, skipFrameNum, enableArk);
    }
#endif
    return Unwind(&context_, maxFrameNum, skipFrameNum);
}

bool Unwinder::Impl::UnwindRemote(pid_t tid, bool withRegs, size_t maxFrameNum, size_t skipFrameNum)
{
    std::string timeLimitCheck =
        "Unwinder::Impl::UnwindRemote, tid: " + std::to_string(tid);
    ElapsedTime counter(std::move(timeLimitCheck), 20); // 20 : limit cost time 20 ms
    if ((maps_ == nullptr) || (pid_ <= 0) || (tid < 0)) {
        DFXLOGE("params is nullptr, pid: %{public}d, tid: %{public}d", pid_, tid);
        return false;
    }
    if (tid == 0) {
        tid = pid_;
    }
    if (!withRegs) {
        regs_ = DfxRegs::CreateRemoteRegs(tid);
    }
    if ((regs_ == nullptr)) {
        DFXLOGE("regs is nullptr");
        return false;
    }
    SetBytecodePcAndInterruptPc();
    firstFrameSp_ = regs_->GetSp();
    context_.pid = tid;
    context_.regs = regs_;
    context_.maps = maps_;
    return Unwind(&context_, maxFrameNum, skipFrameNum);
}

int Unwinder::Impl::ArkWriteJitCodeToFile(int fd)
{
#if defined(ENABLE_MIXSTACK)
    return DfxArk::Instance().JitCodeWriteFile(memory_.get(), &(Unwinder::AccessMem), fd,
        jitCache_.data(), jitCache_.size());
#else
    return -1;
#endif
}

#if defined(ENABLE_MIXSTACK)
bool Unwinder::Impl::StepArkJsFrame(StepFrame& frame, uint64_t frameIndex)
{
    DFX_TRACE_SCOPED_DLSYM("StepArkJsFrame pc: %p", reinterpret_cast<void *>(frame.pc));
    std::string timeLimitCheck;
    timeLimitCheck += "StepArkJsFrame, ark pc: " + std::to_string(frame.pc) +
        ", fp:" + std::to_string(frame.fp) + ", sp:" + std::to_string(frame.sp) +
        ", isJsFrame:" + std::to_string(frame.isJsFrame);
    ElapsedTime counter(timeLimitCheck, 20); // 20 : limit cost time 20 ms
    if (pid_ != UNWIND_TYPE_CUSTOMIZE) {
        DFXLOGD("+++ark pc: %{private}p, fp: %{private}p, sp: %{private}p, isJsFrame: %{public}d.",
            reinterpret_cast<void *>(frame.pc),
            reinterpret_cast<void *>(frame.fp), reinterpret_cast<void *>(frame.sp), frame.isJsFrame);
    }

    int ret = -1;
    if (isJitCrash_) {
        MAYBE_UNUSED uintptr_t methodId = 0;
        ArkUnwindParam arkParam(memory_.get(), &(Unwinder::AccessMem), &frame.fp, &frame.sp, &frame.pc,
            &methodId, &frame.isJsFrame, &frame.frameType, frameIndex, jitCache_);
        ret = DfxArk::Instance().StepArkFrameWithJit(&arkParam);
    } else {
        // Appfreeze in interpreter requires interruptPc_ and bytecodePc_ for StepArkFrame.
        // Since frame.sp and frame.pc only receive return values in the original logic,
        // they are reused to pass these values. (This can be changed once ArkStepParam
        // can be unified to have dedicated fields for interruptPc_ and bytecodePc_.)
        // When frame.pc == interruptPc_, an appfreeze in the interpreter is handled. In
        // that case, use UINTPTR_MAX as a sentinel sp to notify StepArkByNativeFrame;
        // otherwise use the real sp.
        uintptr_t stepSp = interruptPc_ != frame.pc ? frame.sp : UINTPTR_MAX;
        uintptr_t prevSp = stepSp;
        frame.pc = bytecodePc_;
        ArkStepParam arkParam(&frame.fp, &stepSp, &frame.pc, &frame.isJsFrame, &frame.frameType, frameIndex);
        ret = DfxArk::Instance().StepArkFrame(memory_.get(), &(Unwinder::AccessMem), &arkParam);
        // StepArkFrame does not rewrite sp on every invocation. Check whether sp was
        // updated via prevSp/stepSp. If updated, use new sp; otherwise keep original
        // to avoid UINTPTR_MAX polluting frame.sp.
        frame.sp = stepSp == prevSp ? frame.sp : stepSp;
    }
    if (ret < 0) {
        DFXLOGE("Failed to step ark frame");
        return false;
    }
    if (pid_ != UNWIND_TYPE_CUSTOMIZE) {
        DFXLOGD("---ark pc: %{private}p, fp: %{private}p, sp: %{private}p, isJsFrame: %{public}d.",
            reinterpret_cast<void *>(frame.pc),
            reinterpret_cast<void *>(frame.fp), reinterpret_cast<void *>(frame.sp), frame.isJsFrame);
    }
    regs_->SetPc(StripPac(frame.pc, pacMask_));
    regs_->SetSp(frame.sp);
    regs_->SetFp(frame.fp);
    return true;
}
#endif

bool Unwinder::Impl::StepV8Frame(StepFrame& frame, const std::shared_ptr<DfxMap>& map, bool& stopUnwind)
{
    if (map == nullptr) {
        return false;
    }
    bool needStepJsvmStack = enableJsvmstack_ && (map->IsJsvmExecutable());
    bool needStepArkwebStak = map->IsArkWebJsExecutable();
    if (!needStepJsvmStack && !needStepArkwebStak) {
        stopUnwind = false;
        return true;
    }
    DFX_TRACE_SCOPED_DLSYM("StepV8Frame pc: %p", reinterpret_cast<void *>(frame.pc));
    std::string timeLimitCheck;
    timeLimitCheck += "StepV8Frame, pc: " + std::to_string(frame.pc) +
        ", fp:" + std::to_string(frame.fp) + ", sp:" + std::to_string(frame.sp) +
        ", frameType: "+ std::to_string(static_cast<uint8_t>(frame.frameType));
    ElapsedTime counter(timeLimitCheck, 20); // 20 : limit cost time 20 ms
    JsvmStepParam jsvmParam(&frame.fp, &frame.sp, &frame.pc, &frame.isJsFrame);
    if (DfxJsvm::Instance().StepJsvmFrame(memory_.get(), &(Unwinder::AccessMem), &jsvmParam) < 0) {
        DFXLOGE("Failed to step jsvm frame");
        return false;
    }
    regs_->SetPc(StripPac(frame.pc, pacMask_));
    regs_->SetSp(frame.sp);
    regs_->SetFp(frame.fp);
    stopUnwind = true;
    return true;
}

// K12:__start_thread / __libc_init 是线程的栈底;它们之后出现的任何帧
// (由 scan/LR/fp 兜底从栈底残留里捞出来的)都是伪帧。hiperf 采样链上
// 观测到约 82% 受此影响(trampoline 镜像 + 重复的 start);
// cdumpcatcher 不受影响。
bool Unwinder::Impl::IsThreadRootFrame()
{
    if (frames_.size() < 2 || maps_ == nullptr) {
        return false;
    }
    if (rootMapGen_ != maps_.get()) { // maps 快照已更换:丢弃过期键
        rootMapCache_.clear();
        rootMapGen_ = maps_.get();
    }
    const DfxFrame& fr = frames_.back();
    const DfxMap* m = fr.map.get();
    if (m == nullptr) {
        return false;
    }
    bool isRootMap = false;
    auto it = rootMapCache_.find(m);
    if (it != rootMapCache_.end()) {
        isRootMap = it->second;
    } else {
        const std::string& name = m->name;
        // 只做精确模块名匹配:裸 "libc" 子串会连带命中 libcrypto /
        // libc++_shared,白白付出符号查询。
        isRootMap = (name.size() >= 8 && name.compare(name.size() - 8, 8, "/libc.so") == 0) ||
                    (name.find("ld-musl") != std::string::npos);
        // qwen 评审:16 太小——一个进程有 100+ 个不同的 DfxMap 指针(每个
        // so 的每个 VMA 一个);上限 16 时大多数应用库帧都会 miss 缓存,
        // 每帧都付一次字符串比较(占 2.58% 热点)。512 项 ≈ 30KB,可覆盖
        // 全部工作集。
        if (rootMapCache_.size() < 512) {
            rootMapCache_[m] = isRootMap;
        }
    }
    if (!isRootMap) {
        return false;
    }
    std::string funcName;
    uint64_t funcOffset = 0;
    if (!GetSymbolByPc(fr.pc, maps_, funcName, funcOffset)) {
        return false; // 查不到符号 -> 继续回溯(旧行为)
    }
    return (funcName.find("__start_thread") != std::string::npos) ||
           (funcName.find("__libc_init") != std::string::npos) ||
           (funcName.find("__libc_start_main") != std::string::npos);
}

// FpTailUnwind:从原始采样 x29 起走纯 FP 链。v2 锚点续走设计
// (FpStep_odex 文档):
//   - 锚点 = frames_.back().sp(最后一个成功帧的 SP,永远干净——失败的帧
//     从不加入 frames_)
//   - 只追加 fp > 锚点的帧(栈内物理位置更深)
//   - 不比较 pc、不去重——避开"返回地址 vs DoPcAdjust 后 pc"错位和
//     合法递归被误删的问题
//   - 到线程根(IsThreadRootFrame)/ fp 不再增长 / 读失败 / 帧数预算
//     耗尽即停
void Unwinder::Impl::FpTailUnwind(void* ctx, size_t maxFrameNum)
{
#if defined(__aarch64__)
    if (ctx != nullptr && memory_ != nullptr) {
        memory_->SetCtx(ctx);
    }
    if (frames_.empty()) return;
    // 锚点:最后一个成功加入帧的 SP(干净、未受污染)
    uintptr_t anchor = frames_.back().sp;
    uintptr_t fp = sampleX29_;
    uintptr_t prevFp = 0;
    size_t budget = maxFrameNum - frames_.size();
    size_t appended = 0;
    while (fp != 0 && fp > prevFp && appended < budget) {
        uintptr_t nextFp = 0, nextPc = 0;
        // 与 FpStep 同一写法:第一次 Read 置 incre=true 推进游标跳过
        // caller_fp,第二次原地读 caller_pc。(Read 形参是 uintptr_t&——
        // 切勿传右值表达式。)
        uintptr_t ptr = fp;
        if (!memory_->Read<uintptr_t>(ptr, &nextFp, true)) break;
        if (!memory_->Read<uintptr_t>(ptr, &nextPc, false)) break;
        if (nextFp == 0 || nextFp <= fp) break;
        nextPc = StripPac(nextPc, pacMask_);
        // 与主循环同一调用点约定:fp 帧记录存的是原始返回地址,主循环帧存
        // DoPcAdjust 后的 pc,这里同样调整保证符号化可比(偏移差 4)。
        DoPcAdjust(nextPc);
        // 锚点续走:跳过位于锚点之上(含)的帧(主循环已回溯过),
        // 只追加更深的帧
        if (fp <= anchor) {
            prevFp = fp;
            fp = nextFp;
            continue;
        }
        // 校验:pc 必须落在可执行映射(拒绝栈残留)
        std::shared_ptr<DfxMap> map = nullptr;
        if (maps_ == nullptr || !maps_->FindMapByAddr(nextPc, map) ||
            map == nullptr || !map->IsMapExec()) {
            break; // 垃圾 pc——停止,不伪造帧
        }
        StepFrame frame;
        frame.pc = nextPc;
        frame.sp = fp;
        frame.fp = nextFp;
        AddFrame(frame, map);
        appended++;
        // 线程根检查(K12,同一逻辑)
        if (!frames_.empty()) {
            const auto& lastF = frames_.back();
            if (lastF.map != nullptr) {
                const std::string& mn = lastF.map->name;
                if (mn.size() >= 8 &&
                    mn.compare(mn.size() - 8, 8, "/libc.so") == 0) {
                    std::string fn; uint64_t fo = 0;
                    if (GetSymbolByPc(lastF.pc, maps_, fn, fo) &&
                        (fn.find("__start_thread") != std::string::npos ||
                         fn.find("__libc_init") != std::string::npos)) {
                        break;
                    }
                }
            }
        }
        prevFp = fp;
        fp = nextFp;
    }
    if (appended > 0) {
        DFXLOGU("FpTailUnwind: appended %zu frames (anchor=0x%lx)",
            appended, (uint64_t)anchor);
    }
#else
    // 非 aarch64 平台:未实现 FP 链收尾;保留函数签名让(无条件)调用点
    // 可链接,stopByFailure 在所有平台都被消费。
    (void)ctx;
    (void)maxFrameNum;
#endif
}

// 确定性跳出 art_quick_to_interpreter_bridge。偏移取自容器 libart 的
// 反汇编(aarch64):
//   art_quick_to_interpreter_bridge @ 0x34f5e0,大小 0xfc
//   序言:sub sp,#224; ...; stp x29, x30, [sp,#208]; bl 桥体
// 保存的这对值就是 quick 调用者的真实帧记录,跳出后链沿标准帧记录继续。
// 与 ART 版本耦合:libart 升级后须按同样方式重推(单符号反汇编)。
void Unwinder::Impl::StepBridge(size_t maxFrameNum)
{
#if defined(__aarch64__)
    constexpr uintptr_t kBridgeOff = 0x34f5e0;
    constexpr uintptr_t kBridgeSize = 0xfc;
    constexpr uintptr_t kSavedFpSlot = 208;
    constexpr uintptr_t kSavedLrSlot = 216;
    constexpr uintptr_t kBridgeFrameSize = 224;
    if (frames_.empty() || maps_ == nullptr) return;
    if (!libartBaseFound_) {
        libartBaseFound_ = true;
        // 加载基址 = libart.so 最低的那个映射(r-- 的 ELF 头 LOAD),而非
        // "任一可执行映射":rx 行不止一条时,首条 exec 行可能是某个 LOAD
        // 中部的 vaddr,bias+符号偏移 就会算错(评审 R3)。
        uintptr_t lowest = UINTPTR_MAX;
        for (const auto& m : maps_->GetMaps()) {
            if (m != nullptr && m->name.find("libart.so") != std::string::npos &&
                m->name.find("libartbase") == std::string::npos &&
                m->name.find("libartd") == std::string::npos &&
                m->begin < lowest) {
                lowest = m->begin;
            }
        }
        if (lowest == UINTPTR_MAX) return;
        // 桥序言的机器码签名(评审 R3/R5):
        //   +0x00: sub sp, sp, #224        = 0xd10383ff
        //   +0x40: stp x29, x30, [sp,#208] = 0xa90d7bfd
        // 任一不匹配(ART 升级挪动/改写了桥)即整体失效:StepBridge 保持
        // 关闭,而不是赌旧偏移仍然正确。
        uintptr_t a0 = lowest + kBridgeOff;
        uintptr_t a40 = lowest + kBridgeOff + 0x40;
        uintptr_t w0 = 0, w40 = 0;
        if (!memory_->Read<uintptr_t>(a0, &w0, false) ||
            !memory_->Read<uintptr_t>(a40, &w40, false) ||
            w0 != 0xd10383ffULL || w40 != 0xa90d7bfdULL) {
            return; // 签名不匹配——保持 libartBase_ == 0(禁用)
        }
        libartBase_ = lowest;
    }
    if (libartBase_ == 0) return;
    const DfxFrame& last = frames_.back();
    const uintptr_t pc = static_cast<uintptr_t>(last.pc);
    const uintptr_t lo = libartBase_ + kBridgeOff;
    if (pc < lo || pc >= lo + kBridgeSize) return;
    // 固定槽位逃生:调用者 fp/lr 就在已捕获的采样栈里。
    const uintptr_t bridgeSp = static_cast<uintptr_t>(last.sp);
    uintptr_t fpAddr = bridgeSp + kSavedFpSlot;
    uintptr_t lrAddr = bridgeSp + kSavedLrSlot;
    uintptr_t callerFp = 0, callerLr = 0;
    if (!memory_->Read<uintptr_t>(fpAddr, &callerFp, false)) return;
    if (!memory_->Read<uintptr_t>(lrAddr, &callerLr, false)) return;
    uintptr_t callerPc = StripPac(callerLr, pacMask_);
    DoPcAdjust(callerPc);
    if (callerFp <= bridgeSp || callerPc == 0) return; // 取值不合理
    // 栈残留加固(评审 R1):ABI 对齐、越过断帧自身 fp 的单调增长、且在
    // 已捕获栈窗口之内。
    if ((callerFp & 0xf) != 0) return;
    if (callerFp <= static_cast<uintptr_t>(last.fp)) return;
    if (callerFp - bridgeSp > 0x10000) return;
    std::shared_ptr<DfxMap> map = nullptr;
    if (!maps_->FindMapByAddr(callerPc, map) || map == nullptr || !map->IsMapExec()) return;
    StepFrame frame;
    frame.pc = callerPc;
    frame.sp = bridgeSp + kBridgeFrameSize;
    frame.fp = callerFp;
    AddFrame(frame, map);
    // 触发/续走可观测性(评审 R3):发布版日志会被裁剪,改落一行计数文件
    // (每 1000 次记一笔)。
    {
        static std::atomic<uint32_t> sBridgeHits {0};
        uint32_t n = sBridgeHits.fetch_add(1) + 1;
        if ((n % 1000) == 0) {
            FILE* sf = fopen("/data/local/tmp/bridge_stats", "a");
            if (sf != nullptr) {
                fprintf(sf, "hits=%u\n", n);
                fclose(sf);
            }
        }
    }
    // 调用者是 quick 代码:沿标准帧记录继续走链,规则同 FpTailUnwind。
    uintptr_t fp = callerFp;
    uintptr_t prevFp = 0;
    while (fp != 0 && fp > prevFp && frames_.size() < maxFrameNum) {
        uintptr_t nextFp = 0, nextPc = 0;
        uintptr_t ptr = fp;
        if (!memory_->Read<uintptr_t>(ptr, &nextFp, true)) break;
        if (!memory_->Read<uintptr_t>(ptr, &nextPc, false)) break;
        if (nextFp == 0 || nextFp <= fp) break;
        uintptr_t pc2 = StripPac(nextPc, pacMask_);
        DoPcAdjust(pc2);
        std::shared_ptr<DfxMap> map2 = nullptr;
        if (!maps_->FindMapByAddr(pc2, map2) || map2 == nullptr || !map2->IsMapExec()) {
            break; // 垃圾 pc——停止,不伪造帧
        }
        StepFrame frame2;
        frame2.pc = pc2;
        frame2.sp = fp;
        frame2.fp = nextFp;
        AddFrame(frame2, map2);
        const auto& lf = frames_.back();
        if (lf.map != nullptr) {
            const std::string& mn = lf.map->name;
            if (mn.size() >= 8 && mn.compare(mn.size() - 8, 8, "/libc.so") == 0) {
                break; // 到达线程根约定
            }
        }
        prevFp = fp;
        fp = nextFp;
    }
#else
    (void)maxFrameNum; // 保留签名,非 aarch64 也可链接
#endif
}

// M3:受管栈走链。读取活的 art::Thread(采样时刻的 x28),从 Thread+168
// 取 quick 链表头,按 FpTailUnwind 同款锚点续走规则走链。所有读取都走
// process_vm_readv:Thread 对象和当前线程栈都在目标进程里(memory_->Read
// 只能看到已捕获的采样栈/elf 文件)。时序:链是回溯时读的,不是采样时;
// 深层帧(靠根方向)在秒级稳定,链头可能已移动——物理地址锚点保证拼接
// 依然有效。
void Unwinder::Impl::StepManaged(void* ctx, size_t maxFrameNum)
{
#if defined(__aarch64__)
    (void)ctx;
    if (frames_.empty() || pid_ <= 0) return;
    uintptr_t self = (*regs_)[REG_AARCH64_X28];
    // 容器 art::Thread* 的保守合法性检查:落在堆区间、指针对齐。其他取值
    // (本机代码会改写 x28)直接退出。
    if (self < 0x5000000000ULL || self >= 0x8000000000ULL || (self & 7) != 0) return;
    auto rdRemote = [this](uintptr_t addr, uintptr_t* out) {
        struct iovec local { out, sizeof(uintptr_t) };
        struct iovec remote { reinterpret_cast<void*>(addr), sizeof(uintptr_t) };
        return process_vm_readv(pid_, &local, 1, &remote, 1, 0) ==
            static_cast<ssize_t>(sizeof(uintptr_t));
    };
    // 自引用检查(art::Thread 存有 self_;顺带过滤曾骗过 probe v2 的
    // 自引用链表节点)。
    bool selfFound = false;
    for (size_t off = 0; off < 512 && !selfFound; off += sizeof(uintptr_t)) {
        uintptr_t v = 0;
        if (rdRemote(self + off, &v) && v == self) selfFound = true;
    }
    if (!selfFound) return;
    // Thread+168 处的 ManagedStack 三元组(反汇编实证)。
    uintptr_t msQuick = 0, msLink = 0, msShadow = 0;
    if (!rdRemote(self + 168, &msQuick) || !rdRemote(self + 176, &msLink) ||
        !rdRemote(self + 184, &msShadow)) {
        return;
    }
    auto inStack = [](uintptr_t v) {
        return v >= 0x5f00000000ULL && v < 0x8000000000ULL;
    };
    if (msQuick != 0 && !inStack(msQuick)) return;      // 假线程
    if (msShadow != 0 && (msShadow < 0x5000000000ULL || msShadow >= 0x8000000000ULL)) return;
    // 锚点续走,规则同 FpTailUnwind:只追加帧记录位于最后一个成功帧 SP
    // 之上的帧。
    const uintptr_t anchor = frames_.back().sp;
    size_t budget = maxFrameNum - frames_.size();
    size_t appended = 0;
    uintptr_t qf = msQuick;
    uintptr_t prevQf = 0;
    while (qf != 0 && qf > prevQf && appended < budget) {
        uintptr_t nextFp = 0, ra = 0;
        if (!rdRemote(qf, &nextFp)) break;
        if (!rdRemote(qf + sizeof(uintptr_t), &ra)) break;
        if (nextFp == 0 || nextFp <= qf) break;
        uintptr_t pc = StripPac(ra, pacMask_);
        DoPcAdjust(pc);
        if (qf > anchor) {
            std::shared_ptr<DfxMap> map = nullptr;
            if (maps_ == nullptr || !maps_->FindMapByAddr(pc, map) ||
                map == nullptr || !map->IsMapExec()) {
                break; // 垃圾 pc——停止,不伪造帧
            }
            StepFrame frame;
            frame.pc = pc;
            frame.sp = qf;
            frame.fp = nextFp;
            AddFrame(frame, map);
            appended++;
            const auto& lastF = frames_.back();
            if (lastF.map != nullptr) {
                const std::string& mn = lastF.map->name;
                if (mn.size() >= 8 && mn.compare(mn.size() - 8, 8, "/libc.so") == 0) {
                    break; // 到达线程根约定
                }
            }
        }
        prevQf = qf;
        qf = nextFp;
    }
    if (appended > 0) {
        DFXLOGW("StepManaged: appended %zu frames from live managed chain", appended);
    }
#else
    (void)ctx;
    (void)maxFrameNum;
#endif
}

bool Unwinder::Impl::UnwindFrame(void *ctx, StepFrame& frame, bool& needAdjustPc)
{
    frame.pc = regs_->GetPc();
    frame.sp = regs_->GetSp();
    frame.fp = regs_->GetFp();
    // Check if this is a signal frame.
    if (pid_ != UNWIND_TYPE_LOCAL && pid_ != UNWIND_TYPE_CUSTOMIZE_LOCAL &&
        regs_->StepIfSignalFrame(static_cast<uintptr_t>(frame.pc), memory_)) {
        DFXLOGW("Step signal frame, pc: %{private}p", reinterpret_cast<void *>(frame.pc));
        StepInner(true, frame, ctx);
        return true;
    }
    // DoPcAdjust 之前的 pc:上一步产出的原始返回地址。LR 兜底若重复消费
    // 陈旧 LR,pc 会在 lr 与 lr-4(调整量)之间往返,所以下方重复帧检查
    // 除调整后的入口 pc 外还须与 rawPc 比较。
    uintptr_t rawPc = frame.pc;
    if (!frame.isJsFrame && needAdjustPc) {
        DoPcAdjust(frame.pc);
    }
    needAdjustPc = true;
    uintptr_t prevPc = frame.pc;
    uintptr_t prevSp = frame.sp;
    if (!StepInner(false, frame, ctx)) {
        return false;
    }
    // The first frame may not have been updated on the pc and sp, when lr fall back
    if (frame.sp == prevSp && frames_.size() > 1 &&
        (frame.pc == prevPc || frame.pc == rawPc)) {
        if (pid_ >= 0) {
            MAYBE_UNUSED UnwindContext* uctx = reinterpret_cast<UnwindContext *>(ctx);
            DFXLOGU("pc and sp is same, tid: %{public}d", uctx->pid);
        } else {
            DFXLOGU("pc and sp is same");
        }
        lastErrorData_.SetAddrAndCode(frame.pc, UNW_ERROR_REPEATED_FRAME);
        return false;
    }
    return true;
}

bool Unwinder::Impl::Unwind(void *ctx, size_t maxFrameNum, size_t skipFrameNum)
{
    if ((regs_ == nullptr) || (!CheckAndReset(ctx))) {
        DFXLOGE("[%{public}d]: params is nullptr?", __LINE__);
        lastErrorData_.SetCode(UNW_ERROR_INVALID_CONTEXT);
        return false;
    }
    SetLocalStackCheck(ctx, false);
    Clear();
#if defined(__aarch64__)
    sampleXRefs_ = (*regs_)[25]; // 25: x25(xREFS) — perf sample真值,不受CFI链污染
    sampleX29_ = (*regs_)[29]; // 29: x29(FP) — sample true value, FpTailUnwind chain anchor
#endif

    bool needAdjustPc = false;
    isResetFrames_ = false;
    lastLrFallbackPc_ = 0;
    bool stopByFailure = false; // 阶段一:仅链中失败时才走 FpTailUnwind
    StepFrame frame;
    do {
        if (!isResetFrames_ && (skipFrameNum != 0) && (frames_.size() >= skipFrameNum)) {
            isResetFrames_ = true;
            DFXLOGU("frames size: %{public}zu, will be reset frames", frames_.size());
            frames_.clear();
        }
        if (frames_.size() >= maxFrameNum) {
            DFXLOGW("frames size: %{public}zu", frames_.size());
            lastErrorData_.SetCode(UNW_ERROR_MAX_FRAMES_EXCEEDED);
            break;
        }

        if (!UnwindFrame(ctx, frame, needAdjustPc)) {
            stopByFailure = true;
            break;
        }
        if (IsThreadRootFrame()) { // K12:到达线程根,停止回溯
            break;
        }
    } while (true);
    // 阶段零可观测性:把终止错误码分桶统计,一次 hilog 检索即可区分
    // RA-undefined 终止(odex 桥 CFI,成因 (d))、被污染 fp 的非法值
    // (成因 (a))与读失败((a)/(c))。
    {
        static std::atomic<uint64_t> sTotal {0}, sNone {0}, sRaUndef {0}, sIllegal {0}, sMem {0}, sOther {0};
        uint64_t n = sTotal.fetch_add(1) + 1;
        uint16_t termCode = lastErrorData_.GetCode();
        if (termCode == 0) {
            sNone.fetch_add(1);
        } else if (termCode == UNW_ERROR_RETURN_ADDRESS_UNDEFINED) {
            sRaUndef.fetch_add(1);
        } else if (termCode == UNW_ERROR_ILLEGAL_VALUE) {
            sIllegal.fetch_add(1);
        } else if (termCode == UNW_ERROR_INVALID_MEMORY) {
            sMem.fetch_add(1);
        } else {
            sOther.fetch_add(1);
        }
        if ((n % 500) == 0) {
            DFXLOGI("UNW_STATS total:%{public}" PRIu64 " none:%{public}" PRIu64
                    " ra_undef:%{public}" PRIu64 " illegal:%{public}" PRIu64
                    " memfail:%{public}" PRIu64 " other:%{public}" PRIu64 "",
                n, sNone.load(), sRaUndef.load(), sIllegal.load(), sMem.load(), sOther.load());
        }
    }
    // speed-profile 文档 §7:DWARF 在无表 odex 中断链、兜底链被污染时,
    // 从原始采样 x29 出发、由 ART 维护的 FP 链依然有效。作为终极兜底走
    // 一遍(锚点续走:只追加物理位置深于最后一个成功帧 SP 的帧——不比
    // pc、不去重)。仅失败时走:已到线程根(或帧数预算耗尽)的链没有尾巴
    // 可捞,不应白付一趟走链。(无条件调用:FpTailUnwind 在非 aarch64 上
    // 编译为空操作,顺带让 stopByFailure 在所有平台都被消费。)
    if (stopByFailure && !frames_.empty()) {
        // 先做确定性桥跳转(无活读,用已捕获的栈);FP 收尾和受管走链
        // 随后处理其他形态。
        StepBridge(maxFrameNum);
    }
    if (stopByFailure && sampleX29_ != 0 && !frames_.empty()) {
        FpTailUnwind(ctx, maxFrameNum);
    }
    // M3:FP 收尾之后再试活受管链——它能穿过挡住 FP 走链的 JNI/nterp
    // 壁垒(链头在壁垒之后)。默认关闭(评审 R6):实测活走链几乎无增益
    // (深层帧在回溯前就已弹栈),每条断链却要付一次 vm-readv。
#if defined(__aarch64__)
    if (stopByFailure && enableManagedWalk_ && !frames_.empty()) {
        StepManaged(ctx, maxFrameNum);
    }
#endif
#if defined(__aarch64__)
    // 受管栈探针(原型,里程碑 M1):断链且采样 x28 带有貌似合法的
    // art::Thread*(ART quick 代码 SELF 约定)时,经 process_vm_readv 转储
    // Thread 对象邻域(memory_->Read 够不到匿名堆;JIT 读取器已实证这条
    // 直读路径可在进程内工作)。只落探针文件——不改变行为,每进程限次,
    // 供离线偏移分析。
    if (stopByFailure) {
        static std::atomic<uint32_t> sProbeCount {0};
        uintptr_t self = (*regs_)[REG_AARCH64_X28];
        if (self > 0x10000 && (self & 7) == 0 && pid_ > 0 && sProbeCount.load() < 16) {
            const uintptr_t page = self & ~static_cast<uintptr_t>(0xfff);
            const size_t kBytes = 8192; // 覆盖 [page, page+8K):self 及其后
                                        // 的 tls_/tlsPtr_ 邻域
            uint8_t out[kBytes];
            // 先一次大块读(单次系统调用);仅当整块失败(窗口部分未映射)
            // 才退回逐字读。
            struct iovec localBulk { out, kBytes };
            struct iovec remoteBulk { reinterpret_cast<void *>(page), kBytes };
            bool ok = process_vm_readv(pid_, &localBulk, 1, &remoteBulk, 1, 0) ==
                static_cast<ssize_t>(kBytes);
            if (!ok) {
                ok = true;
                for (size_t i = 0; i < kBytes && ok; i += sizeof(uintptr_t)) {
                    struct iovec local { out + i, sizeof(uintptr_t) };
                    struct iovec remote { reinterpret_cast<void *>(page + i), sizeof(uintptr_t) };
                    if (process_vm_readv(pid_, &local, 1, &remote, 1, 0) !=
                        static_cast<ssize_t>(sizeof(uintptr_t))) {
                        ok = false;
                    }
                }
            }
            if (ok) {
                // 转储前校验:真正的 art::Thread 含自引用的 self_ 指针
                // (== x28)。本机代码里 x28 只是普通被调用者保存寄存器
                // (probe v1 就这样转储过 JSON 缓冲)——必须找到自引用才认。
                bool selfFound = false;
                for (size_t i = 0; i + sizeof(uintptr_t) <= kBytes; i += sizeof(uintptr_t)) {
                    uintptr_t v = 0;
                    if (memcpy_s(&v, sizeof(v), out + i, sizeof(v)) == EOK && v == self) {
                        selfFound = true;
                        break;
                    }
                }
                if (selfFound) {
                    char probePath[96] = {0};
                    if (snprintf_s(probePath, sizeof(probePath), sizeof(probePath) - 1,
                        "/data/local/tmp/mprobe_%u.bin", sProbeCount.load()) > 0) {
                        FILE* pf = fopen(probePath, "wb");
                        if (pf != nullptr) {
                            // 16 字节头:magic + tid + self,随后是 8K 窗口
                            const uint32_t magic = 0x4b54534d; // "MSTK"
                            fwrite(&magic, sizeof(magic), 1, pf);
                            const uint32_t tid = static_cast<uint32_t>(gettid());
                            fwrite(&tid, sizeof(tid), 1, pf);
                            fwrite(&self, sizeof(self), 1, pf);
                            fwrite(out, 1, kBytes, pf);
                            fclose(pf);
                            sProbeCount.fetch_add(1); // 只有真正转储才消耗配额
                            DFXLOGW("ManagedProbe: dumped thread=%{private}p to %{public}s",
                                reinterpret_cast<void *>(self), probePath);
                        }
                    }
                }
            }
        }
    }
#endif
    DFXLOGU("Last error code: %{public}d, addr: %{public}p",
        (int)GetLastErrorCode(), reinterpret_cast<void *>(GetLastErrorAddr()));
    DFXLOGU("Last frame size: %{public}zu, last frame pc: %{public}p",
        frames_.size(), reinterpret_cast<void *>(regs_->GetPc()));
    return (frames_.size() > 0);
}

#if defined(ENABLE_MIXSTACK)
int Unwinder::Impl::UnwindArkFrameByFp(StepFrame& frame, const ArkMapRange& arkMapRange, uint64_t& frameIndex)
{
    bool isStaticArkInterpreter = (frame.pc >= arkMapRange.staticArkMapStart) &&
        (frame.pc < arkMapRange.staticArkMapEnd);
    bool isArkInterpreter = (frame.pc >= arkMapRange.arkMapStart) && (frame.pc < arkMapRange.arkMapEnd);
    bool isArkFrame = (frame.frameType == FrameType::STATIC_JS_FRAME) || (frame.frameType == FrameType::JS_FRAME);
    if (!isStaticArkInterpreter && !isArkInterpreter && !isArkFrame) {
        return 1; // if it is not an ark frame, return 1 directly
    }
    if (isStaticArkInterpreter) {
        frame.frameType = FrameType::STATIC_JS_FRAME;
        frameIndex = 0;
    }
    if (!StepArkJsFrame(frame, frameIndex)) {
        DFXLOGE("Failed to step ark Js frame, pc: %{private}p", reinterpret_cast<void *>(frame.pc));
        lastErrorData_.SetAddrAndCode(frame.pc, UNW_ERROR_STEP_ARK_FRAME);
        return -1;
    }
    frameIndex++;
    return 0;
}
#endif

bool Unwinder::Impl::UnwindByFp(void *ctx, size_t maxFrameNum, size_t skipFrameNum, bool enableArk)
{
    if (regs_ == nullptr) {
        DFXLOGE("[%{public}d]: params is nullptr?", __LINE__);
        return false;
    }
    pcs_.clear();
    bool needAdjustPc = false;
    bool resetFrames = false;
    ArkMapRange arkMapRange;
    if (enableArk) {
        GetArkStackRangeInner(arkMapRange.arkMapStart, arkMapRange.arkMapEnd);
        GetStaticArkStackRange(arkMapRange.staticArkMapStart, arkMapRange.staticArkMapEnd);
    }

    StepFrame frame;
    MAYBE_UNUSED uint64_t frameIndex = 0;
    do {
        if (!resetFrames && skipFrameNum != 0 && (pcs_.size() == skipFrameNum)) {
            DFXLOGU("pcs size: %{public}zu, will be reset pcs", pcs_.size());
            resetFrames = true;
            pcs_.clear();
        }
        if (pcs_.size() >= maxFrameNum) {
            lastErrorData_.SetCode(UNW_ERROR_MAX_FRAMES_EXCEEDED);
            break;
        }

        frame.pc = regs_->GetPc();
        frame.sp = regs_->GetSp();
        frame.fp = regs_->GetFp();
        if (!frame.isJsFrame && needAdjustPc) {
            DoPcAdjust(frame.pc);
        }
        needAdjustPc = true;
        pcs_.emplace_back(frame.pc);
#if defined(ENABLE_MIXSTACK)
        if (enableArk) {
            int ret = UnwindArkFrameByFp(frame, arkMapRange, frameIndex);
            if (ret == 0) {
                continue;
            } else if (ret == -1) {
                break;
            }
        }
#endif

        if (!FpStep(frame.fp, frame.pc, ctx) || (frame.pc == 0)) {
            break;
        }
    } while (true);
    return (pcs_.size() > 0);
}

bool Unwinder::Impl::FpStep(uintptr_t& fp, uintptr_t& pc, void *ctx)
{
#if defined(__aarch64__) || defined(__x86_64__)
    DFXLOGU("+fp: %{public}lx, pc: %{public}lx", (uint64_t)fp, (uint64_t)pc);
    if ((regs_ == nullptr) || (memory_ == nullptr)) {
        DFXLOGE("[%{public}d]: params is nullptr", __LINE__);
        return false;
    }
    if (ctx != nullptr) {
        memory_->SetCtx(ctx);
    }

    uintptr_t prevFp = fp;
    uintptr_t ptr = fp;
    if (ptr != 0 && memory_->Read<uintptr_t>(ptr, &fp, true) &&
        memory_->Read<uintptr_t>(ptr, &pc, false)) {
        if (fp != 0 && fp <= prevFp) {
            DFXLOGU("Illegal or same fp value");
            lastErrorData_.SetAddrAndCode(pc, UNW_ERROR_ILLEGAL_VALUE);
            return false;
        }
#ifdef __x86_64__
        uintptr_t newSp = fp + X86_FP_SP_OFFSET;
        regs_->SetReg(REG_FP, &fp);
        regs_->SetReg(REG_SP, &newSp);
        regs_->SetPc(pc);
#else
        regs_->SetReg(REG_FP, &fp);
        regs_->SetReg(REG_SP, &prevFp);
        regs_->SetPc(StripPac(pc, pacMask_));
#endif
        DFXLOGU("-fp: %{public}lx, pc: %{public}lx", (uint64_t)fp, (uint64_t)pc);
        return true;
    }
#endif
    return false;
}

bool Unwinder::Impl::Step(uintptr_t& pc, uintptr_t& sp, void *ctx)
{
    DFX_TRACE_SCOPED_DLSYM("Step pc:%p", reinterpret_cast<void *>(pc));
    if ((regs_ == nullptr) || (!CheckAndReset(ctx))) {
        DFXLOGE("[%{public}d]: params is nullptr?", __LINE__);
        return false;
    }
    bool ret = false;
    StepFrame frame;
    frame.pc = pc;
    frame.sp = sp;
    frame.fp = regs_->GetFp();
    // Check if this is a signal frame.
    if (regs_->StepIfSignalFrame(frame.pc, memory_)) {
        DFXLOGW("Step signal frame, pc: %{private}p", reinterpret_cast<void *>(frame.pc));
        ret = StepInner(true, frame, ctx);
    } else {
        ret = StepInner(false, frame, ctx);
    }
    pc = frame.pc;
    sp = frame.sp;
    return ret;
}

bool Unwinder::Impl::FindCache(uintptr_t pc, std::shared_ptr<DfxMap>& map, std::shared_ptr<RegLocState>& rs)
{
    if (enableCache_ && !isFpStep_) {
        auto iter = stepCache_.find(pc);
        if (iter != stepCache_.end()) {
            if (pid_ != UNWIND_TYPE_CUSTOMIZE) {
                DFXLOGU("Find rs cache, pc: %{public}p", reinterpret_cast<void *>(pc));
            }
            rs = iter->second.rs;
            map = iter->second.map;
            return true;
        }
    }
    return false;
}

bool Unwinder::Impl::AddFrameMap(const StepFrame& frame, std::shared_ptr<DfxMap>& map)
{
    int mapRet = memory_->GetMapByPc(frame.pc, map);
    if (mapRet != UNW_ERROR_NONE && maps_ != nullptr) {
        // accessor 提供的 maps 可能落后于目标进程的活映射:customize 调用
        // 方(如 hiperf)喂的是 perf 记录的 maps,永远不知道 reserve+mprotect
        // 出来的区域(如 ART JIT 缓存),此处映射未命中会截断调用链。先拿
        // 自己的 /proc 快照重试,再判定 pc 未映射。只认可执行映射:落在
        // 非执行区的 pc 无论哪种情况都是垃圾。
        std::shared_ptr<DfxMap> snapshotMap;
        if (maps_->FindMapByAddr(static_cast<uintptr_t>(frame.pc), snapshotMap) &&
            snapshotMap != nullptr && snapshotMap->IsMapExec()) {
            map = snapshotMap;
            mapRet = UNW_ERROR_NONE;
            DFXLOGU("Frame map found by snapshot fallback, pc: 0x%{public}" PRIx64
                ", map: %{public}s", (uint64_t)frame.pc, map->name.c_str());
        }
    }
    if (mapRet != UNW_ERROR_NONE) {
        if (frame.isJsFrame) {
            DFXLOGW("Failed to get js frame map, frames size: %{public}zu", frames_.size());
            mapRet = UNW_ERROR_UNKNOWN_ARK_MAP;
        }
        if (frames_.size() > 2) { // 2, least 2 frame
            DFXLOGU("Failed to get map, frames size: %{public}zu", frames_.size());
            lastErrorData_.SetAddrAndCode(frame.pc, mapRet);
            return false;
        }
    }
    AddFrame(frame, map);
    return true;
}

bool Unwinder::Impl::UnwindArkFrame(StepFrame& frame, const std::shared_ptr<DfxMap>& map, bool& stopUnwind)
{
#if defined(ENABLE_MIXSTACK)
    if (stopWhenArkFrame_ && (map != nullptr && (map->IsArkExecutable() || map->IsStaticArkExecutable()))) {
        DFXLOGU("Stop by ark frame");
        stopUnwind = true;
        return false;
    }
    if (!enableMixstack_ || map == nullptr) {
        return true;
    }
    if (map->IsStaticArkExecutable() || frame.frameType == FrameType::STATIC_JS_FRAME) {
        static uint64_t frameIndex = 0;
        if (map->IsStaticArkExecutable()) {
            frame.frameType = FrameType::STATIC_JS_FRAME;
            frameIndex = 0;
        }
        if (!StepArkJsFrame(frame, frameIndex)) {
            DFXLOGE("Failed to step static ark Js frame, pc: %{private}p", reinterpret_cast<void *>(frame.pc));
            return false;
        }
        frameIndex++;
        stopUnwind = true;
    } else if (map->IsArkExecutable() || frame.frameType == FrameType::JS_FRAME) {
        if (!StepArkJsFrame(frame)) {
            DFXLOGE("Failed to step ark Js frame, pc: %{private}p", reinterpret_cast<void *>(frame.pc));
            lastErrorData_.SetAddrAndCode(frame.pc, UNW_ERROR_STEP_ARK_FRAME);
            return false;
        }
        stopUnwind = true;
    }
#endif
    return true;
}

bool Unwinder::Impl::ParseUnwindTable(uintptr_t pc, std::shared_ptr<RegLocState>& rs)
{
    // find unwind table and entry
    UnwindTableInfo uti;
    int utiRet = memory_->FindUnwindTable(pc, uti);
    if (utiRet != UNW_ERROR_NONE) {
        lastErrorData_.SetAddrAndCode(pc, utiRet);
        DFXLOGU("Failed to find unwind table ret: %{public}d", utiRet);
        return false;
    }
    rs = std::make_shared<RegLocState>();
    // parse instructions and get cache rs
    std::shared_ptr<UnwindEntryParser> parser = unwindEntryParser_;
    if (!parser->Step(pc, uti, rs)) {
        lastErrorData_.SetAddrAndCode(parser->GetLastErrorAddr(), parser->GetLastErrorCode());
        DFXLOGU("Step unwind entry failed");
        return false;
    }
    return true;
}

void Unwinder::Impl::StepToNextFpIfNeed()
{
#if defined(__aarch64__) || defined(__x86_64__)
    if (memory_ == nullptr || regs_ == nullptr) {
        return;
    }
    const uintptr_t pcSlotOff = sizeof(uintptr_t);
    uintptr_t fpStepPc = 0;
    uintptr_t pcPtr = regs_->GetFp() + pcSlotOff;
    memory_->Read<uintptr_t>(pcPtr, &fpStepPc, false);
    // if the pc which is step by fp is duplicated with the current frame, update fp val to next frame
    if (regs_->GetPc() == fpStepPc) {
        auto fp = regs_->GetFp();
        uintptr_t nextFp = 0;
        if (!memory_->Read<uintptr_t>(fp, &nextFp, false)) {
            return;
        }
        // 只沿貌似合法的 fp 链前进。[fp] 处可能是任意数据(例如经 LR 兜底
        // 到达本机帧时读到的是 Java 对象指针);盲目采纳会污染 fp、毁掉
        // 后续 FpStep。FpStep 自身要求链单调增长,这里沿用同一判据。
        if (nextFp > fp) {
            regs_->SetFp(nextFp);
        }
    }
#endif
}

bool Unwinder::Impl::StepByScan(uintptr_t sp, uintptr_t currentPc)
{
#if defined(__aarch64__) || defined(__x86_64__)
    if (memory_ == nullptr || maps_ == nullptr || sp == 0) {
        return false;
    }
    // 终极兜底栈扫描(AOSP ScanFrame 风格),只在其余策略全部失败时到达:
    // pc 无回溯信息(第三方库如 libttffmpeg.so / libsscronet.so 的大部分
    // .text 不带 .eh_frame)、LR 已失效或无操作、fp 链不可用
    // (-fomit-frame-pointer)。从 sp 向上扫栈,采纳第一个貌似保存返回地址
    // 的字:4 字节对齐且指向可执行映射。调用者的保存 RA 通常离 sp 只有
    // 几十个字,512 字节窗口足够。
    for (size_t i = 0; i < SCAN_WINDOW_WORDS; i++) {
        uintptr_t addr = sp + i * sizeof(uintptr_t);
        uintptr_t val = 0;
        if (!memory_->ReadMem(addr, &val)) {
            break; // 已离开可读栈区
        }
        uintptr_t candidate = StripPac(val, pacMask_);
        // aarch64:指令 4 字节对齐。x86_64:无对齐要求——掩码只是
        // 过滤掉大概率不是返回地址的值。
        if ((candidate & 0x3) != 0) {
            continue;
        }
        if (candidate == currentPc) {
            continue; // 无进展
        }
        std::shared_ptr<DfxMap> map;
        if (!maps_->FindMapByAddr(candidate, map) || map == nullptr || !map->IsMapExec()) {
            continue;
        }
        regs_->SetPc(candidate);
        regs_->SetSp(addr + sizeof(uintptr_t));
        DFXLOGU("StepByScan: adopted pc: %{private}p from slot %{private}p (sp: %{private}p)",
            reinterpret_cast<void *>(candidate), reinterpret_cast<void *>(addr), reinterpret_cast<void *>(sp));
        return true;
    }
    DFXLOGU("StepByScan: no candidate in [%{private}p, %{private}p)",
        reinterpret_cast<void *>(sp), reinterpret_cast<void *>(sp + SCAN_WINDOW_WORDS * sizeof(uintptr_t)));
#endif
    return false;
}

void Unwinder::Impl::UpdateRegsState(
    StepFrame& frame, void* ctx, bool& unwinderResult, std::shared_ptr<RegLocState>& rs,
    const std::shared_ptr<DfxMap>& frameMap)
{
    SetLocalStackCheck(ctx, true);
#if defined(__aarch64__)
    // Apply 前保存 x22(dex_pc)与 x25(xREFS):即使 Apply 返回 false,
    // Flush 也可能已改写它们;StepNterp 需要原始现场值定位 nterp 帧。
    uintptr_t origDexPc = (*regs_)[22]; // 22: x22 (xPC) on ARM64
    // 优先用采样时刻的 x25(不受 CFI 链污染)
    uintptr_t origXRefs = (sampleXRefs_ != 0) ? sampleXRefs_ : (*regs_)[25];
#endif
    MAYBE_UNUSED bool noCallerInCfi = false;
    // 本帧完全没有回溯表时为 true(下方 else 分支)。LR 兜底只允许用于
    // 这类帧,且排在 StepNterp/TryJitStep 之后:匿名可执行区的 pc(如
    // ART JIT 缓存内)必须先做 JIT 步进——那是唯一能同时正确恢复 sp/fp
    // 的兜底。LR 兜底无法更新 sp/fp,下一帧只能拿陈旧 sp 求值,产出垃圾。
    MAYBE_UNUSED bool noUnwindTable = !unwinderResult;
    if (unwinderResult) {
#if defined(__arm__) || defined(__aarch64__)
    uintptr_t lr = *(regs_->GetReg(REG_LR));
#endif
    uint16_t applyErrCode = 0;
    unwinderResult = Apply(regs_, rs, applyErrCode);
    // CFI 明确声明本帧没有调用者(返回地址寄存器上为 DW_CFA_undefined;
    // 典型于 noreturn/最外层帧)。libunwindstack 到此结束回溯。此处按
    // 栈底处理:若继续落入 TryJitStep/FpStep,会拿陈旧 fp 伪造帧(实测
    // 为 RETURN_ADDRESS_UNDEFINED 失败后出现垃圾 libicu_jni 帧,随后
    // fp 模式卡死循环)。下方仍允许 StepNterp:它自带校验(libart 映射 +
    // nterp 被调用者保存帧布局)。
    if (!unwinderResult && applyErrCode == UNW_ERROR_RETURN_ADDRESS_UNDEFINED) {
        noCallerInCfi = true;
    }
#if defined(__arm__) || defined(__aarch64__)
    if (!unwinderResult && enableLrFallback_ && (frames_.size() == 1) &&
        StripPac(lr, pacMask_) != StripPac(regs_->GetPc(), pacMask_)) {
        regs_->SetPc(lr);
        lastLrFallbackPc_ = StripPac(lr, pacMask_);
        unwinderResult = true;
        if (pid_ != UNWIND_TYPE_CUSTOMIZE) {
            DFXLOGW("Failed to apply first frame, lr fallback");
        }
    }
#endif
    } else {
        // 本帧没有回溯表。LR 兜底原来在这里、StepNterp/TryJitStep 之前
        // 执行;现已移到它们之后(见下),让 JIT 缓存帧先以正确的 sp/fp
        // 完成步进。
    }
    regs_->SetPc(StripPac(regs_->GetPc(), pacMask_));

#if defined(__aarch64__)
    if (!unwinderResult) {
        unwinderResult = StepNterp(frame.pc, frame.sp, origDexPc, origXRefs);
        if (unwinderResult) {
            isFpStep_ = false;
        }
    }
    if (!unwinderResult && !noCallerInCfi) {
        unwinderResult = TryJitStep(frame.pc, ctx);
        if (unwinderResult && !isFpStep_) {
            if (pid_ != UNWIND_TYPE_CUSTOMIZE) {
                DFXLOGU("First enter jit step, pc: %{private}p", reinterpret_cast<void *>(frame.pc));
            }
            isFpStep_ = false;
        }
    }
#endif
    // LR 兜底,FpStep 之前的最后手段(只用于无回溯表的帧;见
    // noUnwindTable)。fp 步进模式下 DWARF 不再运行,LR 冻结在进入 fp
    // 模式时的取值——用它只会反复把 pc 拉回那个陈旧 LR,与 FpStep 构成
    // 二帧循环,故 fp 模式下跳过。
    // LR 只在 DWARF Apply 成功时经 x30 规则刷新;FpStep 与 StepNterp 不
    // 碰它。对已消费过的 LR 再兜底毫无进展(pc 只会在 lr 与 lr-4 之间经
    // DoPcAdjust 振荡,同时绕过 SetPcFromReturnAddress 内部的 pc==lr 守
    // 卫),故每个 LR 值每次回溯至多消费一次。目标等于当前 pc 时同样拒绝:
    // 本帧 pc 通常正来自 Apply 刚恢复进 LR 的那个 RA 栈槽,PAC 加 ±4 的
    // DoPcAdjust 会让 SetPcFromReturnAddress 里的 pc==lr 守卫看不出这一
    // 相等;这种兜底只会复现同一帧,最终止步于 UnwindFrame 的重复帧检查。
    // 被拒绝的兜底保持 unwinderResult 为 false,FpStep 仍有机会接着跑。
    if (!unwinderResult && noUnwindTable && enableLrFallback_ && !isResetFrames_ && !isFpStep_) {
        uintptr_t pcBefore = regs_->GetPc();
        if (regs_->SetPcFromReturnAddress(memory_)) {
            uintptr_t fallbackPc = StripPac(regs_->GetPc(), pacMask_);
            if (fallbackPc != lastLrFallbackPc_ && fallbackPc != StripPac(pcBefore, pacMask_)) {
                lastLrFallbackPc_ = fallbackPc;
                unwinderResult = true;
                StepToNextFpIfNeed();
                DFXLOGU("LR fallback: old_pc=%{private}p -> new_pc=%{private}p",
                    reinterpret_cast<void *>(frame.pc), reinterpret_cast<void *>(regs_->GetPc()));
            } else {
                // 陈旧或无操作的 LR:恢复 pc,不宣称成功。
                regs_->SetPc(pcBefore);
                DFXLOGU("LR fallback skipped: stale or no-op lr %{private}p", reinterpret_cast<void *>(fallbackPc));
            }
        }
    }
#if defined(__aarch64__) || defined(__x86_64__)
    // 尝试 fp。vDSO 类映射跳过(IsVdsoMap 覆盖 [vdso] 与 [shmm]):这类
    // 伪映射由 VdsoElfFactory 按内存 ELF 解析,若解析不出回溯表,帧指针
    // 寄存器里就不会是可靠的帧指针(其代码是内核/共享内存桩,不是按帧
    // 指针编译的用户代码)。在那里追 [fp] 会拿栈残留伪造垃圾帧,且因步进
    // 被标记成功,还会挡住下方有界的 StepByScan 兜底。ART JIT 缓存
    // (fp==0) 本来就会让 FpStep 快速失败,不受影响。
    if (!unwinderResult && !noCallerInCfi &&
        !(frameMap != nullptr && frameMap->IsVdsoMap())) {
        unwinderResult = FpStep(frame.fp, frame.pc, ctx);
        if (unwinderResult && !isFpStep_) {
            if (pid_ != UNWIND_TYPE_CUSTOMIZE) {
                static std::atomic<uint64_t> fpStepCnt {0};
                if ((fpStepCnt.fetch_add(1) % 500) == 0) {
                    DFXLOGI("First enter fp step, pc: %{private}p, total: %{public}" PRIx64 "",
                        reinterpret_cast<void *>(frame.pc), fpStepCnt.load());
                }
            }
            isFpStep_ = true;
        } else if (!unwinderResult && isFpStep_) {
            // fp 链已断(例如下一个 fp 不再增长)。退出 fp 模式让下一帧
            // 重试 DWARF:fp 模式下 StepInner 完全跳过 ParseUnwindTable,
            // 链断后回溯会卡死无解。若 DWARF(及其他兜底)也失败,
            // UnwindFrame 的重复帧守卫会终止回溯。
            isFpStep_ = false;
        }
    }
    if (!unwinderResult && enableScanStep_ && scanUsedCount_ < MAX_SCAN_STEPS) {
        // 栈扫描,所有策略失败后的最终兜底。每次回溯受 MAX_SCAN_STEPS
        // 限制;扫描帧只是尽力猜测(栈残留可能导致跳帧),故默认关闭、
        // 需显式开启。
        scanUsedCount_++;
        unwinderResult = StepByScan(frame.sp, StripPac(regs_->GetPc(), pacMask_));
        if (unwinderResult) {
            isFpStep_ = false;
        }
    }
#endif
    frame.pc = regs_->GetPc();
    frame.sp = regs_->GetSp();
    frame.fp = regs_->GetFp();
}

bool Unwinder::Impl::CheckFrameValid(const StepFrame& frame, const std::shared_ptr<DfxMap>& map, uintptr_t prevSp)
{
    DFXLOGU("-pc: %{public}p, sp: %{public}p, fp: %{public}p, prevSp: %{public}p", reinterpret_cast<void *>(frame.pc),
        reinterpret_cast<void *>(frame.sp), reinterpret_cast<void *>(frame.fp), reinterpret_cast<void *>(prevSp));
    if (!isFpStep_ && (map != nullptr) && (!map->IsVdsoMap()) && (frame.sp < prevSp)) {
        DFXLOGU("Illegal sp value");
        lastErrorData_.SetAddrAndCode(frame.pc, UNW_ERROR_ILLEGAL_VALUE);
        return false;
    }
    if (frame.pc == 0) {
        return false;
    }
    return true;
}

bool Unwinder::Impl::GetCrashLastFrame(StepFrame& frame)
{
    if (isCrash_ && !isFpStep_ && !frames_.empty()) {
        auto &lastFrame = frames_.back();
        frame.pc = lastFrame.pc;
        frame.sp = lastFrame.sp;
        frame.fp = lastFrame.fp;
        frame.isJsFrame = lastFrame.isJsFrame;
        DFXLOGW("Dwarf unwind failed to find map, try fp unwind again");
        return true;
    }
    return false;
}

void Unwinder::Impl::UpdateCache(uintptr_t pc, bool hasRegLocState, const std::shared_ptr<RegLocState>& rs,
    const std::shared_ptr<DfxMap>& map)
{
    if (hasRegLocState && enableCache_) {
        // 给缓存设上限:跨样本的 pc 几乎全不重复(hiperf 后处理),整表
        // 清空几乎无损失。约 64K 项 ≈ 3-4MB(含节点开销,
        // sizeof(StepCache)=16B)。
        constexpr size_t kMaxStepCacheEntries = 65536;
        if (stepCache_.size() >= kMaxStepCacheEntries) {
            stepCache_.clear();
        }
        StepCache cache;
        cache.map = map;
        cache.rs = rs;
        stepCache_.emplace(pc, cache);
    }
}

bool Unwinder::Impl::StepInner(const bool isSigFrame, StepFrame& frame, void *ctx)
{
    if ((regs_ == nullptr) || (!CheckAndReset(ctx))) {
        DFXLOGE("params is nullptr");
        return false;
    }
    // AOSP16 风格:若上一次 DWARF Step 设置了 dex_pc(经 libart.so 中
    // nterp_helper 的 CFI 里的 DEX1 魔数标记),在加入当前本机帧之前先
    // 注入虚拟 DEX 帧。dex_pc 指向已映射的 DEX/vdex/apk/jar 文件,代表
    // 解释执行 Java 方法的当前 PC。必须先于下方任何 AddFrame 调用执行。
    InjectDexFrameFromDwarf();
    SetLocalStackCheck(ctx, false);
    DFXLOGU("+pc: %{public}p, sp: %{public}p, fp: %{public}p", reinterpret_cast<void *>(frame.pc),
        reinterpret_cast<void *>(frame.sp), reinterpret_cast<void *>(frame.fp));
    uintptr_t prevPc = frame.pc;
    uintptr_t prevSp = frame.sp;
    bool hasRegLocState = false;
    std::shared_ptr<RegLocState> rs = nullptr;
    std::shared_ptr<DfxMap> map = nullptr;
    do {
        // 1. find cache rs
        hasRegLocState = FindCache(frame.pc, map, rs);
        if (hasRegLocState) {
            AddFrame(frame, map);
            break;
        }

        // 2. find map and process frame
        if (!AddFrameMap(frame, map)) {
            DFXLOGU("StepInner: AddFrameMap failed, pc=0x%{public}" PRIx64 ", sp=0x%{public}" PRIx64
                ", dexPc=0x%{public}" PRIx64 ", seen=%{public}d",
                (uint64_t)frame.pc, (uint64_t)frame.sp, (uint64_t)regs_->DexPc(), (int)regs_->DexPcSeen());
            if (!GetCrashLastFrame(frame)) {
                return false;
            }
            break;
        }
        if (isSigFrame) {
            return true;
        }
        bool stopUnwind = false;
        bool res = StepV8Frame(frame, map, stopUnwind);
        if (stopUnwind) {
            return res;
        } else if (!res) {
            break;
        }
        bool processFrameResult = UnwindArkFrame(frame, map, stopUnwind);
        if (stopUnwind) {
            return processFrameResult;
        } else if (!processFrameResult) {
            break;
        }
        if (isFpStep_) {
            if (enableFpCheckMapExec_ && (map != nullptr && !map->IsMapExec())) {
                DFXLOGE("Fp step check map is not exec");
                return false;
            }
            break;
        }
        // 3. find unwind table and entry, parse instructions and get cache rs
        hasRegLocState = ParseUnwindTable(frame.pc, rs);
        // 4. update rs cache
        UpdateCache(frame.pc, hasRegLocState, rs, map);
    } while (false);

    // 5. update regs and regs state
    UpdateRegsState(frame, ctx, hasRegLocState, rs, map);
    if (!CheckFrameValid(frame, map, prevSp)) {
        return false;
    }
    // hasRegLocState 为 true 表示 DWARF 成功。
    // UpdateRegsState 在 DWARF 失败时也可能经 LR 兜底或 JIT 步进成功。
    // 那种情况下 frame.pc/sp/fp 已更新为下一帧的值,应返回 true 继续
    // 回溯。
    if (hasRegLocState || frame.pc != prevPc) {
        return true;
    }
    return false;
}

bool Unwinder::Impl::Apply(std::shared_ptr<DfxRegs> regs, std::shared_ptr<RegLocState> rs, uint16_t& errCode)
{
    errCode = 0;
    if (rs == nullptr || regs == nullptr) {
        errCode = UNW_ERROR_INVALID_REGS;
        return false;
    }

    uintptr_t prevPc = regs->GetPc();
    uintptr_t prevSp = regs->GetSp();
    bool ret = DfxInstructions::Apply(memory_, *(regs.get()), *(rs.get()), errCode);
    // DWARF Apply 成功后不要再校验新 SP 可读:返回地址寄存器可能正确,
    // 而 CFA 推出的 SP 不是可用栈值(nterp_helper 的 CFA 由存活的 xREFS
    // 寄存器计算)。坏 SP 自会终止回溯:后续经它的读取都会失败,且下一帧
    // 会按自己的 CFI 重算自己的 SP。
    if (StripPac(regs->GetPc(), pacMask_) == prevPc && regs->GetSp() == prevSp) {
        DFXLOGU("Apply: repeated frame, pc=0x%{public}" PRIx64 ", sp=0x%{public}" PRIx64
            "", (uint64_t)prevPc, (uint64_t)prevSp);
        errCode = UNW_ERROR_REPEATED_FRAME;
        ret = false;
    }
    if (ret) {
        DFXLOGU("Apply: success, prevPc=0x%{public}" PRIx64 " -> newPc=0x%{public}" PRIx64
            ", prevSp=0x%{public}" PRIx64 " -> newSp=0x%{public}" PRIx64
            ", dexPc=0x%{public}" PRIx64 ", seen=%{public}d",
            (uint64_t)prevPc, (uint64_t)regs->GetPc(), (uint64_t)prevSp, (uint64_t)regs->GetSp(),
            (uint64_t)regs->DexPc(), (int)regs->DexPcSeen());
    }
    if (!ret) {
        lastErrorData_.SetCode(errCode);
        DFXLOGU("Failed to apply reg state, errCode: %{public}d, prevPc=0x%{public}" PRIx64
            ", prevSp=0x%{public}" PRIx64 ", newPc=0x%{public}" PRIx64 ", newSp=0x%{public}" PRIx64 "",
            static_cast<int>(errCode), (uint64_t)prevPc, (uint64_t)prevSp,
            (uint64_t)regs->GetPc(), (uint64_t)regs->GetSp());
    }
    return ret;
}

void Unwinder::Impl::DoPcAdjust(uintptr_t& pc)
{
    if (pc <= 0x4) {
        return;
    }
    uintptr_t sz = 0x4;
#if defined(__arm__)
    if ((pc & 0x1) && (memory_ != nullptr)) {
        uintptr_t val;
        if (pc < 0x5 || !(memory_->ReadMem(pc - 0x5, &val)) ||
            (val & 0xe000f000) != 0xe000f000) {
            sz = 0x2;
        }
    }
#elif defined(__x86_64__)
    sz = 0x1;
#endif
    pc -= sz;
}

const std::vector<DfxFrame>& Unwinder::Impl::GetFrames()
{
    if (enableFillFrames_) {
        FillFrames(frames_);
    }
    return frames_;
}

void Unwinder::Impl::AddFrame(const StepFrame& frame, std::shared_ptr<DfxMap> map)
{
#if defined(ENABLE_MIXSTACK)
    if (ignoreMixstack_ && frame.isJsFrame) {
        return;
    }
#endif
    pcs_.emplace_back(frame.pc);
    DfxFrame dfxFrame;
    if (map != nullptr && map->IsArkWebJsExecutable()) { // Arkwebjs frames require setting the frametype in advance
        dfxFrame.isJsFrame = true;
        dfxFrame.frameType = FrameType::ARKWEB_JS_FRAME;
    } else {
        dfxFrame.isJsFrame = frame.isJsFrame;
        dfxFrame.frameType = frame.frameType;
    }
    dfxFrame.index = frames_.size();
    dfxFrame.fp = static_cast<uint64_t>(frame.fp);
    dfxFrame.pc = static_cast<uint64_t>(frame.pc);
    dfxFrame.sp = static_cast<uint64_t>(frame.sp);
    dfxFrame.map = map;
    frames_.emplace_back(dfxFrame);
}

void Unwinder::Impl::AddFrame(DfxFrame& frame)
{
    frames_.emplace_back(frame);
}

bool Unwinder::AccessMem(void* memory, uintptr_t addr, uintptr_t *val)
{
    return reinterpret_cast<DfxMemory*>(memory)->ReadMem(addr, val);
}

void Unwinder::FillLocalFrames(std::vector<DfxFrame>& frames)
{
    if (frames.empty()) {
        return;
    }
    auto it = frames.begin();
    while (it != frames.end()) {
        if (dl_iterate_phdr(Unwinder::Impl::DlPhdrCallback, &(*it)) != 1) {
            // clean up frames after first invalid frame
            frames.erase(it, frames.end());
            break;
        }
        it++;
    }
}

void Unwinder::Impl::FillFrames(std::vector<DfxFrame>& frames)
{
    for (size_t i = 0; i < frames.size(); ++i) {
        auto& frame = frames[i];
        if (frame.frameType == FrameType::JS_FRAME || frame.frameType == FrameType::STATIC_JS_FRAME) {
#if defined(ENABLE_MIXSTACK)
            FillJsFrame(frame);
#endif
        } else if (frame.frameType == FrameType::ARKWEB_JS_FRAME) {
            FillArkwebJsFrame(frame);
        } else if (frame.frameType == FrameType::DEX_FRAME) {
            FillDexFrame(frame);
        } else {
            FillFrame(frame, enableParseNativeSymbol_);
        }
    }
}

void Unwinder::Impl::ParseFrameSymbol(DfxFrame& frame)
{
    if (frame.map == nullptr) {
        return;
    }
    pid_t pid = pid_ <= 0 ? getpid() : pid_;
    auto elf = frame.map->GetElf(pid);
    if (elf == nullptr) {
        TryJitSymbolLookup(frame);
        return;
    }
    if (!DfxSymbols::GetFuncNameAndOffsetByPc(frame.relPc, elf, frame.funcName, frame.funcOffset)) {
        TryJitSymbolLookup(frame);
        DFXLOGU("Failed to get symbol, relPc: 0x%{public}" PRIx64 ", pc: 0x%{public}" PRIx64 ", mapName: %{public}s",
            frame.relPc, frame.pc, frame.mapName.c_str());
    }
    frame.parseSymbolState.SetParseSymbolState(true);
}

void Unwinder::Impl::TryJitSymbolLookup(DfxFrame& frame)
{
    // 符号化兜底:map 拿不到 elf 时(匿名可执行区)查 JIT 注册表。
    // 见 IsFileBackedMapName:有名文件映射里的 pc 不可能是 JIT 代码,
    // JIT 符号注册表里也不可能有它,直接跳过。
    if (frame.map != nullptr && IsFileBackedMapName(frame.map->name)) {
        return;
    }
    auto& jitDebug = jitDebug_;
    jitDebug.SetMemory(memory_);
    jitDebug.SetMaps(maps_);
    jitDebug.SetPid(pid_);
#if defined(__aarch64__)
    jitDebug.SetArch(ARCH_ARM64);
#elif defined(__arm__)
    jitDebug.SetArch(ARCH_ARM);
#elif defined(__x86_64__)
    jitDebug.SetArch(ARCH_X86_64);
#elif defined(__i386__)
    jitDebug.SetArch(ARCH_X86);
#elif defined(__riscv) && defined(__riscv64)
    jitDebug.SetArch(ARCH_RISCV64);
#else
    return;
#endif

    JitSymbolInfo info;
    if (!jitDebug.GetJitSymbolInfo(frame.pc, info)) {
        DFXLOGU("No JIT ELF found for pc: 0x%{public}" PRIx64, frame.pc);
        return;
    }

    if (info.elf == nullptr || !info.elf->IsValid()) {
        return;
    }

    uint64_t relPc = frame.pc;
    if (info.loadBias != 0 && info.loadBias != static_cast<uint64_t>(-1)) {
        relPc = frame.pc - info.loadBias;
    } else {
        relPc = frame.pc - info.startPc;
    }

    DFXLOGU("JIT lookup: pc=0x%{public}" PRIx64 ", loadBias=0x%{public}" PRIx64
        ", startPc=0x%{public}" PRIx64 ", endPc=0x%{public}" PRIx64 ", relPc=0x%{public}" PRIx64,
        frame.pc, info.loadBias, info.startPc, info.endPc, relPc);

    if (!DfxSymbols::GetFuncNameAndOffsetByPc(relPc, info.elf, frame.funcName, frame.funcOffset)) {
        DFXLOGU("Failed to get JIT symbol, relPc: 0x%{public}" PRIx64 ", pc: 0x%{public}" PRIx64,
            relPc, frame.pc);
        return;
    }

    DFXLOGU("Found JIT symbol: funcName: %{public}s, relPc: 0x%{public}" PRIx64,
        frame.funcName.c_str(), relPc);
    frame.parseSymbolState.SetParseSymbolState(true);
}

bool Unwinder::Impl::TryJitStep(uintptr_t pc, void *ctx)
{
    DFX_TRACE_SCOPED_DLSYM("TryJitStep:%p", reinterpret_cast<void *>(pc));
    // JIT 步进:pc 落在 JIT 代码里时,取 JIT ELF 的回溯表走一步。
    // JIT 编译代码从不存在于有名文件映射(见 IsFileBackedMapName),
    // 这类 pc 先行跳过注册表扫描,不做任何工作。
    if (maps_ != nullptr) {
        std::shared_ptr<DfxMap> map;
        if (memory_->GetMapByPc(pc, map) == UNW_ERROR_NONE && map != nullptr &&
            IsFileBackedMapName(map->name)) {
            return false;
        }
    }

    auto& jitDebug = jitDebug_;
    jitDebug.SetMemory(memory_);
    jitDebug.SetMaps(maps_);
    jitDebug.SetPid(pid_);
#if defined(__aarch64__)
    jitDebug.SetArch(ARCH_ARM64);
#elif defined(__arm__)
    jitDebug.SetArch(ARCH_ARM);
#elif defined(__x86_64__)
    jitDebug.SetArch(ARCH_X86_64);
#elif defined(__i386__)
    jitDebug.SetArch(ARCH_X86);
#elif defined(__riscv) && defined(__riscv64)
    jitDebug.SetArch(ARCH_RISCV64);
#else
    return false;
#endif

    std::shared_ptr<DfxElf> jitElf;
    uint64_t loadBias = 0;
    if (!jitDebug.FindJitElf(pc, jitElf, loadBias)) {
        DFXLOGU("TryJitStep: No JIT ELF found for pc: 0x%{public}" PRIx64 "", (uint64_t)pc);
        return false;
    }

    if (jitElf == nullptr || !jitElf->IsValid()) {
        DFXLOGU("TryJitStep: JIT ELF invalid for pc: 0x%{public}" PRIx64 "", (uint64_t)pc);
        return false;
    }

    DFXLOGU("TryJitStep: pc=0x%{public}" PRIx64 ", loadBias=0x%{public}" PRIx64 ", hasRuntime=%{public}d, "
        "runtime=[0x%{public}" PRIx64 ", 0x%{public}" PRIx64 ")",
        (uint64_t)pc, loadBias, jitElf->HasRuntimeRange(),
        jitElf->GetRuntimeStart(), jitElf->GetRuntimeEnd());

    UnwindTableInfo uti;
    std::shared_ptr<DfxMap> tmpMap = std::make_shared<DfxMap>();
    if (jitElf->HasRuntimeRange()) {
        tmpMap->begin = 0;
        tmpMap->end = 0;
    } else {
        tmpMap->begin = jitElf->GetStartVaddr() + loadBias;
        tmpMap->end = jitElf->GetEndVaddr() + loadBias;
    }
    tmpMap->offset = 0;
    tmpMap->name = "[jit]";

    int utiRet = jitElf->FindUnwindTableInfo(pc, tmpMap, uti);
    if (utiRet != UNW_ERROR_NONE) {
        DFXLOGU("TryJitStep: Failed to find unwind table in JIT ELF, ret: %{public}d, pc: 0x%{public}" PRIx64 "",
            utiRet, (uint64_t)pc);
        return false;
    }

    std::shared_ptr<RegLocState> rs = std::make_shared<RegLocState>();
    if (!unwindEntryParser_->Step(pc, uti, rs)) {
        DFXLOGU("TryJitStep: Failed to step JIT unwind entry, pc: 0x%{public}" PRIx64 "", (uint64_t)pc);
        return false;
    }

    bool ret = false;
    uint16_t jitApplyErrCode = 0;
    ret = Apply(regs_, rs, jitApplyErrCode);
    if (ret) {
        regs_->SetPc(StripPac(regs_->GetPc(), pacMask_));
        DFXLOGU("TryJitStep: success, new pc: 0x%{public}" PRIx64 "", (uint64_t)regs_->GetPc());
    } else {
        DFXLOGU("TryJitStep: Apply failed, pc: 0x%{public}" PRIx64 "", (uint64_t)pc);
    }
    return ret;
}

bool Unwinder::Impl::StepNterp(uintptr_t pc, uintptr_t origSp, uintptr_t origDexPc, uintptr_t origXRefs)
{
    DFX_TRACE_SCOPED_DLSYM("StepNterp:%p", reinterpret_cast<void *>(pc));
#if defined(__aarch64__)
    // 只处理 libart.so/libartd.so 内的 ARM64 nterp_helper /
    // art_quick_nterp_* 帧。用 origSp(Apply 污染之前的 SP),因为 Apply
    // 可能在返回 false 前已把 regs_->sp 设成坏 CFA 值;同理用保存下来的
    // x22/x25,因为 Apply 的 Flush 可能已把它们改写。
    if (maps_ == nullptr || memory_ == nullptr || regs_ == nullptr) {
        return false;
    }

    std::shared_ptr<DfxMap> map;
    if (memory_->GetMapByPc(pc, map) != UNW_ERROR_NONE || map == nullptr) {
        return false;
    }

    // 必须位于 libart.so / libartd.so。nterp_helper 是 libart.so 内的
    // ART 解释器入口。没有这道守卫,其他 .so 里被误判的帧可能被错当
    // 成 nterp。
    auto pos = map->name.rfind('/');
    std::string baseName = (pos == std::string::npos) ? map->name : map->name.substr(pos + 1);
    if (baseName != "libart.so" && baseName != "libartd.so") {
        return false;
    }

    // 不依赖 libart.so 符号表识别 nterp 帧。nterp_helper 是静态(未导出)
    // 符号,.dynsym 里没有;libart.so 发布版通常连 .symtab 也剥掉。因此
    // 符号名匹配(GetFuncNameAndOffsetByPc)在生产版 libart.so 上必然
    // 失败,ART 解释器穿越就此断链。
    //
    // 两个信号可识别 nterp 帧,按优先级:
    //   1) regs_->DexPcSeen():nterp_helper 的 DWARF CFI 在某寄存器规则上
    //      使用 AOSP16 DEX1 魔数(DW_OP_const4u 'D' 'E' 'X' '1' DW_OP_drop,
    //      val_expression 于 x0,读 x22)。魔数一命中 DfxInstructions::
    //      Apply 就置起该标志,与 dex_pc 求值结果无关。DEX1 魔数只有 ART
    //      为 nterp_helper 发出的 CFI 才有,所以仅凭该标志即可证明是
    //      nterp 帧——即使 dex_pc 求值为 0/未映射(例如线程到达系统调用
    //      前,val_expression 读的存活 x22 已被中间编译帧/JNI 帧改写为
    //      0)。旧判据(DexPc() != 0)把"魔数命中"与"数值非零"混为一谈,
    //      x22 碰巧为 0 时回溯就止步于 nterp_helper。DexPcSeen() 能存活,
    //      是因为它在 CFA flush 之前、Apply 可能因返回地址寄存器
    //      undefined 而失败之前就已置位。只要 DWARF 存在,这是最可靠的
    //      信号。
    //   2) x22 物理寄存器(origDexPc):nterp 正在解释执行时的活 dex_pc。
    //      用于完全没有 DEX1 CFI(旧版 libart.so)或任何 DWARF 路径尚未
    //      运行时。此路径仍要求该值映射到 DEX 区域,否则 libart.so 里的
    //      非 nterp 帧可能被误判。
    //
    // dex_pc 有效性只控制 DEX 帧注入(对应 Unwinder::FillInDexFrame 语义)。
    // 一旦判定为 nterp 帧,下方被调用者保存帧恢复总会执行;dex_pc 有假
    // 只是不注入 DEX 帧——不会叫停回溯。
    bool dexPcValid = false;
    std::string dexMapName;
    std::shared_ptr<DfxMap> dexMap;
    uintptr_t effectiveDexPc = regs_->DexPc();
    if (effectiveDexPc == 0) {
        effectiveDexPc = origDexPc;
    }
    if (effectiveDexPc != 0) {
        if (maps_->FindMapByAddr(static_cast<uintptr_t>(effectiveDexPc), dexMap) && dexMap != nullptr) {
            const std::string& n = dexMap->name;
            dexMapName = n;
            // 常见 DEX 容器。.vdex 用子串匹配:dex2oat 会先产出
            // "base.vdex.<hash>.tmp" 这类临时文件再改名为正式的
            // "base.vdex",严格后缀匹配 ".vdex.tmp" 会漏掉正式形态。
            dexPcValid = n.find(".vdex") != std::string::npos ||
                       EndsWith(n, ".dex") || EndsWith(n, ".apk") ||
                       StartsWith(n, "[anon:dalvik") ||
                       // 抽取到匿名映射的 DEX 名字为空;要求页面可执行,
                       // 避免匹配到任意读写的匿名区域。
                       (n.empty() && dexMap->IsMapExec());
        }
    }
    // DEX1 魔数命中 => 必是 nterp 帧(该魔数只有 ART 为 nterp_helper 的
    // CFI 才发),即使 dex_pc 为 0 或未映射(如线程到达系统调用前,活的
    // x22 已被中间编译帧/JNI 帧改写为 0)。DexPcSeen() 独立于数值记录
    // 魔数命中,所以仍进入被调用者保存帧恢复,读 [saved_sp+88] 处保存的
    // x22。此处若用 DexPc()!=0(旧判据)会漏掉 x22==0 的情形,回溯止步
    // 于 nterp_helper。否则退回要求 dex_pc 有效映射到 DEX 区(最初信号),
    // 避免把 libart.so 里其他帧(如 GC、JIT)误判为 nterp。
    bool isNterp = regs_->DexPcSeen() || dexPcValid;
    if (!isNterp) {
        DFXLOGU("StepNterp: not nterp, pc=0x%{public}" PRIx64 ", dexPc=0x%{public}" PRIx64
            " (seen=%{public}d, regs:%{public}" PRIx64 ", x22:%{public}" PRIx64 "), dexMap=%{public}s",
            (uint64_t)pc, (uint64_t)effectiveDexPc, (int)regs_->DexPcSeen(),
            (uint64_t)regs_->DexPc(), (uint64_t)origDexPc, dexMapName.c_str());
        return false;
    }
    // 消费掉 DWARF 伪寄存器,防止下一次 StepInner 迭代里
    // InjectDexFrameFromDwarf 为同一 dex_pc 重复注入 DEX 帧。
    // 我们自己在下方注入。
    regs_->ClearDexPc();

    DFXLOGU("StepNterp: hit nterp frame, pc=0x%{public}" PRIx64 ", dexPc=0x%{public}" PRIx64
        " (valid=%{public}d), dexMap=%{public}s, origSp=0x%{public}" PRIx64 "",
        (uint64_t)pc, (uint64_t)effectiveDexPc, (int)dexPcValid, dexMapName.c_str(), (uint64_t)origSp);

    // ARM64 nterp 寄存器分配(出自 art/runtime/interpreter/mterp/arm64ng/
    // main.S):
    //   x22 (xPC)   = 解释器程序计数器(DEX PC,已映射 DEX 内的绝对地址)
    //   x25 (xREFS) = dex 寄存器对象引用区基址
    //
    // ARM64 nterp 被调用者保存帧布局(main.S 的 SAVE_ALL_CALLEE_SAVES /
    // RESTORE_ALL_CALLEE_SAVES):
    //   [xREFS - 8]        = 保存的 SP(被调用者保存区基址)
    //   [saved_sp + 0..56] = d8..d15(浮点被调用者保存)
    //   [saved_sp + 64]    = x19(有保存,nterp 不恢复)
    //   [saved_sp + 72]    = x20(有保存,nterp 不恢复)
    //   [saved_sp + 80]    = x21(有保存,nterp 不恢复)
    //   [saved_sp + 88]    = x22(xPC / DEX PC)   <-- 保存的 DEX PC 在此
    //   [saved_sp + 96]    = x23
    //   [saved_sp + 104]   = x24
    //   [saved_sp + 112]   = x25 (xREFS)
    //   [saved_sp + 120]   = x26
    //   [saved_sp + 128]   = x27
    //   [saved_sp + 136]   = x28
    //   [saved_sp + 144]   = x29 (FP)
    //   [saved_sp + 152]   = lr(返回本机调用者的地址)
    //   溢出槽到 +160 结束;帧大小 CALLEE_SAVES_SIZE = 176(顶部 16 字节
    //   是留白):
    //   调用者 SP          = saved_sp + 176
    //
    // nterp 正在解释执行时,活 DEX PC 在寄存器 x22。nterp_helper 调出至
    // 编译/OAT/JNI 代码后,捕获到的 x22 可能是某个内层帧的函数中值,
    // DWARF DEX1 魔数因此可能求出假 dex_pc。真正的 DEX PC 在调出前已
    // 溢出到 [saved_sp + 88],从那里恢复。先为解释执行的 Java 方法注入
    // 虚拟 DEX 帧,再把 regs 设到本机调用者(lr / 调用者 SP)。
    uintptr_t xRefs = origXRefs; // Apply 前保存的 x25
    DFXLOGU("StepNterp: dexPc=0x%{public}" PRIx64 ", x25(xREFS)=0x%{public}" PRIx64 "",
        (uint64_t)effectiveDexPc, (uint64_t)xRefs);

    // 从 [xREFS - 8] 读保存的 SP,定位被调用者保存帧基址。
    uintptr_t savedSp = 0;
    if (xRefs != 0) {
        uintptr_t refsAddr = xRefs - 8; // 8: 保存的 SP 位于 [xREFS - 8]
        if (!memory_->Read<uintptr_t>(refsAddr, &savedSp, false)) {
            DFXLOGU("StepNterp: failed to read saved_sp at [xREFS-8]=0x%{public}" PRIx64 "", (uint64_t)refsAddr);
            return false;
        }
    }
    if (savedSp == 0) {
        DFXLOGU("StepNterp: saved_sp is 0, cannot locate callee-saves frame");
        return false;
    }

    // 从被调用者保存区读本机返回地址(lr)。
    uintptr_t nativeLr = 0;
    uintptr_t lrAddr = savedSp + 152; // 152: lr 在被调用者保存帧中的偏移
    if (!memory_->Read<uintptr_t>(lrAddr, &nativeLr, false)) {
        DFXLOGU("StepNterp: failed to read native lr at saved_sp+152=0x%{public}" PRIx64 "", (uint64_t)lrAddr);
        return false;
    }
    uintptr_t nativeSp = savedSp + 176; // 176: ARM64 的 CALLEE_SAVES_SIZE

    // 确定要注入的 DEX PC。DWARF DEX1 值映射到 DEX 区域时优先用之;否则
    // (x22 被中间编译帧/JNI 帧改写)退回 nterp 被调用者保存帧 [saved_sp
    // + 88] 处保存的 x22——nterp_helper 调出前溢出在那里的值。
    // 88:x22(xPC / DEX PC)在 nterp 被调用者保存帧中的偏移。
    uintptr_t dexPc = effectiveDexPc;
    if (!dexPcValid) {
        uintptr_t savedDexPc = 0;
        uintptr_t savedDexPcAddr = savedSp + 88;
        if (memory_->Read<uintptr_t>(savedDexPcAddr, &savedDexPc, false) && savedDexPc != 0) {
            std::shared_ptr<DfxMap> savedDexMap;
            if (maps_->FindMapByAddr(static_cast<uintptr_t>(savedDexPc), savedDexMap) && savedDexMap != nullptr) {
                const std::string& sn = savedDexMap->name;
                bool savedDexPcValid = sn.find(".vdex") != std::string::npos ||
                    EndsWith(sn, ".dex") || EndsWith(sn, ".apk") ||
                    StartsWith(sn, "[anon:dalvik") ||
                    (sn.empty() && savedDexMap->IsMapExec());
                if (savedDexPcValid) {
                    dexPc = savedDexPc;
                    dexMap = savedDexMap;
                    dexPcValid = true;
                    DFXLOGU("StepNterp: DEX1 dex_pc=0x%{public}" PRIx64
                        " unmapped, recovered saved x22=0x%{public}" PRIx64 " from "
                        "[saved_sp+88]=0x%{public}" PRIx64 ", map=%{public}s",
                        (uint64_t)effectiveDexPc, (uint64_t)savedDexPc, (uint64_t)savedDexPcAddr, sn.c_str());
                } else {
                    DFXLOGU("StepNterp: DEX1 dex_pc=0x%{public}" PRIx64 " unmapped, saved x22=0x%{public}" PRIx64
                        " maps to non-DEX '%{public}s', skip DEX frame",
                        (uint64_t)effectiveDexPc, (uint64_t)savedDexPc, sn.c_str());
                }
            } else {
                DFXLOGU("StepNterp: DEX1 dex_pc=0x%{public}" PRIx64 " unmapped, saved x22=0x%{public}" PRIx64
                    " not in any map, skip DEX frame",
                    (uint64_t)effectiveDexPc, (uint64_t)savedDexPc);
            }
        } else {
            DFXLOGU("StepNterp: DEX1 dex_pc=0x%{public}" PRIx64
                " unmapped, failed to read saved x22 at [saved_sp+88]=0x%{public}" PRIx64 ", skip DEX frame",
                (uint64_t)effectiveDexPc, (uint64_t)savedDexPcAddr);
        }
    }

    DFXLOGU("StepNterp: saved_sp=0x%{public}" PRIx64 ", native_lr=0x%{public}" PRIx64
        ", native_sp=0x%{public}" PRIx64 ", dex_pc=0x%{public}" PRIx64 "",
        (uint64_t)savedSp, (uint64_t)nativeLr, (uint64_t)nativeSp, (uint64_t)dexPc);

    // 为解释执行的 Java 方法注入虚拟 DEX 帧(对齐 AOSP FillInDexFrame)。
    // DEX 帧的 PC 是 dex_pc(x22),指向已映射的 DEX 文件(如 .apk/.vdex/
    // .odex 映射内部)。仅当 dex_pc 确实映射到 DEX 区域时注入,否则静默
    // 跳过(对齐 AOSP16 libunwindstack FillInDexFrame 的机会式行为,
    // 从不阻塞回溯)。
    if (dexPc != 0 && dexPcValid && dexMap != nullptr) {
        StepFrame dexFrame;
        dexFrame.pc = dexPc;
        dexFrame.sp = nativeSp;
        dexFrame.fp = 0;
        dexFrame.frameType = FrameType::DEX_FRAME;
        AddFrame(dexFrame, dexMap);
        DFXLOGU("StepNterp: injected DEX frame, pc=0x%{public}" PRIx64 ", map=%{public}s",
            (uint64_t)dexPc, dexMap->name.c_str());
    } else if (dexPc != 0) {
        DFXLOGU("StepNterp: dex_pc=0x%{public}" PRIx64 " not in DEX map, skip DEX frame (continue to native caller)",
            (uint64_t)dexPc);
    }

    // 把 regs 设为本机调用者,回溯得以穿过 nterp_helper 继续。
    if (nativeLr == 0) {
        DFXLOGU("StepNterp: native_lr is 0, stop unwinding");
        return false;
    }
    regs_->SetPc(StripPac(nativeLr, pacMask_));
    regs_->SetSp(nativeSp);
    DFXLOGU("StepNterp: set native pc=0x%{public}" PRIx64 ", sp=0x%{public}" PRIx64
        "", (uint64_t)nativeLr, (uint64_t)nativeSp);
    return true;
#else
    (void)pc;
    (void)origSp;
    (void)origDexPc;
    (void)origXRefs;
    return false;
#endif
}

void Unwinder::Impl::InjectDexFrameFromDwarf()
{
    // AOSP16 libunwindstack 风格:nterp_helper 的 DWARF CFI 用 DEX1 魔数
    // (DW_OP_const4u 'D' 'E' 'X' '1' DW_OP_drop)标记某寄存器时,
    // DfxInstructions::Apply 会把求值结果存入 regs_->DexPc()。这里消费
    // 它,注入一个 PC 为 dex_pc、指向已映射 DEX/vdex/apk/jar 文件的虚拟
    // DEX 帧(FrameType::DEX_FRAME)。运行于 StepInner 顶部、当前本机帧
    // 加入之前,得到的栈序为:
    //   ... nterp_helper 帧 | <注入的 DEX 帧> | 调用者帧 ...
    // (对齐 libunwindstack Unwinder::Unwind + FillInDexFrame)。
    if (regs_ == nullptr) {
        return;
    }
    uintptr_t dexPc = regs_->DexPc();
    bool seen = regs_->DexPcSeen();
    if (dexPc == 0 && !seen) {
        return;
    }
    // 无条件消费 DEX1 信号(同时清 dex_pc 与 seen 标志),它绝不能泄漏到
    // 此处之后,把后续某个 libart.so 帧误判成 nterp。若 nterp 帧上 Apply
    // 成功但求值的 dex_pc 为 0(活 x22 被改写),这里无帧可注入;
    // StepNterp 只在 Apply 失败时运行,所以在"Apply 成功但 dex_pc=0"的
    // 少见情形下跳过 DEX 帧、直接继续到本机调用者即可(对齐 AOSP 机会式
    // 的 FillInDexFrame,从不阻塞回溯)。
    regs_->ClearDexPc();
    if (dexPc == 0) {
        DFXLOGU("InjectDexFrame: DEX1 magic seen but dex_pc=0, skip frame (signal consumed)");
        return;
    }

    if (maps_ == nullptr) {
        DFXLOGU("InjectDexFrame: dex_pc=0x%{public}" PRIx64 " but maps_ is null, skip", (uint64_t)dexPc);
        return;
    }
    std::shared_ptr<DfxMap> dexMap;
    if (!maps_->FindMapByAddr(static_cast<uintptr_t>(dexPc), dexMap) || dexMap == nullptr) {
        DFXLOGU("InjectDexFrame: dex_pc=0x%{public}" PRIx64 " not in any map, skip", (uint64_t)dexPc);
        return;
    }
    StepFrame dexFrame;
    dexFrame.pc = dexPc;
    dexFrame.sp = regs_->GetSp();
    dexFrame.fp = 0;
    dexFrame.frameType = FrameType::DEX_FRAME;
    AddFrame(dexFrame, dexMap);
    DFXLOGU("InjectDexFrame: injected DEX frame via DWARF DEX1 magic, pc=0x%{public}" PRIx64 ", map=%{public}s",
        (uint64_t)dexPc, dexMap->name.c_str());
}

void Unwinder::Impl::FillFrame(DfxFrame& frame, bool needSymParse)
{
    if (frame.map == nullptr) {
        frame.relPc = frame.pc;
        frame.mapName = "Not mapped";
        DFXLOGU("Current frame is not mapped.");
        return;
    }
    std::string mapName = frame.map->GetElfName();
    frame.mapName = mapName;
    DFX_TRACE_SCOPED_DLSYM("FillFrame:%s", frame.mapName.c_str());
    pid_t pid = pid_ <= 0 ? getpid() : pid_;
    auto elf = frame.map->GetElf(pid);
    frame.relPc = frame.map->GetRelPc(frame.pc);
    frame.mapOffset = frame.map->offset;
    if (elf == nullptr) {
        if (needSymParse) {
            TryJitSymbolLookup(frame);
        }
        return;
    }
    frame.buildId = elf->GetBuildId();
    frame.elfOffset = elf->GetBaseOffset();
    if (needSymParse) {
        ParseFrameSymbol(frame);
    }
    if (elf->IsAdlt()) {
        std::string originSoName = elf->GetAdltOriginSoNameByRelPc(frame.relPc);
        if (!originSoName.empty()) {
            mapName.append(":" + originSoName);
        }
    }
    frame.mapName = mapName;
    DFXLOGU("mapName: %{public}s, mapOffset: %{public}" PRIx64 "", frame.mapName.c_str(), frame.mapOffset);
}

void Unwinder::Impl::FillDexFrame(DfxFrame& frame)
{
    // DEX 帧由 StepNterp 注入,代表解释执行的 Java 方法。其 PC 是 dex_pc
    // (x22 寄存器),指向已映射的 DEX 文件(如 .apk/.vdex/.odex 映射内部)。
    // 绝不能对该映射尝试加载 ELF——只算 rel_pc = pc - map->begin,并设置
    // map offset 让输出显示正确的文件偏移(对齐 AOSP FillInDexFrame 行为)。
    if (frame.map == nullptr) {
        frame.relPc = frame.pc;
        frame.mapName = "Not mapped";
        DFXLOGU("DEX frame is not mapped, pc=0x%{public}" PRIx64 "", frame.pc);
        return;
    }
    frame.mapName = frame.map->GetElfName();
    frame.relPc = frame.pc - frame.map->begin;
    frame.mapOffset = frame.map->offset;
    DFXLOGU("FillDexFrame: pc=0x%{public}" PRIx64 ", relPc=0x%{public}" PRIx64
        ", map=%{public}s, offset=0x%{public}" PRIx64,
        frame.pc, frame.relPc, frame.mapName.c_str(), frame.mapOffset);
}

void Unwinder::Impl::FillArkwebJsFrame(DfxFrame& frame)
{
    if (frame.map == nullptr) {
        DFXLOGU("Current ArkwebJs frame is not map.");
        return;
    }
    DFX_TRACE_SCOPED_DLSYM("FillArkwebJsFrame:%s", frame.map->name.c_str());
    DFXLOGU("FillArkwebJsFrame, map name: %{public}s", frame.map->name.c_str());
    int32_t pid = pid_ <= 0 ? getpid() : pid_;
    if (pid <= 0) {
        DFXLOGE("pid can not less than 0, return directly!");
        return;
    }
    if (arkwebJsExtractorptr_ == 0 &&
        DfxJsvm::Instance().JsvmCreateJsSymbolExtractor(&arkwebJsExtractorptr_, static_cast<uint32_t>(pid)) == -1) {
        DFXLOGE("create arkweb js extractor failed");
        return;
    }
    JsvmFunction jsFunction;
    DfxJsvm::Instance().ParseJsvmFrameInfo(frame.pc, arkwebJsExtractorptr_, &jsFunction);
    frame.funcName = std::string(jsFunction.functionName);
    if (StartsWith(frame.map->name, ARKWEB_NATIVE_MAP)) {
        frame.mapName = frame.map->GetElfName();
        frame.isJsFrame = false;
        frame.relPc = frame.pc - frame.map->begin;
        frame.funcOffset = jsFunction.offsetInFunction;
    } else {
        frame.isJsFrame = true;
        frame.mapName = std::string(jsFunction.url);
        frame.line = jsFunction.line;
        frame.column = jsFunction.column;
    }
    DFXLOGU("arkweb js frame funcName: %{public}s", frame.funcName.c_str());
}

void Unwinder::Impl::FillJsFrame(DfxFrame& frame)
{
    if (frame.map == nullptr) {
        DFXLOGU("Current js frame is not map.");
        return;
    }
    DFX_TRACE_SCOPED_DLSYM("FillJsFrame:%s", frame.map->name.c_str());
    DFXLOGU("Fill js frame, map name: %{public}s", frame.map->name.c_str());
    JsFunction jsFunction {};
    if ((pid_ == UNWIND_TYPE_LOCAL) || (pid_ == UNWIND_TYPE_CUSTOMIZE_LOCAL)) {
        if (!FillJsFrameLocal(frame, &jsFunction)) {
            return;
        }
    } else {
        auto hap = frame.map->GetHap();
        if (hap == nullptr) {
            DFXLOGW("Get hap error, name: %{public}s", frame.map->name.c_str());
            return;
        }
        if (!hap->ParseHapInfo(pid_, frame.pc, frame.map, &jsFunction)) {
            DFXLOGW("Failed to parse hap info, pid: %{public}d", pid_);
            return;
        }
    }
    frame.isJsFrame = true;
    frame.mapName = std::string(jsFunction.url, strnlen(jsFunction.url, sizeof(jsFunction.url)));
    frame.funcName = std::string(jsFunction.functionName,
        strnlen(jsFunction.functionName, sizeof(jsFunction.functionName)));
    frame.packageName = std::string(jsFunction.packageName,
        strnlen(jsFunction.packageName, sizeof(jsFunction.packageName)));
    frame.line = static_cast<int32_t>(jsFunction.line);
    frame.column = jsFunction.column;
    DFXLOGU("Js frame mapName: %{public}s, funcName: %{public}s, line: %{public}d, column: %{public}d",
        frame.mapName.c_str(), frame.funcName.c_str(), frame.line, frame.column);
}

bool Unwinder::Impl::FillJsFrameLocal(DfxFrame& frame, JsFunction* jsFunction)
{
    if (!isArkCreateLocal_) {
        if (DfxArk::Instance().ArkCreateLocal() < 0) {
            DFXLOGW("Failed to ark create local.");
            return false;
        }
        isArkCreateLocal_ = true;
    }

    if (DfxArk::Instance().ParseArkFrameInfoLocal(static_cast<uintptr_t>(frame.pc),
        static_cast<uintptr_t>(frame.map->begin), static_cast<uintptr_t>(frame.map->offset), jsFunction) < 0) {
        DFXLOGW("Failed to parse ark frame info local, pc: %{private}p, begin: %{private}p",
            reinterpret_cast<void *>(frame.pc), reinterpret_cast<void *>(frame.map->begin));
        return false;
    }
    frame.isJsFrame = true;
    return true;
}

bool Unwinder::Impl::GetFrameByPc(uintptr_t pc, std::shared_ptr<DfxMaps> maps, DfxFrame &frame)
{
    frame.pc = static_cast<uint64_t>(StripPac(pc, 0));
    std::shared_ptr<DfxMap> map = nullptr;
    if ((maps == nullptr) || !maps->FindMapByAddr(frame.pc, map) || map == nullptr) {
        DFXLOGE("Find map error");
        return false;
    }

    frame.map = map;
    if (DfxMaps::IsArkHapMapItem(map->name) || DfxMaps::IsArkCodeMapItem(map->name)) {
        FillJsFrame(frame);
    } else if (map->IsArkWebJsExecutable()) {
        FillArkwebJsFrame(frame);
    } else {
        FillFrame(frame, enableParseNativeSymbol_);
    }
    return true;
}

bool Unwinder::Impl::GetLockInfo(int32_t tid, char* buf, size_t sz)
{
#ifdef __aarch64__
    if (frames_.empty()) {
        return false;
    }

    if (frames_[0].funcName.find("__timedwait_cp") == std::string::npos) {
        return false;
    }

    uintptr_t lockPtrAddr = firstFrameSp_ + 64; // 64 : sp + 0x40
    uintptr_t lockAddr;
    if (ReadProcMemByPid(tid, lockPtrAddr, &lockAddr, sizeof(uintptr_t)) != sizeof(uintptr_t)) {
        DFXLOGW("Failed to find lock addr.");
        return false;
    }

    size_t rsize = ReadProcMemByPid(tid, lockAddr, buf, sz);
    if (rsize != sz) {
        DFXLOGW("Failed to fetch lock content, read size:%{public}zu expected size:%{public}zu", rsize, sz);
        return false;
    }
    return true;
#else
    return false;
#endif
}

void Unwinder::Impl::GetFramesByPcs(std::vector<DfxFrame>& frames, std::vector<uintptr_t> pcs)
{
    if (maps_ == nullptr) {
        DFXLOGE("maps_ is null, return directly!");
        return;
    }
    frames.clear();
    std::shared_ptr<DfxMap> map = nullptr;
    for (size_t i = 0; i < pcs.size(); ++i) {
        DfxFrame frame;
        frame.index = i;
        pcs[i] = StripPac(pcs[i], 0);
        frame.pc = static_cast<uint64_t>(pcs[i]);
        if ((map != nullptr) && map->Contain(frame.pc)) {
            DFXLOGU("map had matched");
        } else if (!maps_->FindMapByAddr(pcs[i], map)) {
            map = nullptr;
            frame.relPc = frame.pc;
            frame.mapName = "Not mapped";
            DFXLOGE("Find map error");
            continue;
        }
        frame.map = map;
        if (DfxMaps::IsArkHapMapItem(map->name) || DfxMaps::IsArkCodeMapItem(map->name)) {
            FillJsFrame(frame);
        } else if (map->IsArkWebJsExecutable()) {
            FillArkwebJsFrame(frame);
        } else {
            FillFrame(frame, enableParseNativeSymbol_);
        }
        frames.emplace_back(frame);
    }
}

void Unwinder::GetLocalFramesByPcs(std::vector<DfxFrame>& frames, std::vector<uintptr_t> pcs)
{
    frames.clear();
    for (size_t i = 0; i < pcs.size(); ++i) {
        DfxFrame frame;
        frame.index = i;
        frame.pc = static_cast<uint64_t>(pcs[i]);
        frames.emplace_back(frame);
    }
    FillLocalFrames(frames);
}

bool Unwinder::GetSymbolByPc(uintptr_t pc, std::shared_ptr<DfxMaps> maps, std::string& funcName, uint64_t& funcOffset)
{
    if (maps == nullptr) {
        return false;
    }
    std::shared_ptr<DfxMap> map = nullptr;
    if (!maps->FindMapByAddr(pc, map) || (map == nullptr)) {
        DFXLOGE("Find map is null");
        return false;
    }
    uint64_t relPc = map->GetRelPc(static_cast<uint64_t>(pc));
    auto elf = map->GetElf();
    if (elf == nullptr) {
        DFXLOGE("Get elf is null");
        return false;
    }
    return DfxSymbols::GetFuncNameAndOffsetByPc(relPc, elf, funcName, funcOffset);
}

std::string Unwinder::GetFramesStr(const std::vector<DfxFrame>& frames)
{
    return DfxFrameFormatter::GetFramesStr(frames);
}

int Unwinder::Impl::DlPhdrCallback(struct dl_phdr_info *info, size_t size, void *data)
{
    auto frame = reinterpret_cast<DfxFrame *>(data);
    const ElfW(Phdr) *phdr = info->dlpi_phdr;
    frame->pc = StripPac(frame->pc, 0);
    for (int n = info->dlpi_phnum; --n >= 0; phdr++) {
        if (phdr->p_type == PT_LOAD) {
            ElfW(Addr) vaddr = phdr->p_vaddr + info->dlpi_addr;
            if (frame->pc >= vaddr && frame->pc < vaddr + phdr->p_memsz) {
                frame->relPc = frame->pc - info->dlpi_addr;
                frame->mapName = std::string(info->dlpi_name);
                DFXLOGU("relPc: %{public}" PRIx64 ", mapName: %{public}s", frame->relPc, frame->mapName.c_str());
                return 1;
            }
        }
    }
    return 0;
}

bool Unwinder::Impl::UnwindLocalByOtherTid(const pid_t tid, bool fast, size_t maxFrameNum, size_t skipFrameNum)
{
    if (tid < 0 || tid == gettid()) {
        lastErrorData_.SetCode(UNW_ERROR_NOT_SUPPORT);
        return false;
    }
    auto& instance = LocalThreadContextMix::GetInstance();

    if (tid == getpid()) {
        uintptr_t stackBottom = 1;
        uintptr_t stackTop = static_cast<uintptr_t>(-1);
        if (!GetMainStackRangeInner(stackBottom, stackTop)) {
            return false;
        }
        instance.SetStackRang(stackTop, stackBottom);
    }
    bool isSuccess = instance.CollectThreadContext(tid);
    if (!isSuccess) {
        instance.ReleaseCollectThreadContext();
        return false;
    }

    std::shared_ptr<DfxRegs> regs = DfxRegs::Create();
    instance.SetRegister(regs);
    SetRegs(regs);
    EnableFillFrames(true);
    SetBytecodePcAndInterruptPc();

    bool ret = false;
    if (fast) {
        maps_ = instance.GetMaps();
        ret = UnwindByFp(&instance, maxFrameNum, 0, true);
    } else {
        ret = Unwind(&instance, maxFrameNum, skipFrameNum);
    }
    instance.ReleaseCollectThreadContext();
    return ret;
}
} // namespace HiviewDFX
} // namespace OHOS
