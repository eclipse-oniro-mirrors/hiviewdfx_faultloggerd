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
// Stack-scan fallback (StepByScan): bound the scan window and the number of
// scan-adopted frames per unwind so a broken stack cannot cause unbounded work.
constexpr size_t SCAN_WINDOW_WORDS = 64; // 64 words = 512 bytes above sp
constexpr uint8_t MAX_SCAN_STEPS = 2;
#endif

// JIT-compiled code only ever lives in anonymous or memfd mappings; a pc inside
// a named file mapping (.so / .oat / .apk) can never match a
// __jit_debug_descriptor entry, so the JIT registry scan can be skipped for it.
static bool IsFileBackedMapName(std::string name)
{
    // Strip the "/proc/<pid>/root" sandbox prefix (added by DfxMap::FormatMapName)
    // first: pseudo entries like "[shmm]" / "[anon:dalvik-...]" would otherwise
    // start with '/' and be mistaken for file paths, which would skip the JIT
    // lookup for anonymous executable regions (e.g. the ART JIT cache).
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
        // Reusing one Unwinder for another pid must not keep the previous
        // pid's JIT descriptor/entries cache.
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
    // x25(xREFS) captured at Unwind() entry from the perf sample
#if defined(__aarch64__)
    uintptr_t sampleXRefs_ = 0;
    // x29(FP) at Unwind() entry — sample true value, immune to
    // CFI/fallback-chain pollution (speed-profile doc §7 fix)
    uintptr_t sampleX29_ = 0;
#endif
    // FpTailUnwind: pure-FP chain tail from sample x29 (anchor-continuation)
    void FpTailUnwind(void* ctx, size_t maxFrameNum);
    // K12: map-pointer cache for thread-root candidates (libc/ld-musl maps).
    // Frames in those maps are cheap to classify; only they pay a symbol
    // lookup. Untouched when lookup fails (strip/unreachable) = old behavior.
    std::unordered_map<const DfxMap *, bool> rootMapCache_ {};
    const DfxMaps *rootMapGen_ = nullptr; // maps_ generation, invalidates cache
    bool IsThreadRootFrame();
    // AOSP16-style DEX frame injection: called at the start of each StepInner
    // iteration. If a previous DWARF Step set the dex_pc pseudo-register (via
    // the DEX1 magic marker in libart.so's CFI), inject a virtual DEX frame
    // for the interpreted Java method before the current native frame is
    // added. This produces the canonical stack ordering:
    //   ... | nterp_helper | <DEX frame> | caller-of-nterp_helper | ...
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
    // Last pc produced by the LR fallback (see UpdateRegsState). LR is only
    // refreshed by a successful DWARF Apply (x30 rule); falling back to an
    // already-consumed LR value never advances the unwind.
    uintptr_t lastLrFallbackPc_ = 0;
    // Last-resort stack scan (off by default; enable via SetEnableScanStep).
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

// K12: __start_thread / __libc_init are the stack bottom of a thread; any
// frame beyond them (produced by scan/LR/fp fallbacks from stack-bottom
// residue) is an artifact. Observed on ~82% of hiperf sample chains
// (trampoline mirror + repeated start); cdumpcatcher is unaffected.
bool Unwinder::Impl::IsThreadRootFrame()
{
    if (frames_.size() < 2 || maps_ == nullptr) {
        return false;
    }
    if (rootMapGen_ != maps_.get()) { // maps snapshot replaced: drop stale keys
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
        // exact module names only: a bare "libc" substring would also match
        // libcrypto / libc++_shared and pay needless symbol lookups.
        isRootMap = (name.size() >= 8 && name.compare(name.size() - 8, 8, "/libc.so") == 0) ||
                    (name.find("ld-musl") != std::string::npos);
        // qwen review: 16 is too small — a process has 100+ distinct DfxMap
        // pointers (one per VMA per so); at 16, most app-library frames miss
        // the cache and pay a string comparison every frame (the 2.58%
        // hotspot). 512 entries ≈ 30KB covers the full working set.
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
        return false; // no symbol -> keep unwinding (old behavior)
    }
    return (funcName.find("__start_thread") != std::string::npos) ||
           (funcName.find("__libc_init") != std::string::npos) ||
           (funcName.find("__libc_start_main") != std::string::npos);
}

#if defined(__aarch64__)
// FpTailUnwind: walk the pure FP chain from the original sample x29.
// v2 anchor-continuation design (FpStep_odex doc):
//   - anchor = frames_.back().sp (last successful frame's SP, always clean
//     because failed frames are never added to frames_)
//   - only append frames whose fp > anchor (physically deeper in stack)
//   - no pc comparison / no dedup — avoids return-addr vs DoPcAdjust
//     mismatch and legitimate-recursion false deletion
//   - stops at thread root (IsThreadRootFrame) / fp non-increasing /
//     read failure / frame budget
void Unwinder::Impl::FpTailUnwind(void* ctx, size_t maxFrameNum)
{
    if (ctx != nullptr && memory_ != nullptr) {
        memory_->SetCtx(ctx);
    }
    if (frames_.empty()) return;
    // anchor: SP of the last successfully added frame (clean, unpolluted)
    uintptr_t anchor = frames_.back().sp;
    uintptr_t fp = sampleX29_;
    uintptr_t prevFp = 0;
    size_t budget = maxFrameNum - frames_.size();
    size_t appended = 0;
    while (fp != 0 && fp > prevFp && appended < budget) {
        uintptr_t nextFp = 0, nextPc = 0;
        if (!memory_->Read<uintptr_t>(fp, &nextFp, false)) break;
        if (!memory_->Read<uintptr_t>(fp + sizeof(uintptr_t), &nextPc, false)) break;
        if (nextFp == 0 || nextFp <= fp) break;
        nextPc = StripPac(nextPc, pacMask_);
        // anchor-continuation: skip frames at or above the anchor
        // (already unwound by the main loop); only append deeper frames
        if (fp <= anchor) {
            prevFp = fp;
            fp = nextFp;
            continue;
        }
        // validate: pc must be in an executable map (reject stack residue)
        std::shared_ptr<DfxMap> map = nullptr;
        if (maps_ == nullptr || !maps_->FindMapByAddr(nextPc, map) ||
            map == nullptr || !map->IsMapExec()) {
            break; // garbage pc — stop, don't fabricate frames
        }
        StepFrame frame;
        frame.pc = nextPc;
        frame.sp = fp;
        frame.fp = nextFp;
        AddFrame(frame, map);
        appended++;
        // thread-root check (K12, same logic)
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
}
#endif

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
    // pc before DoPcAdjust: the raw return address produced by the previous
    // step. An LR fallback that re-consumes a stale LR bounces the pc between
    // lr and lr-4 (the adjust), so the repeated-frame check below must compare
    // against rawPc as well, not only the adjusted entry pc.
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
    sampleXRefs_ = (*regs_)[25];
    sampleX29_ = (*regs_)[29]; // 29: x29(FP) — sample FP chain anchor // 25: x25(xREFS) — perf sample真值,不受CFI链污染
#endif

    bool needAdjustPc = false;
    isResetFrames_ = false;
    lastLrFallbackPc_ = 0;
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
            break;
        }
        if (IsThreadRootFrame()) { // K12: thread root reached, stop unwinding
            break;
        }
    } while (true);
#if defined(__aarch64__)
    // speed-profile doc §7: when dwarf broke in no-table odex and the
    // fallback chain got polluted, the ART-maintained FP chain from the
    // original sample x29 is still valid. Walk it as ultimate fallback
    // (anchor-continuation: only append frames physically deeper than
    // the last successful frame's SP — no pc comparison, no dedup).
    if (sampleX29_ != 0 && !frames_.empty()) {
        FpTailUnwind(ctx, maxFrameNum);
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
        // The accessor-provided maps can lag behind the target's live mappings:
        // customize callers (e.g. hiperf) feed perf-recorded maps, which never
        // learn about reserve+mprotect regions such as the ART JIT cache, and a
        // map miss here would cut the callchain short. Retry with our own
        // /proc snapshot before treating the pc as unmapped. Only an executable
        // map counts: a pc in a non-exec region is garbage either way.
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
        // Only advance along a plausible fp chain. [fp] can hold arbitrary
        // data (e.g. a Java object pointer read while the fp belongs to a
        // native frame reached via LR fallback); blindly adopting it clobbers
        // the fp and dooms the later FpStep. FpStep itself requires the chain
        // to grow, so require the same here.
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
    // Last-resort stack scan (AOSP ScanFrame style), reached only when every
    // other strategy failed: no unwind info for the pc (third-party libs such
    // as libttffmpeg.so / libsscronet.so ship most of .text without
    // .eh_frame), LR is stale or a no-op, and the fp chain is unusable
    // (-fomit-frame-pointer). Walk the stack upwards from sp and adopt the
    // first word that plausibly is a saved return address: 4-byte aligned and
    // pointing into an executable mapping. The caller's saved RA usually sits
    // within a few dozen words of sp, so the 512-byte window suffices.
    for (size_t i = 0; i < SCAN_WINDOW_WORDS; i++) {
        uintptr_t addr = sp + i * sizeof(uintptr_t);
        uintptr_t val = 0;
        if (!memory_->ReadMem(addr, &val)) {
            break; // left the readable stack
        }
        uintptr_t candidate = StripPac(val, pacMask_);
        // aarch64: instructions are 4-byte aligned. x86_64: no alignment
        // requirement — the mask only discards values unlikely to be
        // return addresses.
        if ((candidate & 0x3) != 0) {
            continue;
        }
        if (candidate == currentPc) {
            continue; // no progress
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
    // Save x22 (dex_pc) and x25 (xREFS) before Apply: the flush can
    // overwrite them even when Apply returns false, and StepNterp needs
    // the original live values to locate the nterp frame.
    uintptr_t origDexPc = (*regs_)[22]; // 22: x22 (xPC) on ARM64
    // Prefer sample-time x25 (immune to CFI-chain corruption)
    uintptr_t origXRefs = (sampleXRefs_ != 0) ? sampleXRefs_ : (*regs_)[25];
#endif
    MAYBE_UNUSED bool noCallerInCfi = false;
    // True when this frame had no unwind table at all (the else path below).
    // The LR fallback is only allowed for such frames and runs AFTER
    // StepNterp/TryJitStep: an anonymous executable pc (e.g. in the ART JIT
    // cache) must get its JIT step first, because that is the only fallback
    // which also restores sp/fp correctly. An LR fallback cannot update sp/fp,
    // so the next frame is evaluated with a stale sp and produces garbage.
    MAYBE_UNUSED bool noUnwindTable = !unwinderResult;
    if (unwinderResult) {
#if defined(__arm__) || defined(__aarch64__)
    uintptr_t lr = *(regs_->GetReg(REG_LR));
#endif
    uint16_t applyErrCode = 0;
    unwinderResult = Apply(regs_, rs, applyErrCode);
    // The CFI explicitly says this frame has no caller (DW_CFA_undefined on the
    // return-address register; typical for noreturn / outermost frames).
    // libunwindstack ends the unwind here. Treat it as end-of-stack: falling
    // through to TryJitStep/FpStep would fabricate frames from stale fp values
    // (observed as garbage libicu_jni frames after a RETURN_ADDRESS_UNDEFINED
    // failure, followed by an fp-mode stall loop). StepNterp is still allowed
    // below: it self-validates (libart map + nterp callee-saves layout).
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
        // No unwind table for this frame. The LR fallback used to run here,
        // before StepNterp/TryJitStep; it now runs after them (see below) so
        // JIT-cache frames are stepped with correct sp/fp first.
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
    // LR fallback, last resort before FpStep (only for frames without an
    // unwind table; see noUnwindTable). In fp step mode DWARF no longer runs,
    // so LR is frozen at the value captured when fp mode was entered — using
    // it would repeatedly pull pc back to that stale LR and form a 2-cycle
    // with FpStep, so it is skipped in fp mode.
    // LR is only refreshed by a successful DWARF Apply (x30 rule); FpStep and
    // StepNterp leave it untouched. Falling back to an already-consumed LR makes
    // no progress (the pc only oscillates between lr and lr-4 through DoPcAdjust,
    // which also defeats the pc==lr guard inside SetPcFromReturnAddress), so each
    // LR value is consumed at most once per unwind. Also reject when the target
    // equals the current pc: the frame's pc typically came from the same RA stack
    // slot Apply just restored into LR, and PAC plus the ±4 DoPcAdjust hide this
    // equality from the pc==lr guard inside SetPcFromReturnAddress; such a
    // fallback reproduces the identical frame and ends the unwind at
    // UnwindFrame's repeated-frame check. A rejected fallback keeps
    // unwinderResult false so FpStep still gets a chance to run.
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
                // Stale or no-op LR: restore pc, do not claim success.
                regs_->SetPc(pcBefore);
                DFXLOGU("LR fallback skipped: stale or no-op lr %{private}p", reinterpret_cast<void *>(fallbackPc));
            }
        }
    }
#if defined(__aarch64__) || defined(__x86_64__)
    // try fp. Skip for vDSO-type maps (IsVdsoMap covers [vdso] and [shmm]):
    // these pseudo-mappings are parsed as in-memory ELF by VdsoElfFactory and,
    // when that yields no unwind table, the frame pointer register does not hold
    // a reliable frame pointer (the code is a kernel/shared-memory stub, not
    // frame-pointer-compiled user code). Chasing [fp] there fabricates garbage
    // frames from stack residue and, by marking the step successful, also blocks
    // the bounded StepByScan fallback below. The ART JIT cache (fp==0) already
    // fast-fails FpStep, so it is unaffected.
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
            // The fp chain is broken (e.g. the next fp did not increase). Leave fp
            // mode so the next frame retries DWARF: in fp mode StepInner skips
            // ParseUnwindTable entirely, so a broken chain would otherwise stall
            // the unwind with no way out. If DWARF (and the other fallbacks) also
            // fail, UnwindFrame's repeated-frame guard terminates the unwind.
            isFpStep_ = false;
        }
    }
    if (!unwinderResult && enableScanStep_ && scanUsedCount_ < MAX_SCAN_STEPS) {
        // Stack scan, final fallback after all strategies failed. Bounded by
        // MAX_SCAN_STEPS per unwind; a scanned frame is a best-effort guess
        // (stack residue may cause a jump), so it is opt-in (default off).
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
        // bound the cache: pcs are mostly unique across samples (hiperf
        // post-pass), so a full clear loses almost nothing. ~64K entries
        // ≈ 3-4 MB including node overhead (sizeof(StepCache)=16B).
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
    // AOSP16-style: if a previous DWARF Step set dex_pc (via the DEX1 magic
    // marker in libart.so's CFI for nterp_helper), inject a virtual DEX
    // frame BEFORE the current native frame is added. The dex_pc points
    // into a mapped DEX/vdex/apk/jar file and represents the interpreted
    // Java method's current PC. Must run before any AddFrame call below.
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
    // hasRegLocState is true when DWARF succeeds.
    // UpdateRegsState may succeed via LR fallback or JIT step even if DWARF fails.
    // In those cases, frame.pc/sp/fp have been updated to the next frame's values,
    // so we should return true to continue unwinding.
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
    // Do NOT verify that the new SP is readable after a successful DWARF
    // Apply: the return-address register can be correct while the
    // CFA-derived SP is not a usable stack value (nterp_helper's CFA is
    // computed from the live xREFS register). A bogus SP terminates the
    // unwind on its own: reads through it fail on the next steps, and the
    // next frame recomputes its own SP from its own CFI.
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
    // See IsFileBackedMapName: a pc in a named file mapping cannot be JIT code,
    // so the JIT symbol registry cannot contain it either.
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
    // JIT-compiled code never lives in a named file mapping (see IsFileBackedMapName),
    // so skip the registry scan for such pcs before doing any work.
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
    // Only handle ARM64 nterp_helper / art_quick_nterp_* frames in libart.so/libartd.so.
    // Use origSp (the SP before Apply corrupted it) because Apply may have set regs_->sp
    // to a bad CFA value before returning false. Similarly, use saved x22/x25 because
    // Apply's Flush may have overwritten them.
    if (maps_ == nullptr || memory_ == nullptr || regs_ == nullptr) {
        return false;
    }

    std::shared_ptr<DfxMap> map;
    if (memory_->GetMapByPc(pc, map) != UNW_ERROR_NONE || map == nullptr) {
        return false;
    }

    // Must be in libart.so / libartd.so. nterp_helper is an ART interpreter
    // entry that lives in libart.so. Without this guard, a misclassified
    // frame in some other .so could be wrongly treated as nterp.
    auto pos = map->name.rfind('/');
    std::string baseName = (pos == std::string::npos) ? map->name : map->name.substr(pos + 1);
    if (baseName != "libart.so" && baseName != "libartd.so") {
        return false;
    }

    // Identify nterp frames WITHOUT relying on libart.so's symbol table.
    // nterp_helper is a static (non-exported) symbol, so it is absent from
    // .dynsym, and release builds of libart.so usually strip .symtab as well.
    // Symbol-name matching (GetFuncNameAndOffsetByPc) therefore fails on
    // production libart.so, which breaks the ART-interpreter crossing.
    //
    // Two signals can identify an nterp frame, in priority order:
    //   1) regs_->DexPcSeen(): the DWARF CFI for nterp_helper uses the AOSP16
    //      DEX1 magic marker (DW_OP_const4u 'D' 'E' 'X' '1' DW_OP_drop) on
    //      a register rule (val_expression on x0, reading x22). DfxInstructions
    //      ::Apply raises this flag whenever the magic fires, independently of
    //      the evaluated dex_pc value. The DEX1 magic is ONLY emitted by ART's
    //      CFI for nterp_helper, so the flag alone is proof of an nterp frame
    //      EVEN WHEN the dex_pc value is 0/unmapped (e.g. the live x22 read by
    //      the val_expression was clobbered to 0 by intermediate compiled/JNI
    //      frames before the thread reached a syscall). The previous check
    //      (DexPc() != 0) conflated "magic fired" with "value non-zero" and
    //      stopped the unwind at nterp_helper whenever x22 happened to be 0.
    //      DexPcSeen() survives because it is set BEFORE the CFA flush and
    //      before Apply may fail on an undefined return-address register.
    //      This is the most reliable signal when DWARF is present at all.
    //   2) x22 physical register (origDexPc): the live dex_pc while nterp is
    //      actively interpreting. Used when there is no DEX1 CFI at all
    //      (older libart.so) or before any DWARF path has run. This path
    //      still requires the value to map to a DEX-bearing region, since
    //      otherwise a non-nterp libart.so frame could be misidentified.
    //
    // dex_pc validity only controls the DEX frame injection
    // (Unwinder::FillInDexFrame semantics). The callee-saves recovery below
    // always runs once this is identified as an nterp frame; a bogus dex_pc
    // only suppresses the DEX frame injection — it does not stop the unwind.
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
            // Common DEX containers. Use substring match for .vdex because
            // dex2oat emits transient files like "base.vdex.<hash>.tmp" before
            // renaming to the canonical "base.vdex", so a strict suffix match
            // on ".vdex.tmp" would miss the production form.
            dexPcValid = n.find(".vdex") != std::string::npos ||
                       EndsWith(n, ".dex") || EndsWith(n, ".apk") ||
                       StartsWith(n, "[anon:dalvik") ||
                       // DEX extracted into an anonymous mapping has an empty
                       // name; require the page to be executable so we don't
                       // match arbitrary read/write anon regions.
                       (n.empty() && dexMap->IsMapExec());
        }
    }
    // DEX1 magic fired => definitely an nterp frame (the magic is only
    // emitted by ART's CFI for nterp_helper), even if the dex_pc value is 0
    // or unmapped (e.g. live x22 was clobbered to 0 by an intermediate
    // compiled/JNI frame before the thread reached a syscall). DexPcSeen()
    // tracks the magic hit independently of the value, so we still enter the
    // callee-saves recovery and read the saved x22 at [saved_sp+88]. Using
    // DexPc()!=0 here (the old check) would miss the x22==0 case and stop the
    // unwind at nterp_helper. Otherwise, fall back to requiring a valid
    // DEX-mapped dex_pc (the original signal) so we don't misclassify other
    // libart.so frames (e.g. GC, JIT) as nterp.
    bool isNterp = regs_->DexPcSeen() || dexPcValid;
    if (!isNterp) {
        DFXLOGU("StepNterp: not nterp, pc=0x%{public}" PRIx64 ", dexPc=0x%{public}" PRIx64
            " (seen=%{public}d, regs:%{public}" PRIx64 ", x22:%{public}" PRIx64 "), dexMap=%{public}s",
            (uint64_t)pc, (uint64_t)effectiveDexPc, (int)regs_->DexPcSeen(),
            (uint64_t)regs_->DexPc(), (uint64_t)origDexPc, dexMapName.c_str());
        return false;
    }
    // Consume the DWARF pseudo-register so InjectDexFrameFromDwarf on the next
    // StepInner iteration does not inject a duplicate DEX frame for the same
    // dex_pc. We inject it ourselves below.
    regs_->ClearDexPc();

    DFXLOGU("StepNterp: hit nterp frame, pc=0x%{public}" PRIx64 ", dexPc=0x%{public}" PRIx64
        " (valid=%{public}d), dexMap=%{public}s, origSp=0x%{public}" PRIx64 "",
        (uint64_t)pc, (uint64_t)effectiveDexPc, (int)dexPcValid, dexMapName.c_str(), (uint64_t)origSp);

    // ARM64 nterp register allocation (from art/runtime/interpreter/mterp/arm64ng/main.S):
    //   x22 (xPC)   = interpreted program counter (DEX PC, absolute address in mapped DEX)
    //   x25 (xREFS) = base of object references of dex registers
    //
    // ARM64 nterp callee-saves frame layout (SAVE_ALL_CALLEE_SAVES /
    // RESTORE_ALL_CALLEE_SAVES in art/runtime/interpreter/mterp/arm64ng/main.S):
    //   [xREFS - 8]       = saved SP (base of callee-saves area)
    //   [saved_sp + 0..56] = d8..d15 (FP callee-saves)
    //   [saved_sp + 64]   = x19 (saved, not restored by nterp)
    //   [saved_sp + 72]   = x20 (saved, not restored by nterp)
    //   [saved_sp + 80]   = x21 (saved, not restored by nterp)
    //   [saved_sp + 88]   = x22 (xPC / DEX PC)   <-- saved DEX PC lives here
    //   [saved_sp + 96]   = x23
    //   [saved_sp + 104]  = x24
    //   [saved_sp + 112]  = x25 (xREFS)
    //   [saved_sp + 120]  = x26
    //   [saved_sp + 128]  = x27
    //   [saved_sp + 136]  = x28
    //   [saved_sp + 144]  = x29 (FP)
    //   [saved_sp + 152]  = lr (return address to native caller)
    //   Spill slots end at +160; the frame size CALLEE_SAVES_SIZE is 176
    //   (the top 16 bytes are slack):
    //   caller's SP       = saved_sp + 176
    //
    // The live DEX PC lives in register x22 while nterp is actively
    // interpreting. After nterp_helper calls out into compiled/OAT/JNI
    // code, the captured x22 can hold a mid-function value of an inner
    // frame, so the DWARF DEX1 magic can evaluate to a bogus dex_pc. The
    // real DEX PC was spilled at [saved_sp + 88] before the call-out and is
    // recovered from there. Inject a virtual DEX frame for the interpreted
    // Java method, then set regs to the native caller (lr / caller's SP).
    uintptr_t xRefs = origXRefs; // x25 saved before Apply
    DFXLOGU("StepNterp: dexPc=0x%{public}" PRIx64 ", x25(xREFS)=0x%{public}" PRIx64 "",
        (uint64_t)effectiveDexPc, (uint64_t)xRefs);

    // Read saved SP from [xREFS - 8] to locate the callee-saves frame base.
    uintptr_t savedSp = 0;
    if (xRefs != 0) {
        uintptr_t refsAddr = xRefs - 8; // 8: saved SP is at [xREFS - 8]
        if (!memory_->Read<uintptr_t>(refsAddr, &savedSp, false)) {
            DFXLOGU("StepNterp: failed to read saved_sp at [xREFS-8]=0x%{public}" PRIx64 "", (uint64_t)refsAddr);
            return false;
        }
    }
    if (savedSp == 0) {
        DFXLOGU("StepNterp: saved_sp is 0, cannot locate callee-saves frame");
        return false;
    }

    // Read the native return address (lr) from the callee-saves area.
    uintptr_t nativeLr = 0;
    uintptr_t lrAddr = savedSp + 152; // 152: offset of lr in callee-saves frame
    if (!memory_->Read<uintptr_t>(lrAddr, &nativeLr, false)) {
        DFXLOGU("StepNterp: failed to read native lr at saved_sp+152=0x%{public}" PRIx64 "", (uint64_t)lrAddr);
        return false;
    }
    uintptr_t nativeSp = savedSp + 176; // 176: CALLEE_SAVES_SIZE on ARM64

    // Resolve the DEX PC to inject. Prefer the DWARF DEX1 value when it maps
    // to a DEX-bearing region. Otherwise (x22 was clobbered by an intermediate
    // compiled/JNI frame) fall back to the saved x22 in the nterp callee-saves
    // frame at [saved_sp + 88], which nterp_helper spilled before calling out.
    // 88: offset of x22 (xPC / DEX PC) in the nterp callee-saves frame.
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

    // Inject a virtual DEX frame for the interpreted Java method (matches AOSP
    // FillInDexFrame). The DEX frame's PC is the dex_pc (x22), which points into
    // the mapped DEX file (e.g. inside an .apk/.vdex/.odex mapping). Only inject
    // when dex_pc actually maps to a DEX-bearing region; otherwise silently
    // skip (matches AOSP16 libunwindstack FillInDexFrame, which is opportunistic
    // and never blocks the unwind).
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

    // Set regs to the native caller so unwinding continues past nterp_helper.
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
    // AOSP16 libunwindstack-style: when the DWARF CFI for nterp_helper marks
    // a register with the DEX1 magic (DW_OP_const4u 'D' 'E' 'X' '1' DW_OP_drop),
    // DfxInstructions::Apply stores the evaluated value in regs_->DexPc().
    // We consume it here to inject a virtual DEX frame (FrameType::DEX_FRAME)
    // whose PC is the dex_pc, pointing into a mapped DEX/vdex/apk/jar file.
    // This runs at the top of StepInner, BEFORE the current native frame is
    // added, so the resulting ordering is:
    //   ... nterp_helper frame | <injected DEX frame> | caller frame ...
    // (matches libunwindstack Unwinder::Unwind + FillInDexFrame).
    if (regs_ == nullptr) {
        return;
    }
    uintptr_t dexPc = regs_->DexPc();
    bool seen = regs_->DexPcSeen();
    if (dexPc == 0 && !seen) {
        return;
    }
    // Consume the DEX1 signal unconditionally (clears both dex_pc and the
    // seen flag) so it can never leak past this point and misidentify a later
    // libart.so frame as nterp. When Apply succeeded on the nterp frame but
    // the evaluated dex_pc was 0 (live x22 clobbered), there is nothing to
    // inject here; StepNterp only runs when Apply fails, so in that rare
    // apply-succeeded-but-dex_pc=0 case the DEX frame is skipped and the
    // unwind simply continues to the native caller (matches AOSP's
    // opportunistic FillInDexFrame, which never blocks the unwind).
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
    // DEX frames are injected by StepNterp to represent interpreted Java methods.
    // The PC is the dex_pc (x22 register), which points into a mapped DEX file
    // (e.g. inside an .apk/.vdex/.odex mapping). We must NOT try to load an ELF
    // from this mapping — just compute rel_pc = pc - map->begin, and set the
    // map offset so the output shows the correct file offset (matches AOSP
    // FillInDexFrame behaviour).
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
