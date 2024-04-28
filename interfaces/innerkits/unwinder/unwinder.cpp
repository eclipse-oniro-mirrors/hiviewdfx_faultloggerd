/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include "unwinder.h"

#include <dlfcn.h>
#include <link.h>

#include "dfx_ark.h"
#include "dfx_ark_local.h"
#include "dfx_define.h"
#include "dfx_errors.h"
#include "dfx_extractor_utils.h"
#include "dfx_frame_formatter.h"
#include "dfx_hap.h"
#include "dfx_instructions.h"
#include "dfx_log.h"
#include "dfx_regs_get.h"
#include "dfx_symbols.h"
#include "fp_unwinder.h"
#include "string_printf.h"
#include "string_util.h"
#include "thread_context.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxUnwinder"
}

void Unwinder::Init(bool crash)
{
    LOGI("Unwinder init, crash: %d", crash);
    Destroy();
    memory_ = std::make_shared<DfxMemory>(acc_);
#if defined(__arm__)
    armExidx_ = std::make_shared<ArmExidx>(memory_);
#endif
    dwarfSection_ = std::make_shared<DwarfSection>(memory_);

    if (pid_ == UNWIND_TYPE_LOCAL) {
        maps_ = DfxMaps::Create();
    } else {
        if (pid_ > 0) {
            maps_ = DfxMaps::Create(pid_, crash);
        }
    }

    InitParam();
#if defined(ENABLE_MIXSTACK)
    LOGI("Unwinder mixstack enable: %d", enableMixstack_);
#endif
}

void Unwinder::Clear()
{
    isFpStep_ = false;
    enableMixstack_ = true;
    pcs_.clear();
    frames_.clear();
    if (memset_s(&lastErrorData_, sizeof(UnwindErrorData), 0, sizeof(UnwindErrorData)) != 0) {
        LOGE("%s", "Failed to memset lastErrorData");
    }
}

void Unwinder::Destroy()
{
#if defined(OFFLINE_MIXSTACK)
    if (arkSymbolExtractorPtr_ != 0) {
        DfxArk::ArkDestoryJsSymbolExtractor(arkSymbolExtractorPtr_);
    }
#endif
    Clear();
    rsCache_.clear();
}

bool Unwinder::CheckAndReset(void* ctx)
{
    if ((ctx == nullptr) || (memory_ == nullptr)) {
        return false;
    }
    memory_->SetCtx(ctx);
    return true;
}

bool Unwinder::GetStackRange(uintptr_t& stackBottom, uintptr_t& stackTop)
{
    if (gettid() == getpid()) {
        if (maps_ == nullptr || !maps_->GetStackRange(stackBottom, stackTop)) {
            return false;
        }
    } else {
        if (!GetSelfStackRange(stackBottom, stackTop)) {
            return false;
        }
    }
    return true;
}

bool Unwinder::UnwindLocalWithTid(const pid_t tid, size_t maxFrameNum, size_t skipFrameNum)
{
    if (tid < 0) {
        LOGE("params is nullptr, tid: %d", tid);
        return false;
    }
    LOGI("UnwindLocalWithTid:: tid: %d", tid);
    auto threadContext = LocalThreadContext::GetInstance().CollectThreadContext(tid);
#if defined(__aarch64__)
    if (threadContext != nullptr && threadContext->frameSz > 0) {
        pcs_.clear();
        for (size_t i = 0; i < threadContext->frameSz; i++) {
            pcs_.emplace_back(threadContext->pcs[i]);
        }
        return true;
    }
    return false;
#else
    if (threadContext == nullptr || threadContext->ctx == nullptr) {
        LOGW("Failed to get thread context of tid(%d)", tid);
        LocalThreadContext::GetInstance().ReleaseThread(tid);
        return false;
    }
    if (regs_ == nullptr) {
        regs_ = DfxRegs::CreateFromUcontext(*(threadContext->ctx));
    } else {
        regs_->SetFromUcontext(*(threadContext->ctx));
    }
    uintptr_t stackBottom = 1;
    uintptr_t stackTop = static_cast<uintptr_t>(-1);
    if (tid == getpid()) {
        if (maps_ == nullptr || !maps_->GetStackRange(stackBottom, stackTop)) {
            return false;
        }
    } else if (!LocalThreadContext::GetInstance().GetStackRange(tid, stackBottom, stackTop)) {
        LOGE("Failed to get stack range with tid(%d)", tid);
        return false;
    }
    LOGU("stackBottom: %" PRIx64 ", stackTop: %" PRIx64 "", (uint64_t)stackBottom, (uint64_t)stackTop);
    UnwindContext context;
    context.pid = UNWIND_TYPE_LOCAL;
    context.regs = regs_;
    context.maps = maps_;
    context.stackCheck = false;
    context.stackBottom = stackBottom;
    context.stackTop = stackTop;
    auto ret = Unwind(&context, maxFrameNum, skipFrameNum);
    LocalThreadContext::GetInstance().ReleaseThread(tid);
    return ret;
#endif
}

bool Unwinder::UnwindLocalWithContext(const ucontext_t& context, size_t maxFrameNum, size_t skipFrameNum)
{
    if (regs_ == nullptr) {
        regs_ = DfxRegs::CreateFromUcontext(context);
    } else {
        regs_->SetFromUcontext(context);
    }
    return UnwindLocal(true, false, maxFrameNum, skipFrameNum);
}

bool Unwinder::UnwindLocal(bool withRegs, bool fpUnwind, size_t maxFrameNum, size_t skipFrameNum)
{
    LOGI("UnwindLocal:: fpUnwind: %d", fpUnwind);
    uintptr_t stackBottom = 1;
    uintptr_t stackTop = static_cast<uintptr_t>(-1);
    if (!GetStackRange(stackBottom, stackTop)) {
        LOGE("%s", "Get stack range error");
        return false;
    }
    LOGU("stackBottom: %" PRIx64 ", stackTop: %" PRIx64 "", (uint64_t)stackBottom, (uint64_t)stackTop);

    if (!withRegs) {
#if defined(__aarch64__)
        if (fpUnwind) {
            uintptr_t miniRegs[FP_MINI_REGS_SIZE] = {0};
            GetFramePointerMiniRegs(miniRegs);
            regs_ = DfxRegs::CreateFromRegs(UnwindMode::FRAMEPOINTER_UNWIND, miniRegs);
            withRegs = true;
        }
#endif
        if (!withRegs) {
            regs_ = DfxRegs::Create();
            auto regsData = regs_->RawData();
            if (regsData == nullptr) {
                LOGE("%s", "params is nullptr");
                return false;
            }
            GetLocalRegs(regsData);
        }
    }

    UnwindContext context;
    context.pid = UNWIND_TYPE_LOCAL;
    context.regs = regs_;
    context.maps = maps_;
    context.stackCheck = false;
    context.stackBottom = stackBottom;
    context.stackTop = stackTop;
    if (fpUnwind) {
        return UnwindByFp(&context, maxFrameNum, skipFrameNum);
    } else {
        return Unwind(&context, maxFrameNum, skipFrameNum);
    }
}

bool Unwinder::UnwindRemote(pid_t tid, bool withRegs, size_t maxFrameNum, size_t skipFrameNum)
{
    if ((maps_ == nullptr) || (pid_ <= 0) || (tid < 0)) {
        LOGE("params is nullptr, pid: %d, tid: %d", pid_, tid);
        return false;
    }
    if (tid == 0) {
        tid = pid_;
    }
    LOGI("UnwindRemote:: tid: %d", tid);
    if (!withRegs) {
        regs_ = DfxRegs::CreateRemoteRegs(tid);
    }
    if ((regs_ == nullptr)) {
        LOGE("%s", "regs is nullptr");
        return false;
    }

    UnwindContext context;
    context.pid = tid;
    context.regs = regs_;
    context.maps = maps_;
    bool ret = Unwind(&context, maxFrameNum, skipFrameNum);
    LOGI("tid: %d, ret: %d", tid, ret);
    return ret;
}

#if defined(ENABLE_MIXSTACK)
bool Unwinder::StepArkJsFrame(uintptr_t& pc, uintptr_t& fp, uintptr_t& sp)
{
    const size_t JSFRAME_MAX = 64;
    JsFrame jsFrames[JSFRAME_MAX];
    size_t size = JSFRAME_MAX;
    if (memset_s(jsFrames, sizeof(JsFrame) * JSFRAME_MAX, 0, sizeof(JsFrame) * JSFRAME_MAX) != 0) {
        LOGE("%s", "Failed to memset_s jsFrames.");
        return false;
    }
    LOGI("+++ark pc: %" PRIx64 ", fp: %" PRIx64 ", sp: %" PRIx64 ".", (uint64_t)pc, (uint64_t)fp, (uint64_t)sp);
    int32_t pid = pid_;
    if (pid_ == UNWIND_TYPE_LOCAL) {
        pid = getpid();
    }
    if (DfxArk::GetArkNativeFrameInfo(pid, pc, fp, sp, jsFrames, size) < 0) {
        return false;
    }
    LOGI("---ark pc: %" PRIx64 ", fp: %" PRIx64 ", sp: %" PRIx64 ", js frame size: %zu.",
        (uint64_t)pc, (uint64_t)fp, (uint64_t)sp, size);

    if (!ignoreMixstack_) {
        for (size_t i = 0; i < size; ++i) {
            DfxFrame frame;
            frame.isJsFrame = true;
            frame.index = frames_.size();
            frame.mapName = std::string(jsFrames[i].url);
            frame.funcName = std::string(jsFrames[i].functionName);
            frame.line = jsFrames[i].line;
            frame.column = jsFrames[i].column;
            AddFrame(frame);
        }
    }
    return true;
}

bool Unwinder::StepArkJsFrame(uintptr_t& pc, uintptr_t& fp, uintptr_t& sp, bool& isJsFrame)
{
    if (pid_ != UNWIND_TYPE_CUSTOMIZE) {
        LOGI("+++ark pc: %" PRIx64 ", fp: %" PRIx64 ", sp: %" PRIx64 ", isJsFrame: %d.",
            (uint64_t)pc, (uint64_t)fp, (uint64_t)sp, isJsFrame);
    }
    if (pid_ == UNWIND_TYPE_LOCAL) {
        if (DfxArkLocal::StepArkFrame(memory_.get(), &(Unwinder::AccessMem), &fp, &sp, &pc, &isJsFrame) < 0) {
            LOGE("Failed to step ark Js frames, fp: %" PRIx64 " ,pc: %" PRIx64, (uint64_t)fp, (uint64_t)pc);
            return false;
        }
    } else {
        if (DfxArk::StepArkFrame(memory_.get(), &(Unwinder::AccessMem), &fp, &sp, &pc, &isJsFrame) < 0) {
            LOGE("Failed to step ark Js frames, fp: %" PRIx64 " ,pc: %" PRIx64, (uint64_t)fp, (uint64_t)pc);
            return false;
        }
    }
    if (pid_ != UNWIND_TYPE_CUSTOMIZE) {
        LOGI("---ark pc: %" PRIx64 ", fp: %" PRIx64 ", sp: %" PRIx64 ", isJsFrame: %d.",
            (uint64_t)pc, (uint64_t)fp, (uint64_t)sp, isJsFrame);
    }
    return true;
}
#endif

bool Unwinder::Unwind(void *ctx, size_t maxFrameNum, size_t skipFrameNum)
{
    if ((regs_ == nullptr) || (!CheckAndReset(ctx))) {
        LOGE("%s", "params is nullptr?");
        lastErrorData_.SetCode(UNW_ERROR_INVALID_CONTEXT);
        return false;
    }
    SetLocalStackCheck(ctx, false);
    Clear();

    bool needAdjustPc = false;
    bool resetFrames = false;
    bool isJsFrame = false;
    do {
        if (!resetFrames && (skipFrameNum != 0) && (frames_.size() >= skipFrameNum)) {
            resetFrames = true;
            LOGU("frames size: %zu, will be reset frames", frames_.size());
            frames_.clear();
        }
        if (frames_.size() >= maxFrameNum) {
            LOGW("frames size: %zu", frames_.size());
            lastErrorData_.SetCode(UNW_ERROR_MAX_FRAMES_EXCEEDED);
            break;
        }

        uintptr_t pc = regs_->GetPc();
        uintptr_t sp = regs_->GetSp();
        // Check if this is a signal frame.
        if (pid_ != UNWIND_TYPE_LOCAL && regs_->StepIfSignalFrame(static_cast<uintptr_t>(pc), memory_)) {
            LOGW("Step signal frame, pc: %p", reinterpret_cast<void *>(pc));
            StepInner(true, isJsFrame, pc, sp, ctx);
            continue;
        }

        if (pid_ != UNWIND_TYPE_CUSTOMIZE) {
            if (needAdjustPc) {
                DoPcAdjust(pc);
            }
            needAdjustPc = true;
        }

        uintptr_t prevPc = pc;
        uintptr_t prevSp = sp;
        if (!StepInner(false, isJsFrame, pc, sp, ctx)) {
            break;
        }

        if (pc == prevPc && sp == prevSp) {
            if (pid_ >= 0) {
                MAYBE_UNUSED UnwindContext* uctx = reinterpret_cast<UnwindContext *>(ctx);
                LOGU("pc and sp is same, tid: %d", uctx->pid);
            } else {
                LOGU("%s", "pc and sp is same");
            }
            lastErrorData_.SetAddrAndCode(pc, UNW_ERROR_REPEATED_FRAME);
            break;
        }
    } while (true);
    LOGU("Last error code: %d, addr: %p", (int)GetLastErrorCode(), reinterpret_cast<void *>(GetLastErrorAddr()));
    LOGU("Last frame size: %zu, last frame pc: %p", frames_.size(), reinterpret_cast<void *>(regs_->GetPc()));
    return (frames_.size() > 0);
}

bool Unwinder::UnwindByFp(void *ctx, size_t maxFrameNum, size_t skipFrameNum)
{
    if (regs_ == nullptr) {
        LOGE("%s", "params is nullptr?");
        return false;
    }
    pcs_.clear();
    bool needAdjustPc = false;

    bool resetFrames = false;
    do {
        if (!resetFrames && skipFrameNum != 0 && (pcs_.size() == skipFrameNum)) {
            LOGU("pcs size: %zu, will be reset pcs", pcs_.size());
            resetFrames = true;
            pcs_.clear();
        }
        if (pcs_.size() >= maxFrameNum) {
            lastErrorData_.SetCode(UNW_ERROR_MAX_FRAMES_EXCEEDED);
            break;
        }

        uintptr_t pc = regs_->GetPc();
        uintptr_t fp = regs_->GetFp();
        if (needAdjustPc) {
            DoPcAdjust(pc);
        }
        needAdjustPc = true;
        pcs_.emplace_back(pc);

        if (!FpStep(fp, pc, ctx) || (pc == 0)) {
            break;
        }
    } while (true);
    return (pcs_.size() > 0);
}

bool Unwinder::FpStep(uintptr_t& fp, uintptr_t& pc, void *ctx)
{
#if defined(__aarch64__)
    LOGU("+fp: %lx, pc: %lx", (uint64_t)fp, (uint64_t)pc);
    if ((regs_ == nullptr) || (memory_ == nullptr)) {
        LOGE("%s", "params is nullptr");
        return false;
    }
    if (ctx != nullptr) {
        memory_->SetCtx(ctx);
    }

    uintptr_t prevFp = fp;
    uintptr_t ptr = fp;
    if (memory_->ReadUptr(ptr, &fp, true) &&
        memory_->ReadUptr(ptr, &pc, false)) {
        if (fp == prevFp || fp == 0) {
            LOGW("-fp: %lx is same", (uint64_t)fp);
            return false;
        }
        regs_->SetReg(REG_FP, &fp);
        regs_->SetReg(REG_SP, &prevFp);
        regs_->SetPc(StripPac(pc, pacMask_));
        LOGU("-fp: %lx, pc: %lx", (uint64_t)fp, (uint64_t)pc);
        return true;
    }
#endif
    return false;
}

bool Unwinder::Step(uintptr_t& pc, uintptr_t& sp, void *ctx)
{
    if ((regs_  == nullptr) || (!CheckAndReset(ctx))) {
        LOGE("%s", "params is nullptr?");
        return false;
    }
    bool ret = false;
    bool isJsFrame = false;
    // Check if this is a signal frame.
    if (regs_->StepIfSignalFrame(pc, memory_)) {
        LOGW("Step signal frame, pc: %p", reinterpret_cast<void *>(pc));
        ret = StepInner(true, isJsFrame, pc, sp, ctx);
    } else {
        ret = StepInner(false, isJsFrame, pc, sp, ctx);
    }
    return ret;
}

bool Unwinder::StepInner(const bool isSigFrame, bool& isJsFrame, uintptr_t& pc, uintptr_t& sp, void *ctx)
{
    if ((regs_ == nullptr) || (!CheckAndReset(ctx))) {
        LOGE("%s", "params is nullptr");
        return false;
    }
    SetLocalStackCheck(ctx, false);
    MAYBE_UNUSED uintptr_t fp = regs_->GetFp();
    LOGU("+pc: %" PRIx64 ", sp: %" PRIx64 ", fp: %" PRIx64 "", (uint64_t)pc, (uint64_t)sp, (uint64_t)fp);

    std::shared_ptr<DfxMap> map = nullptr;
    MAYBE_UNUSED int mapRet = acc_->GetMapByPc(pc, map, ctx);
    if (mapRet != UNW_ERROR_NONE) {
        if (frames_.size() > 2) { //2, least 2 frame
            LOGE("Failed to get map, frames size: %zu", frames_.size());
            lastErrorData_.SetAddrAndCode(pc, mapRet);
            return false;
        }
    }
    AddFrame(isJsFrame, pc, sp, map);
    if (isSigFrame) {
        return true;
    }

#if defined(ENABLE_MIXSTACK)
    if (enableMixstack_) {
        if (map != nullptr && map->IsArkExecutable() && stopWhenArkFrame_) {
            LOGU("Stop by ark frame");
            return false;
        }
#if defined(ONLINE_MIXSTACK)
        if (map != nullptr && map->IsArkExecutable()) {
            if (!StepArkJsFrame(pc, fp, sp)) {
                LOGE("Failed to step ark Js frames, pc: %" PRIx64, (uint64_t)pc);
                lastErrorData_.SetAddrAndCode(pc, UNW_ERROR_STEP_ARK_FRAME);
                return false;
            }
            regs_->SetPc(pc);
            regs_->SetSp(sp);
            regs_->SetFp(fp);
        }
#else
        if ((map != nullptr && map->IsArkExecutable()) || isJsFrame) {
            if (!StepArkJsFrame(pc, fp, sp, isJsFrame)) {
                LOGE("Failed to step ark Js frames, pc: %" PRIx64, (uint64_t)pc);
                lastErrorData_.SetAddrAndCode(pc, UNW_ERROR_STEP_ARK_FRAME);
                return false;
            }
            regs_->SetPc(pc);
            regs_->SetSp(sp);
            regs_->SetFp(fp);
            return true;
        }
#endif
    }
#endif

    bool ret = false;
    std::shared_ptr<RegLocState> rs = nullptr;
    do {
        if (isFpStep_) {
            if (enableFpCheckMapExec_ && (map != nullptr && !map->IsMapExec())) {
                LOGE("%s", "Fp step check map is not exec");
                return false;
            }
            break;
        }

        if (enableCache_) {
            // 1. find cache rs
            auto iter = rsCache_.find(pc);
            if (iter != rsCache_.end()) {
                if (pid_ != UNWIND_TYPE_CUSTOMIZE) {
                    LOGU("Find rs cache, pc: %p", reinterpret_cast<void *>(pc));
                }
                rs = iter->second;
                ret = true;
                break;
            }
        }

        // 2. find unwind table and entry
        UnwindTableInfo uti;
        MAYBE_UNUSED int utiRet = acc_->FindUnwindTable(pc, uti, ctx);
        if (utiRet != UNW_ERROR_NONE) {
            lastErrorData_.SetAddrAndCode(pc, utiRet);
            LOGU("Failed to find unwind table ret: %d", utiRet);
            break;
        }

        // 3. parse instructions and get cache rs
        struct UnwindEntryInfo uei;
        rs = std::make_shared<RegLocState>();
#if defined(__arm__)
        if (!ret && uti.format == UNW_INFO_FORMAT_ARM_EXIDX) {
            if (!armExidx_->SearchEntry(pc, uti, uei)) {
                lastErrorData_.SetAddrAndCode(armExidx_->GetLastErrorAddr(), armExidx_->GetLastErrorCode());
                LOGE("%s", "Failed to search unwind entry?");
                break;
            }
            if (!armExidx_->Step((uintptr_t)uei.unwindInfo, rs)) {
                lastErrorData_.SetAddrAndCode(armExidx_->GetLastErrorAddr(), armExidx_->GetLastErrorCode());
                LOGU("%s", "Step exidx section error?");
            } else {
                ret = true;
            }
        }
#endif
        if (!ret && uti.format == UNW_INFO_FORMAT_REMOTE_TABLE) {
            if ((uti.isLinear == false && !dwarfSection_->SearchEntry(pc, uti, uei)) ||
                (uti.isLinear == true && !dwarfSection_->LinearSearchEntry(pc, uti, uei))) {
                lastErrorData_.SetAddrAndCode(dwarfSection_->GetLastErrorAddr(), dwarfSection_->GetLastErrorCode());
                LOGU("%s", "Failed to search unwind entry?");
                break;
            }
            memory_->SetDataOffset(uti.segbase);
            if (!dwarfSection_->Step(pc, (uintptr_t)uei.unwindInfo, rs)) {
                lastErrorData_.SetAddrAndCode(dwarfSection_->GetLastErrorAddr(), dwarfSection_->GetLastErrorCode());
                LOGU("%s", "Step dwarf section error?");
            } else {
                ret = true;
            }
        }

        if (ret && enableCache_) {
            // 4. update rs cache
            rsCache_.emplace(pc, rs);
            break;
        }
    } while (false);

    // 5. update regs and regs state
    SetLocalStackCheck(ctx, true);
    if (ret) {
#if defined(__arm__) || defined(__aarch64__)
        auto lr = *(regs_->GetReg(REG_LR));
#endif
        ret = Apply(regs_, rs);
#if defined(__arm__) || defined(__aarch64__)
        if (!ret && enableLrFallback_ && (frames_.size() == 1)) {
            regs_->SetPc(lr);
            ret = true;
            LOGW("%s", "Failed to apply first frame, lr fallback");
        }
#endif
    } else {
        if (enableLrFallback_ && (frames_.size() == 1) && regs_->SetPcFromReturnAddress(memory_)) {
            ret = true;
            LOGW("%s", "Failed to step first frame, lr fallback");
        }
    }

#if defined(__aarch64__)
    if (!ret && enableFpFallback_) {
        ret = FpStep(fp, pc, ctx);
        if (ret && !isFpStep_) {
            if (pid_ != UNWIND_TYPE_CUSTOMIZE) {
                LOGI("First enter fp step, pc: %p", reinterpret_cast<void *>(pc));
            }
            isFpStep_ = true;
        }
    }
#endif

    pc = regs_->GetPc();
    sp = regs_->GetSp();
    fp = regs_->GetFp();
    if (ret && (pc == 0)) {
        ret = false;
    }
    LOGU("-pc: %" PRIx64 ", sp: %" PRIx64 ", fp: %" PRIx64 ", ret: %d",
        (uint64_t)pc, (uint64_t)sp, (uint64_t)fp, ret);
    return ret;
}

bool Unwinder::Apply(std::shared_ptr<DfxRegs> regs, std::shared_ptr<RegLocState> rs)
{
    if (rs == nullptr || regs == nullptr) {
        return false;
    }

    uint16_t errCode = 0;
    bool ret = DfxInstructions::Apply(memory_, *(regs.get()), *(rs.get()), errCode);
    uintptr_t tmp = 0;
    auto sp = regs_->GetSp();
    if (ret && (!memory_->ReadUptr(sp, &tmp, false))) {
        errCode = UNW_ERROR_UNREADABLE_SP;
        ret = false;
    }
    if (!ret) {
        lastErrorData_.SetCode(errCode);
        LOGE("%s", "Failed to apply reg state");
    }

    regs->SetPc(StripPac(regs_->GetPc(), pacMask_));
    return ret;
}

void Unwinder::DoPcAdjust(uintptr_t& pc)
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

uintptr_t Unwinder::StripPac(uintptr_t inAddr, uintptr_t pacMask)
{
    uintptr_t outAddr = inAddr;
#if defined(__aarch64__)
    if (outAddr != 0) {
        if (pacMask != 0) {
            outAddr &= ~pacMask;
        } else {
            register uint64_t x30 __asm("x30") = inAddr;
            asm("hint 0x7" : "+r"(x30));
            outAddr = x30;
        }
        if (outAddr != inAddr) {
            LOGU("Strip pac in addr: %lx, out addr: %lx", (uint64_t)inAddr, (uint64_t)outAddr);
        }
    }
#endif
    return outAddr;
}

std::vector<DfxFrame>& Unwinder::GetFrames()
{
    if (enableFillFrames_) {
        FillFrames(frames_);
    }
    return frames_;
}

void Unwinder::AddFrame(bool isJsFrame, uintptr_t pc, uintptr_t sp, std::shared_ptr<DfxMap> map)
{
#if defined(OFFLINE_MIXSTACK)
    if (ignoreMixstack_ && isJsFrame) {
        return;
    }
#endif
    pcs_.emplace_back(pc);
    DfxFrame frame;
    frame.isJsFrame = isJsFrame;
    frame.index = frames_.size();
    frame.pc = static_cast<uint64_t>(pc);
    frame.sp = static_cast<uint64_t>(sp);
    frame.map = map;
    frames_.emplace_back(frame);
}

void Unwinder::AddFrame(DfxFrame& frame)
{
    frames_.emplace_back(frame);
}

void Unwinder::FillLocalFrames(std::vector<DfxFrame>& frames)
{
    if (frames.empty()) {
        return;
    }
    auto it = frames.begin();
    while (it != frames.end()) {
        if (dl_iterate_phdr(Unwinder::DlPhdrCallback, &(*it)) != 1) {
            // clean up frames after first invalid frame
            frames.erase(it, frames.end());
            break;
        }
        it++;
    }
}

void Unwinder::FillFrames(std::vector<DfxFrame>& frames)
{
    for (size_t i = 0; i < frames.size(); ++i) {
        auto& frame = frames[i];
        FillFrame(frame);
    }
}

void Unwinder::FillFrame(DfxFrame& frame)
{
    if (frame.map == nullptr) {
        frame.relPc = frame.pc;
        frame.mapName = "Not mapped";
        LOGU("%s", "Current frame is not mapped.");
        return;
    }
    frame.relPc = frame.map->GetRelPc(frame.pc);
    auto elf = frame.map->GetElf();
    if (elf == nullptr) {
#if defined(OFFLINE_MIXSTACK)
        LOGU("elf is null, try to fill js frame?");
        FillJsFrame(frame);
#endif
        return;
    }
    frame.mapName = frame.map->GetElfName();
    frame.mapOffset = frame.map->offset;
    LOGU("mapName: %s, mapOffset: %" PRIx64 "", frame.mapName.c_str(), frame.mapOffset);
    if (!DfxSymbols::GetFuncNameAndOffsetByPc(frame.relPc, elf, frame.funcName, frame.funcOffset)) {
        LOGU("Failed to get symbol, relPc: %" PRIx64 ", mapName: %s", frame.relPc, frame.mapName.c_str());
    }
    frame.buildId = elf->GetBuildId();
}

void Unwinder::FillJsFrame(DfxFrame& frame)
{
    if (frame.map == nullptr) {
        LOGU("%s", "Current js frame is not map.");
        return;
    }

    LOGU("Js frame pc: %" PRIx64 ", map name: %s", frame.pc, frame.map->name.c_str());
    auto hap = frame.map->GetHap();
    if (hap == nullptr) {
        LOGW("hap is null");
        return;
    }
    JsFunction jsFunction;
    if ((pid_ != UNWIND_TYPE_LOCAL) &&
        (!frame.map->name.empty()) && (EndsWith(frame.map->name, ".hap") || EndsWith(frame.map->name, ".hsp"))) {
        if (!hap->ParseHapFileData(frame.map->name)) {
            LOGW("Failed to parse hap file symbol, name: %s", frame.map->name.c_str());
            return;
        }
    } else {
        pid_t pid = pid_;
        if (pid_ == UNWIND_TYPE_LOCAL) {
            pid = getpid();
        }
        if (!hap->ParseHapMemData(pid, frame.map)) {
            LOGW("Failed to parse hap mem symbol, pid: %d", pid);
            return;
        }
    }

#if defined(OFFLINE_MIXSTACK)
    if (arkSymbolExtractorPtr_ == 0) {
        DfxArk::ArkCreateJsSymbolExtractor(&arkSymbolExtractorPtr_);
    }
#endif
    if (hap->abcDataPtr_ != nullptr && DfxArk::ParseArkFrameInfo(frame.pc, static_cast<uintptr_t>(frame.map->begin),
        hap->abcLoadOffset_, hap->abcDataPtr_.get(), hap->abcDataSize_, arkSymbolExtractorPtr_, &jsFunction) < 0) {
        LOGW("Failed to parse ark frame info: %s", frame.map->name.c_str());
        return;
    }
    if (hap->srcMapDataPtr_ != nullptr && DfxArk::TranslateArkFrameInfo(hap->srcMapDataPtr_.get(),
        hap->srcMapDataSize_, &jsFunction) < 0) {
        LOGU("Failed to translate ark frame info: %s", frame.map->name.c_str());
    }
    frame.mapName = std::string(jsFunction.url);
    frame.funcName = std::string(jsFunction.functionName);
    frame.line = jsFunction.line;
    frame.column = jsFunction.column;
    LOGU("Js frame mapName: %s, funcName: %s, line: %d, column: %d",
        frame.mapName.c_str(), frame.funcName.c_str(), frame.line, frame.column);
}

bool Unwinder::GetFrameByPc(uintptr_t pc, std::shared_ptr<DfxMaps> maps, DfxFrame &frame)
{
    frame.pc = static_cast<uint64_t>(StripPac(pc, 0));
    std::shared_ptr<DfxMap> map = nullptr;
    if ((maps == nullptr) || !maps->FindMapByAddr(pc, map) || map == nullptr) {
        LOGE("%s", "Find map error");
        return false;
    }

    frame.map = map;
    FillFrame(frame);
    return true;
}

void Unwinder::GetFramesByPcs(std::vector<DfxFrame>& frames, std::vector<uintptr_t> pcs)
{
    frames.clear();
    std::shared_ptr<DfxMap> map = nullptr;
    for (size_t i = 0; i < pcs.size(); ++i) {
        DfxFrame frame;
        frame.index = i;
        frame.pc = static_cast<uint64_t>(StripPac(pcs[i], 0));
        if ((map != nullptr) && map->Contain(frame.pc)) {
            LOGU("%s", "map had matched");
        } else {
            if ((maps_ == nullptr) || !maps_->FindMapByAddr(pcs[i], map) || (map == nullptr)) {
                LOGE("%s", "Find map error");
            }
        }
        frame.map = map;
        FillFrame(frame);
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
        LOGE("%s", "Find map is null");
        return false;
    }
    uint64_t relPc = map->GetRelPc(static_cast<uint64_t>(pc));
    auto elf = map->GetElf();
    if (elf == nullptr) {
        LOGE("%s", "Get elf is null");
        return false;
    }
    return DfxSymbols::GetFuncNameAndOffsetByPc(relPc, elf, funcName, funcOffset);
}

std::string Unwinder::GetFramesStr(const std::vector<DfxFrame>& frames)
{
    return DfxFrameFormatter::GetFramesStr(frames);
}

int Unwinder::DlPhdrCallback(struct dl_phdr_info *info, size_t size, void *data)
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
                LOGU("relPc: %" PRIx64 ", mapName: %s", frame->relPc, frame->mapName.c_str());
                return 1;
            }
        }
    }
    return 0;
}
} // namespace HiviewDFX
} // namespace OHOS
