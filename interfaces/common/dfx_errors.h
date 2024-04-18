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
#ifndef DFX_ERRORS_H
#define DFX_ERRORS_H

#include <cinttypes>

namespace OHOS {
namespace HiviewDFX {
/**
 * @brief Unwind error data
 */
struct UnwindErrorData {
    inline const uint16_t& GetCode() { return code_; }
    inline const uint64_t& GetAddr() { return addr_; }

    template <typename T1, typename T2>
    inline void SetAddrAndCode(T1 addr, T2 code)
    {
#ifdef DFX_UNWIND_ERROR
        addr_ = static_cast<uint64_t>(addr);
        code_ = static_cast<uint16_t>(code);
#endif
    }

    template <typename T>
    inline void SetCode(T code)
    {
#ifdef DFX_UNWIND_ERROR
        code_ = static_cast<uint16_t>(code);
#endif
    }

    template <typename T>
    inline void SetAddr(T addr)
    {
#ifdef DFX_UNWIND_ERROR
        addr_ = static_cast<uint64_t>(addr);
#endif
    }
private:
    uint16_t code_ = 0;
    uint64_t addr_ = 0;
};

/**
 * @brief Unwind error code
 */
enum UnwindErrorCode : uint16_t {
    /** No error */
    UNW_ERROR_NONE = 0,
    /** No unwind info */
    UNW_ERROR_NO_UNWIND_INFO,
    /** Pc Not in unwind info */
    UNW_ERROR_PC_NOT_IN_UNWIND_INFO,
    /** Invalid unwind context */
    UNW_ERROR_INVALID_CONTEXT,
    /** Invalid unwind memory */
    UNW_ERROR_INVALID_MEMORY,
    /** Invalid unwind regs */
    UNW_ERROR_INVALID_REGS,
    /** Invalid unwind map */
    UNW_ERROR_INVALID_MAP,
    /** Invalid unwind elf */
    UNW_ERROR_INVALID_ELF,
    /** Invalid unwind pid */
    UNW_ERROR_INVALID_PID,
    /** Reserved value */
    UNW_ERROR_RESERVED_VALUE,
    /** Illegal value */
    UNW_ERROR_ILLEGAL_VALUE,
    /** Illegal state */
    UNW_ERROR_ILLEGAL_STATE,
    /** unreadable sp */
    UNW_ERROR_UNREADABLE_SP,
    /** The last frame has the same pc/sp as the next frame */
    UNW_ERROR_REPEATED_FRAME,
    /** The last return address has the same */
    UNW_ERROR_RETURN_ADDRESS_SAME,
    /** The last return address undefined */
    UNW_ERROR_RETURN_ADDRESS_UNDEFINED,
    /** The number of frames exceed the total allowed */
    UNW_ERROR_MAX_FRAMES_EXCEEDED,
    /** arm exidx invalid alignment */
    UNW_ERROR_INVALID_ALIGNMENT,
    /** arm exidx invalid personality */
    UNW_ERROR_INVALID_PERSONALITY,
    /** arm exidx cant unwind */
    UNW_ERROR_CANT_UNWIND,
    /** arm exidx spare */
    UNW_ERROR_ARM_EXIDX_SPARE,
    /** arm exidx finish */
    UNW_ERROR_ARM_EXIDX_FINISH,
    /** Dwarf cfa invalid */
    UNW_ERROR_DWARF_INVALID_CFA,
    /** Dwarf fde invalid */
    UNW_ERROR_DWARF_INVALID_FDE,
    /** Dwarf instr invalid */
    UNW_ERROR_DWARF_INVALID_INSTR,
    /** step ark frame error */
    UNW_ERROR_STEP_ARK_FRAME,
    /** Unsupported qut reg */
    UNW_ERROR_UNSUPPORTED_QUT_REG,
    /** Unsupported version */
    UNW_ERROR_UNSUPPORTED_VERSION,
    /** Not support */
    UNW_ERROR_NOT_SUPPORT,
};

/**
 * @brief Quick unwind table file error code
 */
enum QutFileError : uint16_t {
    /** File not found */
    QUT_FILE_NONE = 0,
    /** File not init */
    QUT_FILE_NOT_INIT,
    /** File not warmed up */
    QUT_FILE_NOT_WARMEDUP,
    /** File load requesting */
    QUT_FILE_LOAD_REQUESTING,
    /** File open failed */
    QUT_FILE_OPEN_FILE_FAILED,
    /** File state error */
    QUT_FILE_FILE_STATE_ERROR,
    /** File too short */
    QUT_FILE_FILE_TOO_SHORT,
    /** File mmap failed */
    QUT_FILE_MMAP_FAILED,
    /** Version dismatched */
    QUT_FILE_QUTVERSION_NOT_MATCH,
    /** Archtecture not matched */
    QUT_FILE_ARCH_NOT_MATCH,
    /** File build id dismatched */
    QUT_FILE_BUILDID_NOT_MATCH,
    /** File length dismatched */
    QUT_FILE_FILE_LENGTH_NOT_MATCH,
    /** Insert new quick unwind table failed */
    QUT_FILE_INSERT_NEW_QUT_FAILED,
    /** Try invode request generete */
    QUT_FILE_TRY_INVOKE_REQUEST_GENERATE,
    /** File load failed */
    QUT_FILE_LOAD_FAILED,
};
} // namespace HiviewDFX
} // namespace OHOS
#endif
