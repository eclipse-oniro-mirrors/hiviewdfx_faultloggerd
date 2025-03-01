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

#include "dfx_symbols.h"

#include <algorithm>
#include <cstdlib>
#include <cxxabi.h>
#ifdef RUSTC_DEMANGLE
#include <dlfcn.h>
#endif

#include "dfx_define.h"
#include "dfx_log.h"
#include "dfx_trace_dlsym.h"
#include "string_util.h"

namespace OHOS {
namespace HiviewDFX {
using RustDemangleFn = char*(*)(const char *);
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxSymbols"

const std::string LINKER_PREFIX = "__dl_";
const std::string LINKER_PREFIX_NAME = "[linker]";

#ifdef RUSTC_DEMANGLE
static std::mutex g_mutex;
static bool g_hasTryLoadRustDemangleLib = false;
static RustDemangleFn g_rustDemangleFn = nullptr;
#endif

#if defined(CJ_DEMANGLE) && defined (__LP64__)
using CJDemangleFn = char*(*)(const char *);
const std::string CJ_RTLIB_NAME = "libcangjie-runtime.so";
const std::string CJ_RTLIB_PATH = "/system/lib64/platformsdk/cjsdk/" + CJ_RTLIB_NAME;
static std::mutex g_cj_mutex;
static bool g_hasTryLoadCJDemangleLib = false;
static CJDemangleFn g_cjDemangleFn = nullptr;
#endif
}

#if defined(CJ_DEMANGLE) && defined(__LP64__)
bool DfxSymbols::FindCJDemangleFunction()
{
    if (g_hasTryLoadCJDemangleLib) {
        return (g_cjDemangleFn != nullptr);
    }

    g_hasTryLoadCJDemangleLib = true;

    Dl_namespace ns;
    dlns_get("cj_rom_sdk", &ns);
    void* cjDemangleLibHandle = dlopen_ns(&ns, CJ_RTLIB_NAME.c_str(), RTLD_LAZY | RTLD_NODELETE);
    if (cjDemangleLibHandle == nullptr) {
        cjDemangleLibHandle = dlopen(CJ_RTLIB_PATH.c_str(), RTLD_LAZY | RTLD_NODELETE);
        if (cjDemangleLibHandle == nullptr) {
            DFXLOGE("Failed to dlopen libcangjie-runtime.so, %{public}s", dlerror());
            return false;
        }
        g_cjDemangleFn = (CJDemangleFn)dlsym(cjDemangleLibHandle, "CJ_MRT_DemangleHandle");
        if (g_cjDemangleFn == nullptr) {
            DFXLOGE("Failed to dlsym CJ_MRT_DemangleHandle, %{public}s", dlerror());
            dlclose(cjDemangleLibHandle);
            return false;
        }
    } else {
        g_cjDemangleFn = (CJDemangleFn)dlsym(cjDemangleLibHandle, "CJ_MRT_DemangleHandle");
        if (g_cjDemangleFn == nullptr) {
            DFXLOGE("Failed to dlsym CJ_MRT_DemangleHandle, %{public}s", dlerror());
            return false;
        }
    }
    return true;
}
#endif

#ifdef RUSTC_DEMANGLE
bool DfxSymbols::FindRustDemangleFunction()
{
    if (g_hasTryLoadRustDemangleLib) {
        return (g_rustDemangleFn != nullptr);
    }

    g_hasTryLoadRustDemangleLib = true;
    void* rustDemangleLibHandle = dlopen("librustc_demangle.z.so", RTLD_LAZY | RTLD_NODELETE);
    if (rustDemangleLibHandle == nullptr) {
        DFXLOGW("Failed to dlopen librustc_demangle, %{public}s", dlerror());
        return false;
    }

    g_rustDemangleFn = (RustDemangleFn)dlsym(rustDemangleLibHandle, "rustc_demangle");
    if (g_rustDemangleFn == nullptr) {
        DFXLOGW("Failed to dlsym rustc_demangle, %{public}s", dlerror());
        dlclose(rustDemangleLibHandle);
        return false;
    }
    return true;
}
#endif

bool DfxSymbols::ParseSymbols(std::vector<DfxSymbol>& symbols, std::shared_ptr<DfxElf> elf, const std::string& filePath)
{
    if (elf == nullptr) {
        return false;
    }
    const auto &elfSymbols = elf->GetFuncSymbols();
    std::string symbolsPath = filePath;
    if (elf->GetBaseOffset() != 0) {
        symbolsPath += ("!" + elf->GetElfName());
    }
    for (const auto &elfSymbol : elfSymbols) {
        symbols.emplace_back(elfSymbol.value, elfSymbol.size,
            elfSymbol.nameStr, Demangle(elfSymbol.nameStr), symbolsPath);
    }
    return true;
}

bool DfxSymbols::AddSymbolsByPlt(std::vector<DfxSymbol>& symbols, std::shared_ptr<DfxElf> elf,
                                 const std::string& filePath)
{
    if (elf == nullptr) {
        return false;
    }
    ShdrInfo shdr;
    elf->GetSectionInfo(shdr, PLT);
    symbols.emplace_back(shdr.addr, shdr.size, PLT, filePath);
    return true;
}

bool DfxSymbols::GetFuncNameAndOffsetByPc(uint64_t relPc, std::shared_ptr<DfxElf> elf,
    std::string& funcName, uint64_t& funcOffset)
{
#if defined(__arm__)
    relPc = relPc | 1;
#endif
    ElfSymbol elfSymbol;
    if ((elf != nullptr) && elf->GetFuncInfo(relPc, elfSymbol)) {
        DFXLOGU("nameStr: %{public}s", elfSymbol.nameStr.c_str());
        funcName = Demangle(elfSymbol.nameStr);
        funcOffset = relPc - elfSymbol.value;
#if defined(__arm__)
        funcOffset &= ~1;
#endif
        DFXLOGU("Symbol relPc: %{public}" PRIx64 ", funcName: %{public}s, funcOffset: %{public}" PRIx64 "",
            relPc, funcName.c_str(), funcOffset);
        return true;
    }
    return false;
}

std::string DfxSymbols::Demangle(const std::string& buf)
{
    DFX_TRACE_SCOPED_DLSYM("Demangle");
    if ((buf.length() < 2) || (buf[0] != '_')) { // 2 : min buf length
        return buf;
    }

    std::string funcName;
    const char *bufStr = buf.c_str();
    if (StartsWith(buf, LINKER_PREFIX)) {
        bufStr += LINKER_PREFIX.size();
        funcName += LINKER_PREFIX_NAME;
    }

    int status = 0;
    char* demangledStr = nullptr;
    if (buf[1] == 'Z') {
        demangledStr = abi::__cxa_demangle(bufStr, nullptr, nullptr, &status);
    }
#ifdef RUSTC_DEMANGLE
    if (buf[1] == 'R') {
        std::lock_guard<std::mutex> lck(g_mutex);
        if (FindRustDemangleFunction()) {
            demangledStr = g_rustDemangleFn(bufStr);
        }
    }
#endif

#if defined(CJ_DEMANGLE) && defined(__LP64__)
    if ((buf[1] == 'C') && (demangledStr == nullptr)) {
        std::lock_guard<std::mutex> lck(g_cj_mutex);
        if (FindCJDemangleFunction()) {
            demangledStr = g_cjDemangleFn(bufStr);
        }
    }
#endif

    std::string demangleName;
    if (demangledStr != nullptr) {
        demangleName = std::string(demangledStr);
        std::free(demangledStr);
    } else {
        demangleName = std::string(bufStr);
    }
    funcName += demangleName;
    return funcName;
}
} // namespace HiviewDFX
} // namespace OHOS
