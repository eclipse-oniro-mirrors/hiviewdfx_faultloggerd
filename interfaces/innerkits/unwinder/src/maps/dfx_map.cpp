/*
 * Copyright (c) 2023-2025 Huawei Device Co., Ltd.
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

#include "dfx_map.h"

#include <algorithm>
#include <securec.h>
#if is_mingw
#include "dfx_nonlinux_define.h"
#else
#include <sys/mman.h>
#endif

#include "dfx_define.h"
#include "dfx_elf.h"
#include "dfx_hap.h"
#include "dfx_log.h"
#include "dfx_util.h"
#include "elf_factory_selector.h"
#include "string_util.h"

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxMap"

#if defined(is_ohos) && is_ohos
AT_ALWAYS_INLINE const char* SkipWhiteSpace(const char *cp)
{
    if (cp == nullptr) {
        return nullptr;
    }

    while (*cp == ' ' || *cp == '\t') {
        ++cp;
    }
    return cp;
}

AT_ALWAYS_INLINE const char* ScanHex(const char *cp, unsigned long &valp)
{
    cp = SkipWhiteSpace(cp);
    if (cp == nullptr) {
        return nullptr;
    }

    unsigned long cnt = 0;
    unsigned long val = 0;
    while (1) {
        unsigned long digit = *cp;
        if ((digit - '0') <= 9) { // 9 : max 9
            digit -= '0';
        } else if ((digit - 'a') < 6) { // 6 : 16 - 10
            digit -= 'a' - 10; // 10 : base 10
        } else if ((digit - 'A') < 6) { // 6 : 16 - 10
            digit -= 'A' - 10; // 10 : base 10
        } else {
            break;
        }
        val = (val << 4) | digit; // 4 : hex
        ++cnt;
        ++cp;
    }
    if (cnt == 0) {
        return nullptr;
    }

    valp = val;
    return cp;
}

AT_ALWAYS_INLINE const char* ScanDec(const char *cp, unsigned long &valp)
{
    cp = SkipWhiteSpace(cp);
    if (cp == nullptr) {
        return nullptr;
    }

    unsigned long cnt = 0;
    unsigned long digit = 0;
    unsigned long val = 0;
    while (1) {
        digit = *cp;
        if ((digit - '0') <= 9) { // 9 : max 9
            digit -= '0';
            ++cp;
        } else {
            break;
        }

        val = (10 * val) + digit; // 10 : base 10
        ++cnt;
    }
    if (cnt == 0) {
        return nullptr;
    }

    valp = val;
    return cp;
}

AT_ALWAYS_INLINE const char* ScanChar(const char *cp, char &valp)
{
    cp = SkipWhiteSpace(cp);
    if (cp == nullptr) {
        return nullptr;
    }

    valp = *cp;

    /* don't step over NUL terminator */
    if (*cp) {
        ++cp;
    }
    return cp;
}

AT_ALWAYS_INLINE const char* ScanString(const char *cp, char *valp, size_t size)
{
    cp = SkipWhiteSpace(cp);
    if (cp == nullptr) {
        return nullptr;
    }

    size_t i = 0;
    while (*cp != ' ' && *cp != '\t' && *cp != '\0') {
        if ((valp != nullptr) && (i < size - 1)) {
            valp[i++] = *cp;
        }
        ++cp;
    }
    if (i == 0 || i >= size) {
        return nullptr;
    }
    valp[i] = '\0';
    return cp;
}

AT_ALWAYS_INLINE bool PermsToProtsAndFlag(const char* permChs, const size_t sz, uint32_t& prots, uint32_t& flag)
{
    if (permChs == nullptr || sz < 4) { // 4 : min perms size
        return false;
    }

    size_t i = 0;
    if (permChs[i] == 'r') {
        prots |= PROT_READ;
    } else if (permChs[i] != '-') {
        return false;
    }
    i++;

    if (permChs[i] == 'w') {
        prots |= PROT_WRITE;
    } else if (permChs[i] != '-') {
        return false;
    }
    i++;

    if (permChs[i] == 'x') {
        prots |= PROT_EXEC;
    } else if (permChs[i] != '-') {
        return false;
    }
    i++;

    if (permChs[i] == 'p') {
        flag = MAP_PRIVATE;
    } else if (permChs[i] == 's') {
        flag = MAP_SHARED;
    } else {
        return false;
    }

    return true;
}
#endif
}

std::shared_ptr<DfxMap> DfxMap::Create(const std::string& vma)
{
    if (vma.empty()) {
        return nullptr;
    }
    auto map = std::make_shared<DfxMap>();
    if (!map->Parse(vma.c_str(), vma.size())) {
        DFXLOGW("Failed to parse map: %{public}s", vma.c_str());
        return nullptr;
    }
    return map;
}

bool DfxMap::Parse(const char* buf, size_t size)
{
#if defined(is_ohos) && is_ohos
    if (buf == nullptr || size == 0) {
        return false;
    }

    char permChs[5] = {0}; // 5 : rwxp
    char dash = 0;
    char colon = 0;
    unsigned long tmp = 0;
    const char *path = nullptr;
    const char* cp = buf;

    // 7658d38000-7658d40000 rw-p 00000000 00:00 0                              [anon:thread signal stack]
    /* scan: "begin-end perms offset major:minor inum path" */
    cp = ScanHex(cp, tmp);
    begin = static_cast<uint64_t>(tmp);
    cp = ScanChar(cp, dash);
    if (dash != '-') {
        return false;
    }
    cp = ScanHex(cp, tmp);
    end = static_cast<uint64_t>(tmp);
    cp = ScanString(cp, permChs, sizeof(permChs));
    if (!PermsToProtsAndFlag(permChs, sizeof(permChs), prots, flag)) {
        return false;
    }
    cp = ScanHex(cp, tmp);
    offset = static_cast<uint64_t>(tmp);
    cp = ScanHex(cp, tmp);
    major = static_cast<uint64_t>(tmp);
    cp = ScanChar(cp, colon);
    if (colon != ':') {
        return false;
    }
    cp = ScanHex(cp, tmp);
    minor = static_cast<uint64_t>(tmp);
    cp = ScanDec(cp, tmp);
    inode = static_cast<ino_t>(tmp);
    path = SkipWhiteSpace(cp);

    perms = std::string(permChs, sizeof(permChs));
    if (path != nullptr && path < buf + size - 1) { // Prevent null pointer dereference when using TrimAndDupStr
        TrimAndDupStr(path, name);
    }
    return true;
#else
    return false;
#endif
}

bool DfxMap::IsMapExec()
{
    if ((prots & PROT_EXEC) != 0) {
        return true;
    }
    return false;
}

bool DfxMap::IsArkExecutable()
{
    if (name.length() == 0) {
        return false;
    }

    if ((!StartsWith(name, "[anon:ArkTS Code")) && (!StartsWith(name, "/dev/zero")) && (!EndsWith(name, "stub.an"))) {
        return false;
    }

    if (!IsMapExec()) {
        DFXLOGU("Current ark map(%{public}s) is not exec", name.c_str());
        return false;
    }
    DFXLOGU("Current ark map: %{public}s", name.c_str());
    return true;
}

bool DfxMap::IsJsvmExecutable()
{
    if (name.empty()) {
        return false;
    }
    if (StartsWith(name, "[anon:JSVM_JIT")) {
        return true;
    }
    if (!EndsWith(name, "libv8_shared.so")) {
        return false;
    }

    if (!IsMapExec()) {
        DFXLOGU("Current jsvm map(%{public}s) is not exec", name.c_str());
        return false;
    }
    DFXLOGU("Current jsvm map: %{public}s", name.c_str());
    return true;
}

bool DfxMap::IsVdsoMap()
{
    if ((name == "[shmm]" || name == "[vdso]") && IsMapExec()) {
        return true;
    }
    return false;
}

uint64_t DfxMap::GetRelPc(uint64_t pc)
{
    if (GetElf() != nullptr) {
        return GetElf()->GetRelPc(pc, begin, offset);
    }
    if (prevMap != nullptr) {
        return (pc - prevMap->begin);
    }
    return (pc - begin + offset);
}

std::string DfxMap::ToString() const
{
    char buf[LINE_BUF_SIZE] = {0};
    std::string realMapName = UnFormatMapName(name);
    int ret = snprintf_s(buf, sizeof(buf), sizeof(buf) - 1, "%" PRIx64 "-%" PRIx64 " %s %08" PRIx64 " %s\n", \
        begin, end, perms.c_str(), offset, realMapName.c_str());
    if (ret <= 0) {
        DFXLOGE("%{public}s :: snprintf_s failed, line: %{public}d.", __func__, __LINE__);
    }
    return std::string(buf);
}

void DfxMap::PermsToProts(const std::string perms, uint32_t& prots, uint32_t& flag)
{
    // rwxp
    if (perms.find("r") != std::string::npos) {
        prots |= PROT_READ;
    }

    if (perms.find("w") != std::string::npos) {
        prots |= PROT_WRITE;
    }

    if (perms.find("x") != std::string::npos) {
        prots |= PROT_EXEC;
    }

    if (perms.find("p") != std::string::npos) {
        flag = MAP_PRIVATE;
    } else if (perms.find("s") != std::string::npos) {
        flag = MAP_SHARED;
    }
}

const std::shared_ptr<DfxHap> DfxMap::GetHap()
{
    if (hap == nullptr) {
        hap = std::make_shared<DfxHap>();
    }
    return hap;
}

const std::shared_ptr<DfxElf> DfxMap::GetElf(pid_t pid)
{
    if (elf == nullptr) {
        if (name.empty()) {
            DFXLOGE("Invalid map, name empty.");
            return nullptr;
        }
        auto elfFactory = ElfFactorySelector::Select(*this, pid);
        if (elfFactory != nullptr) {
            elf = elfFactory->Create();
        }
        if (elf != nullptr && !elf->IsValid()) {
            elf = nullptr;
        }
        DFXLOGU("GetElf name: %{public}s", name.c_str());
    }
    return elf;
}

std::string DfxMap::GetElfName()
{
    if (name.empty() || GetElf() == nullptr) {
        return name;
    }
    std::string soName = name;
    if (EndsWith(name, ".hap")) {
        soName.append("!" + elf->GetElfName());
    }
    return soName;
}

void DfxMap::FormatMapName(pid_t pid, std::string& mapName)
{
    if (pid <= 0 || pid == getpid()) {
        return;
    }
    // format sandbox file path, add '/proc/xxx/root' prefix
    if (StartsWith(mapName, "/data/storage/")) {
        mapName = "/proc/" + std::to_string(pid) + "/root" + mapName;
    }
}

std::string DfxMap::UnFormatMapName(const std::string& mapName)
{
    // unformat sandbox file path, drop '/proc/xxx/root' prefix
    if (StartsWith(mapName, "/proc/")) {
        auto startPos = mapName.find("/data/storage/");
        if (startPos != std::string::npos) {
            return mapName.substr(startPos);
        }
    }
    return mapName;
}

} // namespace HiviewDFX
} // namespace OHOS
