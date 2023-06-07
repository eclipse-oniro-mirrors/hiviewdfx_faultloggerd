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

#include "dfx_util.h"

#include <cctype>
#include <climits>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <securec.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/time.h>
#include <fcntl.h>
#include <pthread.h>
#include <unistd.h>
#include <dirent.h>
#include "dfx_define.h"
#include "dfx_log.h"

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002D11
#endif

#ifdef LOG_TAG
#undef LOG_TAG
#define LOG_TAG "DfxUtil"
#endif

namespace OHOS {
namespace HiviewDFX {
bool TrimAndDupStr(const std::string &source, std::string &str)
{
    if (source.empty()) {
        return false;
    }

    const char *begin = source.data();
    const char *end = begin + source.size();
    if (begin == end) {
        DFXLOG_ERROR("Source is empty");
        return false;
    }

    while ((begin < end) && isspace(*begin)) {
        begin++;
    }

    while ((begin < end) && isspace(*(end - 1))) {
        end--;
    }

    if (begin == end) {
        return false;
    }

    uint32_t maxStrLen = NAME_LEN;
    uint32_t offset = static_cast<uint32_t>(end - begin);
    if (maxStrLen > offset) {
        maxStrLen = offset;
    }

    str.assign(begin, maxStrLen);
    return true;
}

uint64_t GetTimeMilliSeconds(void)
{
    struct timespec ts;
    (void)clock_gettime(CLOCK_REALTIME, &ts);
    return ((uint64_t)ts.tv_sec * NUMBER_ONE_THOUSAND) + // 1000 : second to millisecond convert ratio
        (((uint64_t)ts.tv_nsec) / NUMBER_ONE_MILLION); // 1000000 : nanosecond to millisecond convert ratio
}

std::string GetCurrentTimeStr(uint64_t current)
{
    time_t now = time(nullptr);
    uint64_t millsecond = 0;
    const uint64_t ratio = NUMBER_ONE_THOUSAND;
    if (current > static_cast<uint64_t>(now)) {
        millsecond = current % ratio;
        now = static_cast<time_t>(current / ratio);
    }

    auto tm = std::localtime(&now);
    char seconds[128] = {0}; // 128 : time buffer size
    if (tm == nullptr || strftime(seconds, sizeof(seconds) - 1, "%Y-%m-%d %H:%M:%S", tm) == 0) {
        return "invalid timestamp\n";
    }

    char millBuf[256] = {0}; // 256 : milliseconds buffer size
    int ret = snprintf_s(millBuf, sizeof(millBuf), sizeof(millBuf) - 1,
        "%s.%03u\n", seconds, millsecond);
    if (ret <= 0) {
        return "invalid timestamp\n";
    }
    return std::string(millBuf, strlen(millBuf));
}

bool ReadDirFiles(const std::string& path, std::vector<std::string>& files)
{
    DIR *dir = opendir(path.c_str());
    if (dir == nullptr) {
        return false;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != nullptr) {
        // current dir OR parent dir
        if ((strcmp(ent->d_name, ".") == 0) || (strcmp(ent->d_name, "..") == 0)) {
            continue;
        }
        files.emplace_back(std::string(ent->d_name));
    }
    (void)closedir(dir);
    return (files.size() > 0);
}

bool ReadDirFilesByPid(const int& pid, std::vector<std::string>& files)
{
    char path[PATH_LEN] = {0};
    if (pid == getpid()) {
        if (snprintf_s(path, sizeof(path), sizeof(path) - 1, PROC_SELF_TASK_PATH) <= 0) {
            return false;
        }
    } else {
        if (snprintf_s(path, sizeof(path), sizeof(path) - 1, "/proc/%d/task", pid) <= 0) {
            return false;
        }
    }

    char realPath[PATH_MAX];
    if (!realpath(path, realPath)) {
        return false;
    }
    return ReadDirFiles(realPath, files);
}

bool VerifyFilePath(const std::string& filePath, const std::vector<const std::string>& validPaths)
{
    if (validPaths.size() == 0) {
        return true;
    }

    for (auto validPath : validPaths) {
        if (filePath.find(validPath) == 0) {
            return true;
        }
    }
    return false;
}

off_t GetFileSize(const int& fd)
{
    off_t fileSize = 0;
    if (fd >= 0) {
        struct stat fileStat;
        if (fstat(fd, &fileStat) == 0) {
            fileSize = fileStat.st_size;
        }
    }
    return fileSize;
}

int GetStackRange(uintptr_t& stackBottom, uintptr_t& stackTop)
{
    pthread_attr_t tattr;
    void *base = nullptr;
    size_t size = 0;
    pthread_getattr_np(pthread_self(), &tattr);
    int ret = pthread_attr_getstack(&tattr, &base, &size);
    stackBottom = reinterpret_cast<uintptr_t>(base);
    stackTop = reinterpret_cast<uintptr_t>(base) + size;
    return ret;
}
}   // namespace HiviewDFX
}   // namespace OHOS
