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

#include "dfx_test_util.h"

#include <fstream>
#include <iostream>
#include <sstream>
#include <unistd.h>

#include "dfx_define.h"
#include <directory_ex.h>
#include "file_util.h"
#include <string_ex.h>
#include <sys/inotify.h>

namespace OHOS {
namespace HiviewDFX {
namespace {
#define EVENT_SIZE (sizeof(struct inotify_event))
#define EVENT_BUF_LEN (1024 * (EVENT_SIZE + 16))
const int BUF_LEN = 128;
}

std::string ExecuteCommands(const std::string& cmds)
{
    if (cmds.empty()) {
        return "";
    }
    FILE *procFileInfo = nullptr;
    std::string cmdLog = "";
    procFileInfo = popen(cmds.c_str(), "r");
    if (procFileInfo == nullptr) {
        perror("popen execute failed\n");
        return cmdLog;
    }
    char res[BUF_LEN] = { '\0' };
    while (fgets(res, sizeof(res), procFileInfo) != nullptr) {
        cmdLog += res;
    }
    pclose(procFileInfo);
    return cmdLog;
}

bool ExecuteCommands(const std::string& cmds, std::vector<std::string>& ress)
{
    if (cmds.empty()) {
        return false;
    }

    ress.clear();
    FILE *fp = nullptr;
    fp = popen(cmds.c_str(), "r");
    if (fp == nullptr) {
        perror("popen execute failed\n");
        return false;
    }

    char res[BUF_LEN] = { '\0' };
    while (fgets(res, sizeof(res), fp) != nullptr) {
        ress.push_back(std::string(res));
    }
    pclose(fp);
    return true;
}

int GetProcessPid(const std::string& processName)
{
    std::string cmd = "pidof " + processName;
    std::string pidStr = ExecuteCommands(cmd);
    int32_t pid = 0;
    std::stringstream pidStream(pidStr);
    pidStream >> pid;
    printf("the pid of process(%s) is %s \n", processName.c_str(), pidStr.c_str());
    return pid;
}

int LaunchTestHap(const std::string& abilityName, const std::string& bundleName)
{
    std::string launchCmd = "/system/bin/aa start -a " + abilityName + " -b " + bundleName;
    (void)ExecuteCommands(launchCmd);
    sleep(2); // 2 : sleep 2s
    return GetProcessPid(bundleName);
}

void StopTestHap(const std::string& bundleName)
{
    std::string stopCmd = "/system/bin/aa force-stop " + bundleName;
    (void)ExecuteCommands(stopCmd);
}

void InstallTestHap(const std::string& hapName)
{
    std::string installCmd = "bm install -p " + hapName;
    (void)ExecuteCommands(installCmd);
}

void UninstallTestHap(const std::string& bundleName)
{
    std::string uninstallCmd = "bm uninstall -n " + bundleName;
    (void)ExecuteCommands(uninstallCmd);
}

int CountLines(const std::string& fileName)
{
    std::ifstream readFile;
    readFile.open(fileName.c_str(), std::ios::in);
    if (readFile.fail()) {
        return 0;
    } else {
        int n = 0;
        std::string tmpuseValue;
        while (getline(readFile, tmpuseValue, '\n')) {
            n++;
        }
        readFile.close();
        return n;
    }
}

bool CheckProcessComm(int pid, const std::string& name)
{
    std::string cmd = "cat /proc/" + std::to_string(pid) + "/comm";
    std::string comm = ExecuteCommands(cmd);
    size_t pos = comm.find('\n');
    if (pos != std::string::npos) {
        comm.erase(pos, 1);
    }
    if (!strcmp(comm.c_str(), name.c_str())) {
        return true;
    }
    return false;
}

int CheckKeyWords(const std::string& filePath, std::string *keywords, int length, int minRegIdx)
{
    std::ifstream file;
    file.open(filePath.c_str(), std::ios::in);
    long lines = CountLines(filePath);
    std::vector<std::string> t(lines * 4); // 4 : max string blocks of one line
    int i = 0;
    int j = 0;
    std::string::size_type idx;
    int count = 0;
    int maxRegIdx = minRegIdx + REGISTERS_NUM + 1;
    while (!file.eof()) {
        file >> t.at(i);
        idx = t.at(i).find(keywords[j]);
        if (idx != std::string::npos) {
            if (minRegIdx != -1 && j > minRegIdx && // -1 : do not check register value
                j < maxRegIdx && t.at(i).size() < (REGISTER_FORMAT_LENGTH + 3)) { // 3 : register label length
                count--;
            }
            count++;
            j++;
            if (j == length) {
                break;
            }
            continue;
        }
        i++;
    }
    file.close();
    std::cout << "Matched keywords count: " << count << std::endl;
    if (j < length) {
        std::cout << "Not found keyword: " << keywords[j] << std::endl;
    }
    return count;
}

bool CheckLineMatch(const std::string& filePath, std::list<LineRule>& rules)
{
    std::ifstream logFile(filePath);
    if (!logFile.is_open()) {
        return false;
    }

    std::string line;
    while (std::getline(logFile, line)) {
        if (!logFile.good()) {
            break;
        }

        for (auto it = rules.begin(); it != rules.end(); /* no increment here */) {
            if (!std::regex_match(line, it->lineReg)) {
                ++it;
                continue;
            }

            it->needMatchCnt -= 1;
            if (it->needMatchCnt == 0) {
                it = rules.erase(it);
            }
            break;
        }

        if (rules.empty()) {
            break;
        }
    }
    if (!rules.empty()) {
        for (const auto& it : rules) {
            std::cout << "not match rule: " << it.regString << std::endl;
        }
        return false;
    }
    return true;
}

bool CheckContent(const std::string& content, const std::string& keyContent, bool checkExist)
{
    bool findKeyContent = false;
    if (content.find(keyContent) != std::string::npos) {
        findKeyContent = true;
    }

    if (checkExist && !findKeyContent) {
        printf("Failed to find: %s in %s\n", keyContent.c_str(), content.c_str());
        return false;
    }

    if (!checkExist && findKeyContent) {
        printf("Find: %s in %s\n", keyContent.c_str(), content.c_str());
        return false;
    }
    return true;
}

int GetKeywordsNum(const std::string& msg, std::string *keywords, int length)
{
    int count = 0;
    std::string::size_type idx;
    for (int i = 0; i < length; i++) {
        idx = msg.find(keywords[i]);
        if (idx != std::string::npos) {
            count++;
        }
    }
    return count;
}

int GetKeywordCount(const std::string& msg, const std::string& keyword)
{
    int count = 0;
    auto position = msg.find(keyword);
    while (position != std::string::npos) {
        ++count;
        position = msg.find(keyword, position + 1);
    }
    return count;
}

std::string GetDumpLogFileName(const std::string& prefix, const pid_t pid, const std::string& tempPath)
{
    std::string filePath = "";
    if (pid <= 0) {
        return filePath;
    }
    std::string fileNamePrefix = prefix + "-" + std::to_string(pid);
    std::vector<std::string> files;
    OHOS::GetDirFiles(tempPath, files);
    for (const auto& file : files) {
        if (file.find(fileNamePrefix) != std::string::npos) {
            filePath = file;
            break;
        }
    }
    return filePath;
}

std::string GetCppCrashFileName(const pid_t pid, const std::string& tempPath)
{
    return GetDumpLogFileName("cppcrash", pid, tempPath);
}

uint64_t GetSelfMemoryCount()
{
    std::string path = "/proc/self/smaps_rollup";
    std::string content;
    if (!OHOS::HiviewDFX::LoadStringFromFile(path, content)) {
        printf("Failed to load path content: %s\n", path.c_str());
        return 0;
    }

    std::vector<std::string> result;
    OHOS::SplitStr(content, "\n", result);
    auto iter = std::find_if(result.begin(), result.end(),
        [] (const std::string& str) {
            return str.find("Pss:") != std::string::npos;
        });
    if (iter == result.end()) {
        perror("Failed to find Pss.\n");
        return 0;
    }

    std::string pss = *iter;
    uint64_t retVal = 0;
    for (size_t i = 0; i < pss.size(); i++) {
        if (isdigit(pss[i])) {
            retVal = atoi(&pss[i]);
            break;
        }
    }
    return retVal;
}

uint32_t GetSelfMapsCount()
{
    std::string path = std::string(PROC_SELF_MAPS_PATH);
    std::string content;
    if (!OHOS::HiviewDFX::LoadStringFromFile(path, content)) {
        printf("Failed to load path content: %s\n", path.c_str());
        return 0;
    }

    std::vector<std::string> result;
    OHOS::SplitStr(content, "\n", result);
    return result.size();
}

uint32_t GetSelfFdCount()
{
    std::string path = "/proc/self/fd";
    std::vector<std::string> content;
    OHOS::GetDirFiles(path, content);
    return content.size();
}

void CheckResourceUsage(uint32_t fdCount, uint32_t mapsCount, uint64_t memCount)
{
    // check memory/fd/maps
    auto curFdCount = GetSelfFdCount();
    printf("AfterTest Fd New: %u\n", curFdCount);
    printf("Fd Old: %u\n", fdCount);

    auto curMapsCount = GetSelfMapsCount();
    printf("AfterTest Maps New: %u\n", curMapsCount);
    printf("Maps Old: %u\n", mapsCount);

    auto curMemSize = GetSelfMemoryCount();
    printf("AfterTest Memory New: %lu\n", static_cast<unsigned long>(curMemSize));
    printf("Memory Old: %lu\n", static_cast<unsigned long>(memCount));
}

std::string WaitCreateCrashFile(const std::string& prefix, pid_t pid, int retryCnt)
{
    std::string fileName;
    int fd = inotify_init();
    if (fd < 0) {
        return fileName;
    }
    int wd = inotify_add_watch(fd, TEMP_DIR, IN_CLOSE_WRITE);
    if (wd < 0) {
        close(fd);
        return fileName;
    }
    struct timeval timeoutVal;
    timeoutVal.tv_sec = 1;
    timeoutVal.tv_usec = 0;
    fd_set rfds;
    FD_ZERO(&rfds);
    FD_SET(fd, &rfds);
    std::string fileNamePrefix = prefix + "-" + std::to_string(pid);
    while (retryCnt > 0) {
        int ret = select(fd + 1, &rfds, nullptr, nullptr, &timeoutVal);
        retryCnt--;
        if (ret <= 0 || !FD_ISSET(fd, &rfds)) {
            FD_SET(fd, &rfds);
            continue;
        }
        char buffer[EVENT_BUF_LEN] = {0};
        int length = read(fd, buffer, EVENT_BUF_LEN);
        int eventCnt = 0;
        while (length > 0 && eventCnt < length) {
            struct inotify_event *event = reinterpret_cast<struct inotify_event*>(&buffer[eventCnt]);
            if ((event->len) && (event->mask & IN_CLOSE_WRITE) &&
                    strncmp(event->name, fileNamePrefix.c_str(), strlen(fileNamePrefix.c_str())) == 0) {
                fileName = TEMP_DIR;
                fileName.append(event->name);
                retryCnt = 0;
                break;
            }
            eventCnt += EVENT_SIZE + event->len;
        }
        FD_SET(fd, &rfds);
    }
    inotify_rm_watch(fd, wd);
    close(fd);
    if (fileName.empty()) {
        fileName = GetDumpLogFileName(prefix, pid, TEMP_DIR);
    }
    return fileName;
}

std::string WaitCreateFile(const std::string& folder, std::regex& reg, time_t timeOut)
{
    std::string fileName;
    int fd = inotify_init();
    if (fd < 0) {
        return fileName;
    }
    int wd = inotify_add_watch(fd, folder.c_str(), IN_CLOSE_WRITE);
    if (wd < 0) {
        close(fd);
        return fileName;
    }
    time_t end = time(nullptr) + timeOut;
    struct timeval timeoutVal;
    timeoutVal.tv_usec = 0;
    fd_set rfds;
    bool isRun = true;
    while (isRun) {
        FD_ZERO(&rfds);
        FD_SET(fd, &rfds);
        timeoutVal.tv_sec = end - time(nullptr);
        int ret = select(fd + 1, &rfds, nullptr, nullptr, &timeoutVal);
        if (ret <= 0 || !FD_ISSET(fd, &rfds)) {
            continue;
        }
        char buffer[EVENT_BUF_LEN] = {0};
        int length = read(fd, buffer, EVENT_BUF_LEN);
        int eventCnt = 0;
        while (length > 0 && eventCnt < length) {
            struct inotify_event *event = reinterpret_cast<struct inotify_event*>(&buffer[eventCnt]);
            if ((event->len) && (event->mask & IN_CLOSE_WRITE) && std::regex_match(event->name, reg)) {
                fileName = folder;
                fileName.append(event->name);
                isRun = false;
                break;
            }
            eventCnt += EVENT_SIZE + event->len;
        }
    }
    inotify_rm_watch(fd, wd);
    close(fd);
    return fileName;
}

bool CreatePipeFd(int (&fd)[2])
{
    if (pipe(fd) == -1) {
        return false;
    }
    return true;
}

void NotifyProcStart(int (&fd)[2])
{
    close(fd[0]);
    write(fd[1], "a", 1);
    close(fd[1]);
}

void WaitProcStart(int (&fd)[2])
{
    close(fd[1]);
    const size_t size = 10;
    char msg[size];
    read(fd[0], msg, sizeof(msg));
    close(fd[0]);
}

void CheckAndExit(bool hasFailure)
{
    if (hasFailure) {
        _exit(1);
    }
    _exit(0);
}

bool IsLinuxKernel()
{
    static bool isLinux = [] {
        std::string content;
        LoadStringFromFile("/proc/version", content);
        if (content.empty()) {
            return true;
        }
        if (content.find("Linux") != std::string::npos) {
            return true;
        }
        return false;
    }();
    return isLinux;
}
} // namespace HiviewDFX
} // namespace OHOS
