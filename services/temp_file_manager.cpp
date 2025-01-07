/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "temp_file_manager.h"

#include <bitset>
#include <chrono>

#ifndef is_ohos_lite
#include <cJSON.h>
#endif

#include <cmath>
#include <fcntl.h>
#include <fstream>
#include <map>
#include <memory>
#include <regex>
#include <sys/inotify.h>
#include <sys/stat.h>
#include <sys/timerfd.h>
#include <unistd.h>

#include "dfx_define.h"
#include "dfx_log.h"
#include "dfx_socket_request.h"
#include "dfx_trace.h"
#include "directory_ex.h"
#include "file_ex.h"

namespace OHOS {
namespace HiviewDFX {

namespace {
constexpr const char *const TEMP_FILE_MANAGER_TAG = "TEMP_FILE_MANAGER";
constexpr uint64_t SECONDS_TO_MILLISECONDS = 1000;

const SingleFileConfig* GetTargetFileConfig(const std::function<bool(const SingleFileConfig&)>& filter)
{
    const auto& fileConfigs = FaultLoggerConfig::GetInstance().GetTempFileConfig().singleFileConfigs;
    auto iter = std::find_if(fileConfigs.begin(), fileConfigs.end(), filter);
    return iter == fileConfigs.end() ? nullptr : iter.base();
}

uint64_t GetCurrentTime()
{
    using namespace std::chrono;
    return static_cast<uint64_t>(duration_cast<milliseconds>(system_clock::now().time_since_epoch()).count());
}

uint64_t GetFileSize(const std::string& filePath)
{
    struct stat statBuf{};
    if (stat(filePath.c_str(), &statBuf) == 0) {
        return statBuf.st_size;
    }
    return 0;
}

uint64_t GetTimeFromFileName(const std::string& fileName)
{
    constexpr int timeStrLen = 13;
    constexpr char timeStrSplit = '-';
    constexpr int decimal = 10;
    auto timeStr = fileName.substr(fileName.find_last_of(timeStrSplit) + 1, timeStrLen);
    uint64_t num = strtoull(timeStr.c_str(), nullptr, decimal);
    if (errno == ERANGE) {
        DFXLOGE("%{public}s :: invalid timeStr for file: %{public}s", TEMP_FILE_MANAGER_TAG, timeStr.c_str());
        return 0;
    }
    return num;
}

bool CreateFileDir(const std::string& filePath)
{
    if (access(filePath.c_str(), F_OK) == 0 || OHOS::ForceCreateDirectory(filePath)) {
        return true;
    }
    DFXLOGE("%{public}s :: failed to create dirs: %{public}s.", TEMP_FILE_MANAGER_TAG, filePath.c_str());
    return false;
}

bool RemoveTempFile(const std::string& filePath)
{
    if (access(filePath.c_str(), F_OK) != 0) {
        return true;
    }
    if (!OHOS::RemoveFile(filePath)) {
        DFXLOGE("%{public}s :: failed to remove file: %{public}s.", TEMP_FILE_MANAGER_TAG, filePath.c_str());
        return false;
    }
    DFXLOGI("%{public}s :: success to remove file: %{public}s.", TEMP_FILE_MANAGER_TAG, filePath.c_str());
    return true;
}


void RemoveTimeOutFileIfNeed(const SingleFileConfig& fileConfig, std::list<std::string>& tempFiles)
{
    if (fileConfig.fileExistTime < 0 || fileConfig.keepFileCount < 0 ||
        tempFiles.size() <= static_cast<size_t>(fileConfig.keepFileCount)) {
        return;
    }
    auto currentTime = GetCurrentTime();
    tempFiles.erase(std::remove_if(tempFiles.begin(), tempFiles.end(),
        [currentTime, &fileConfig](const std::string& tempFile) {
            auto fileCreateTime = GetTimeFromFileName(tempFile);
            if (fileCreateTime > currentTime ||
                (fileCreateTime + fileConfig.fileExistTime * SECONDS_TO_MILLISECONDS < currentTime)) {
                return RemoveTempFile(tempFile);
            }
            return false;
        }), tempFiles.end());
}

void ForceRemoveFileIfNeed(const SingleFileConfig& fileConfig, std::list<std::string>& tempFiles)
{
    if (fileConfig.maxFileCount < 0 || tempFiles.size() <= static_cast<size_t>(fileConfig.maxFileCount)) {
        return;
    }
    if (fileConfig.keepFileCount != 0) {
        tempFiles.sort([](std::string& lhs, const std::string& rhs) -> int {
            return GetTimeFromFileName(lhs) < GetTimeFromFileName(rhs);
        });
    }
    auto deleteNum = fileConfig.keepFileCount < 0 ? 1 : tempFiles.size() - fileConfig.keepFileCount;
    tempFiles.erase(std::remove_if(tempFiles.begin(), tempFiles.end(),
        [&deleteNum](const std::string& tempFile) {
            if (deleteNum > 0 && RemoveTempFile(tempFile)) {
                deleteNum--;
                return true;
            }
            return false;
        }), tempFiles.end());
}

uint64_t GetTempFiles(const SingleFileConfig& tempFileConfig, std::list<std::string>& tempFiles)
{
    std::vector<std::string> files;
    const auto& tempFilePath = FaultLoggerConfig::GetInstance().GetTempFileConfig().tempFilePath;
    OHOS::GetDirFiles(tempFilePath, files);
    uint64_t fileSize = 0;
    for (const auto& file : files) {
        if (file.find(tempFileConfig.fileNamePrefix, tempFilePath.size()) != std::string::npos) {
            fileSize += GetFileSize(file);
            tempFiles.emplace_back(file);
        }
    }
    return fileSize;
}

uint64_t GetTempFiles(std::map<const SingleFileConfig*, std::list<std::string>>& tempFilesMap)
{
    std::vector<std::string> files;
    const auto& tempFilePath = FaultLoggerConfig::GetInstance().GetTempFileConfig().tempFilePath;
    OHOS::GetDirFiles(tempFilePath, files);
    uint64_t fileSize = 0;
    for (const auto& file : files) {
        auto fileConfig = GetTargetFileConfig([&file, &tempFilePath](const SingleFileConfig& fileConfig) {
            return file.find(fileConfig.fileNamePrefix, tempFilePath.size()) != std::string::npos;
        });
        if (fileConfig == nullptr) {
            RemoveTempFile(file);
            continue;
        }
        fileSize += GetFileSize(file);
        tempFilesMap[fileConfig].emplace_back(file);
    }
    return fileSize;
}
}

TempFileManager::TempFileManager(EpollManager& epollManager) : epollManager_(epollManager) {}

int32_t& TempFileManager::GetTargetFileCount(int32_t type)
{
    auto iter = std::find_if(fileCounts_.begin(), fileCounts_.end(),
        [type] (const std::pair<int32_t, int32_t>& pair) {
            return pair.first == type;
        });
    if (iter == fileCounts_.end()) {
        fileCounts_.emplace_back(type, 0);
        return fileCounts_.back().second;
    }
    return iter->second;
}

bool TempFileManager::InitTempFileWatcher()
{
    auto& config = FaultLoggerConfig::GetInstance().GetTempFileConfig();
    auto tempFileWatcher = TempFileWatcher::CreateInstance(*this);
    if (tempFileWatcher == nullptr) {
        return false;
    }
    constexpr uint32_t watchEvent = IN_CLOSE_WRITE | IN_MOVE | IN_CREATE | IN_DELETE;
    if (!tempFileWatcher->AddWatchEvent(config.tempFilePath.c_str(), watchEvent)) {
        return false;
    }
    return epollManager_.AddListener(std::move(tempFileWatcher));
}

void TempFileManager::ClearBigFilesOnStart(bool isSizeOverLimit, std::list<std::string>& files)
{
    auto fileClearTime = FaultLoggerConfig::GetInstance().GetTempFileConfig().fileClearTimeAfterBoot;
    if (isSizeOverLimit || fileClearTime == 0) {
        std::for_each(files.begin(), files.end(), RemoveTempFile);
        files.clear();
    } else {
        auto tempFileRemover = TempFileRemover::CreateInstance(*this, fileClearTime);
        if (tempFileRemover) {
            std::for_each(files.begin(), files.end(), [&tempFileRemover](const std::string& filePath) {
                tempFileRemover->AddFiles(filePath);
            });
            epollManager_.AddListener(std::move(tempFileRemover));
        }
    }
}

void TempFileManager::ScanTempFilesOnStart()
{
    std::map<const SingleFileConfig*, std::list<std::string>> tempFilesMap;
    uint64_t filesSize = GetTempFiles(tempFilesMap);
    bool isOverLimit = filesSize > FaultLoggerConfig::GetInstance().GetTempFileConfig().maxTempFilesSize;
    for (auto& pair : tempFilesMap) {
        int32_t fileType = pair.first->type;
        if (fileType <= FaultLoggerType::JS_HEAP_LEAK_LIST && fileType >= FaultLoggerType::JS_HEAP_SNAPSHOT) {
            ClearBigFilesOnStart(isOverLimit, pair.second);
        }
        ForceRemoveFileIfNeed(*pair.first, pair.second);
        GetTargetFileCount(fileType) = static_cast<int32_t>(pair.second.size());
    }
}

bool TempFileManager::Init()
{
    auto& tempFilePath = FaultLoggerConfig::GetInstance().GetTempFileConfig().tempFilePath;
    if (tempFilePath.empty() || !CreateFileDir(tempFilePath)) {
        DFXLOGE("%{public}s :: invalid temp file path %{public}s", TEMP_FILE_MANAGER_TAG, tempFilePath.c_str());
        return false;
    }
    ScanTempFilesOnStart();
    return InitTempFileWatcher();
}

int32_t TempFileManager::CreateFileDescriptor(int32_t type, int32_t pid, int32_t tid, uint64_t time)
{
    const auto fileConfig = GetTargetFileConfig([type](const SingleFileConfig& fileConfig) {
        return fileConfig.type == type;
    });
    if (fileConfig == nullptr) {
        DFXLOGW("%{public}s :: failed to create fileDescriptor because of unknown file type for %{public}d",
            TEMP_FILE_MANAGER_TAG, type);
        return -1;
    }
    std::string ss = FaultLoggerConfig::GetInstance().GetTempFileConfig().tempFilePath + "/" +
        fileConfig->fileNamePrefix + "-" + std::to_string(pid);
    if (type == FaultLoggerType::JS_HEAP_SNAPSHOT || type == FaultLoggerType::JS_RAW_SNAPSHOT) {
        ss += "-" + std::to_string(tid);
    }
    ss += "-" + std::to_string(time == 0 ? std::chrono::duration_cast<std::chrono::milliseconds>\
(std::chrono::system_clock::now().time_since_epoch()).count() : time);
    if (type == FaultLoggerType::JS_RAW_SNAPSHOT) {
        ss += ".rawheap";
    }
    DFXLOGI("%{public}s :: create file for path(%{public}s).", TEMP_FILE_MANAGER_TAG, ss.c_str());
    int32_t fd = OHOS_TEMP_FAILURE_RETRY(open(ss.c_str(), O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP));
    if (fd < 0) {
        DFXLOGE("%{public}s :: Failed to create log file, errno(%{public}d)", TEMP_FILE_MANAGER_TAG, errno);
    }
    return fd;
}

#ifndef is_ohos_lite
std::list<std::pair<int32_t, int64_t>> TempFileManager::crashFileRecords_{};

void TempFileManager::ClearTimeOutRecords()
{
#ifdef FAULTLOGGERD_TEST
    constexpr int validTime = 1;
#else
    constexpr int validTime = 8;
#endif
    auto currentTime = time(nullptr);
    crashFileRecords_.remove_if([currentTime](const std::pair<int32_t, int32_t>& pair) {
        return pair.second + validTime <= currentTime;
    });
}

bool TempFileManager::CheckCrashFileRecord(int32_t pid)
{
    DFX_TRACE_SCOPED("CheckCrashFileRecord");
    ClearTimeOutRecords();
    auto iter = std::find_if(crashFileRecords_.begin(), crashFileRecords_.end(),
        [pid](const auto& record) {
            return record.first == pid;
        });
    return iter != crashFileRecords_.end();
}

void TempFileManager::RecordFileCreation(int32_t type, int32_t pid)
{
    ClearTimeOutRecords();
    if (type != FaultLoggerType::CPP_CRASH) {
        return;
    }
    auto iter = std::find_if(crashFileRecords_.begin(), crashFileRecords_.end(),
        [pid](const auto& record) {
            return record.first == pid;
        });
    if (iter != crashFileRecords_.end()) {
        iter->second = time(nullptr);
    } else {
        crashFileRecords_.emplace_back(pid, time(nullptr));
    }
}
#endif

std::unique_ptr<TempFileManager::TempFileWatcher> TempFileManager::TempFileWatcher::CreateInstance(
    TempFileManager& tempFileManager)
{
    int32_t watchFd = inotify_init();
    if (watchFd < 0) {
        DFXLOGE("%{public}s :: failed to init inotify fd: %{public}d.", TEMP_FILE_MANAGER_TAG, watchFd);
        return nullptr;
    }
    return std::unique_ptr<TempFileManager::TempFileWatcher>(new TempFileWatcher(tempFileManager, watchFd));
}

TempFileManager::TempFileWatcher::TempFileWatcher(TempFileManager& tempFileManager, int32_t fd)
    : EpollListener(fd), tempFileManager_(tempFileManager) {}

bool TempFileManager::TempFileWatcher::AddWatchEvent(const char* watchPath, uint32_t watchEvent)
{
    if (watchPath == nullptr) {
        return false;
    }
    if (inotify_add_watch(GetFd(), watchPath, watchEvent) < 0) {
        DFXLOGE("%{public}s :: failed to add watch for file: %{public}s.", TEMP_FILE_MANAGER_TAG, watchPath);
        return false;
    }
    return true;
}

void TempFileManager::TempFileWatcher::OnEventPoll()
{
    char eventBuf[512]{};
    auto readLen = static_cast<size_t>(OHOS_TEMP_FAILURE_RETRY(read(GetFd(), eventBuf, sizeof(eventBuf))));
    size_t eventPos = 0;
    while (readLen >= sizeof(inotify_event)) {
        auto *event = reinterpret_cast<inotify_event *>(eventBuf + eventPos);
        if (event->len > 0) {
            std::string fileName(event->name);
            auto fileConfig = GetTargetFileConfig([&fileName](const SingleFileConfig& fileConfig) {
                return fileName.find(fileConfig.fileNamePrefix) != std::string::npos;
            });
            std::string filePath = FaultLoggerConfig::GetInstance().GetTempFileConfig().tempFilePath + "/" + fileName;
            if (fileConfig == nullptr) {
                RemoveTempFile(filePath);
            } else {
                HandleEvent(event->mask, filePath, *fileConfig);
            }
        }
        auto eventSize = (sizeof(inotify_event) + event->len);
        readLen -= eventSize;
        eventPos += eventSize;
    }
}

void TempFileManager::TempFileWatcher::HandleEvent(uint32_t eventMask, const std::string& filePath,
    const SingleFileConfig& fileConfig)
{
    if (eventMask & IN_CREATE) {
        HandleFileCreate(filePath, fileConfig);
    }
    if (eventMask & (IN_MOVED_FROM | IN_DELETE)) {
        HandleFileDeleteOrMove(filePath, fileConfig);
    }
    if (eventMask & IN_CLOSE_WRITE) {
        HandleFileWrite(filePath, fileConfig);
    }
    if (eventMask & IN_MOVED_TO) {
        HandleFileCreate(filePath, fileConfig);
        HandleFileWrite(filePath, fileConfig);
    }
}

void TempFileManager::TempFileWatcher::HandleFileCreate(const std::string& filePath, const SingleFileConfig& fileConfig)
{
    int32_t currentFileCount = ++(tempFileManager_.GetTargetFileCount(fileConfig.type));
    DFXLOGD("%{public}s :: file %{public}s is created, currentFileCount: %{public}d, keepFileCount: %{public}d, "
            "maxFileCount: %{public}d, existTime %{public}d, overTimeDeleteType %{public}d",
            TEMP_FILE_MANAGER_TAG, filePath.c_str(), currentFileCount, fileConfig.keepFileCount,
            fileConfig.maxFileCount, fileConfig.fileExistTime, fileConfig.overTimeFileDeleteType);
    if (fileConfig.overTimeFileDeleteType == OverTimeFileDeleteType::ACTIVE) {
        auto tempFileRemover = TempFileRemover::CreateInstance(tempFileManager_, fileConfig.fileExistTime);
        if (tempFileRemover) {
            tempFileRemover->AddFiles(filePath);
            tempFileManager_.epollManager_.AddListener(std::move(tempFileRemover));
        }
    }
    if ((fileConfig.keepFileCount >= 0 && currentFileCount > fileConfig.keepFileCount) ||
        (fileConfig.maxFileCount >= 0 && currentFileCount > fileConfig.maxFileCount)) {
        std::list<std::string> files;
        GetTempFiles(fileConfig, files);
        RemoveTimeOutFileIfNeed(fileConfig, files);
        ForceRemoveFileIfNeed(fileConfig, files);
    }
}

void TempFileManager::TempFileWatcher::HandleFileDeleteOrMove(const std::string& filePath,
                                                              const SingleFileConfig& fileConfig)
{
    int32_t& currentFileCount = tempFileManager_.GetTargetFileCount(fileConfig.type);
    if (currentFileCount > 0) {
        currentFileCount--;
    }
    DFXLOGD("%{public}s :: file %{public}s is deleted or moved, currentFileCount: %{public}d",
            TEMP_FILE_MANAGER_TAG, filePath.c_str(), currentFileCount);
}

void TempFileManager::TempFileWatcher::HandleFileWrite(const std::string& filePath, const SingleFileConfig& fileConfig)
{
    if (fileConfig.maxSingleFileSize == 0 || access(filePath.c_str(), F_OK) != 0) {
        return;
    }
    if (GetFileSize(filePath) <= fileConfig.maxSingleFileSize) {
        return;
    }
    DFXLOGW("%{public}s :: filesize of: %{public}s is over limit %{public}" PRIu64,
            TEMP_FILE_MANAGER_TAG, filePath.c_str(), fileConfig.maxSingleFileSize);
    if (fileConfig.overFileSizeAction == OverFileSizeAction::DELETE) {
        RemoveTempFile(filePath);
    } else {
        truncate64(filePath.c_str(), static_cast<off64_t>(fileConfig.maxSingleFileSize));
    }
}

std::unique_ptr<TempFileManager::TempFileRemover> TempFileManager::TempFileRemover::CreateInstance(
    TempFileManager& tempFileManager, int32_t timeout)
{
    if (timeout <= 0) {
        return nullptr;
    }
    int timefd = timerfd_create(CLOCK_MONOTONIC, 0);
    if (timefd == -1) {
        DFXLOGE("%{public}s :: failed to create time fd, errno: %{public}d", TEMP_FILE_MANAGER_TAG, errno);
        return nullptr;
    }
    struct itimerspec timeOption{};
    timeOption.it_value.tv_sec = timeout;
    if (timerfd_settime(timefd, 0, &timeOption, nullptr) == -1) {
        close(timefd);
        DFXLOGE("%{public}s :: failed to set delay time for fd, errno: %{public}d.", TEMP_FILE_MANAGER_TAG, errno);
        return nullptr;
    }
    return std::unique_ptr<TempFileRemover>(new TempFileRemover(tempFileManager, timefd));
}

TempFileManager::TempFileRemover::TempFileRemover(TempFileManager& tempFileManager, int32_t fd)
    : EpollListener(fd), tempFileManager_(tempFileManager) {}

void TempFileManager::TempFileRemover::AddFiles(std::string fileName)
{
    tempFiles_.emplace_back(std::move(fileName));
}

void TempFileManager::TempFileRemover::OnEventPoll()
{
    uint64_t exp;
    auto ret = OHOS_TEMP_FAILURE_RETRY(read(GetFd(), &exp, sizeof(exp)));
    if (ret != sizeof(exp)) {
        DFXLOGE("%{public}s :: failed read time fd %{public}" PRId32, TEMP_FILE_MANAGER_TAG, GetFd());
    } else {
        std::for_each(tempFiles_.begin(), tempFiles_.end(), RemoveTempFile);
    }
    tempFileManager_.epollManager_.RemoveListener(GetFd());
}
}
}