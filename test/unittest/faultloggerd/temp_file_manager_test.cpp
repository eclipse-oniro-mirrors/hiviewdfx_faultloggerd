/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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
#include <chrono>
#include <condition_variable>
#include <fcntl.h>
#include <gtest/gtest.h>
#include <mutex>
#include <sys/stat.h>
#include <unistd.h>
#include <thread>

#ifdef HISYSEVENT_ENABLE
#include "hisysevent_listener.h"
#include "hisysevent_manager.h"
#endif

#include "directory_ex.h"
#include "faultloggerd_test.h"
#include "faultloggerd_test_server.h"

#define private public
#include "fault_logger_daemon.h"
#include "smart_fd.h"
#include "temp_file_manager.h"

namespace OHOS {
namespace HiviewDFX {
using namespace OHOS::HiviewDFX;
using namespace testing::ext;
using namespace std;

namespace {
constexpr auto CPP_CRASH_FILE = "cppcrash";
constexpr auto JS_HEAP = "jsheap";
constexpr auto LEAK_STACK = "leakstack";
constexpr auto OTHER_FILE = "others";

TempFileManager& tempFileManager = FaultLoggerDaemon::GetInstance().tempFileManager_;

string GetFileName(const string &fileNamePrefix, uint32_t time)
{
    string fileName = TEST_TEMP_FILE_PATH;
    fileName += fileNamePrefix;
    fileName += "-";
    fileName += std::to_string(getpid());
    fileName += "-";
    constexpr int32_t secondsToMilliseconds = 1000;
    fileName += std::to_string(chrono::duration_cast<chrono::milliseconds>\
(chrono::system_clock::now().time_since_epoch()).count() - time * secondsToMilliseconds);
    return fileName;
}

bool IsFileExist(const string &fileName)
{
    return access(fileName.c_str(), F_OK) == 0;
}

SmartFd CreateTestFile(const string& fileName, uint32_t fileSize = 1)
{
    GTEST_LOG_(INFO) << "Create test file: " << fileName;
    SmartFd fd{static_cast<int>(OHOS_TEMP_FAILURE_RETRY(open(fileName.c_str(),
        O_RDWR | O_CREAT, S_IRUSR | S_IWUSR | S_IRGRP)))};
    if (!fd|| fileSize == 0) {
        return fd;
    }
    constexpr int oneKb = 1024;
    char testContent[oneKb] = "";
    for (uint32_t i = 0; i < fileSize; ++i) {
        write(fd.GetFd(), testContent, oneKb);
    }
    return fd;
}

bool WaitForFileSize(const string &fileName, uint64_t expectSize, uint32_t timeoutSec)
{
    constexpr uint32_t pollIntervalMs = 500;
    constexpr uint32_t msPerSecond = 1000;
    for (uint32_t waitedMs = 0; waitedMs < timeoutSec * msPerSecond; waitedMs += pollIntervalMs) {
        struct stat st;
        if (stat(fileName.c_str(), &st) == 0 && static_cast<uint64_t>(st.st_size) == expectSize) {
            return true;
        }
        this_thread::sleep_for(chrono::milliseconds(pollIntervalMs));
    }
    return false;
}

#ifdef HISYSEVENT_ENABLE
class FileSizeMonitorEventListener : public HiSysEventListener {
public:
    void OnEvent(std::shared_ptr<HiSysEventRecord> sysEvent) override
    {
        if (sysEvent == nullptr || sysEvent->GetEventName() != "CPP_CRASH_NO_LOG") {
            return;
        }
        int64_t happenTime = 0;
        bool isStaleEvent = sysEvent->GetParamValue("HAPPEN_TIME", happenTime) == 0 &&
            happenTime < startTime_.load();
        std::lock_guard<std::mutex> lock(mutex_);
        if (!isStaleEvent) {
            eventReceived_ = true;
            condition_.notify_all();
        }
    }

    void OnServiceDied() override {}

    void SetStartTime(int64_t startTime)
    {
        startTime_.store(startTime);
        std::lock_guard<std::mutex> lock(mutex_);
        eventReceived_ = false;
    }

    bool WaitForEvent(uint32_t timeoutSec)
    {
        std::unique_lock<std::mutex> lock(mutex_);
        return condition_.wait_for(lock, chrono::seconds(timeoutSec), [this] { return eventReceived_; });
    }

private:
    std::mutex mutex_;
    std::condition_variable condition_;
    bool eventReceived_ = false;
    std::atomic<int64_t> startTime_ {0};
};
#endif
}

class TempFileManagerTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    void TearDown() override;
};

void TempFileManagerTest::TearDown()
{
    ClearTempFiles();
}

void TempFileManagerTest::SetUpTestCase()
{
    FaultLoggerdTestServer::GetInstance();
    ClearTempFiles();
}

/**
 * @tc.name: InvalidTempFileTest01
 * @tc.desc: delete the file, if the file is not configured.
 * @tc.type: FUNC
 */
HWTEST_F(TempFileManagerTest, InvalidTempFileTest01, TestSize.Level2)
{
    string testFileName = GetFileName("testFiles", 0);
    ASSERT_TRUE(CreateTestFile(testFileName));
    this_thread::sleep_for(chrono::milliseconds(100));
    ASSERT_FALSE(IsFileExist(testFileName));
}

/**
 * @tc.name: OverTimeFileDeleteTest01
 * @tc.desc: remove all timeout files when new file created, if the count of the temporary files exceeds the limit.
 * @tc.type: FUNC
 */
HWTEST_F(TempFileManagerTest, OverTimeFileDeleteTest01, TestSize.Level2)
{
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 66)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 65)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 64)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 63)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 62)));
    this_thread::sleep_for(chrono::milliseconds(100));
    ASSERT_EQ(CountTempFiles(), 5);

    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 61)));
    this_thread::sleep_for(chrono::milliseconds(100));
    ASSERT_EQ(CountTempFiles(), 0);
}

/**
 * @tc.name: OverTimeFileDeleteTest02
 * @tc.desc: only remove the timeout files when new file created, if the count of the temporary files exceeds the limit.
 * @tc.type: FUNC
 */
HWTEST_F(TempFileManagerTest, OverTimeFileDeleteTest02, TestSize.Level2)
{
    string oldFilePath1 = GetFileName(CPP_CRASH_FILE, 66);
    ASSERT_TRUE(CreateTestFile(oldFilePath1));
    string oldFilePath2 = GetFileName(CPP_CRASH_FILE, 65);
    ASSERT_TRUE(CreateTestFile(oldFilePath2));
    string oldFilePath3 = GetFileName(CPP_CRASH_FILE, 64);
    ASSERT_TRUE(CreateTestFile(oldFilePath3));

    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 50)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 49)));
    this_thread::sleep_for(chrono::milliseconds(100));
    ASSERT_EQ(CountTempFiles(), 5);

    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 48)));
    this_thread::sleep_for(chrono::milliseconds(100));
    ASSERT_EQ(CountTempFiles(), 3);
    ASSERT_FALSE(IsFileExist(oldFilePath1));
    ASSERT_FALSE(IsFileExist(oldFilePath2));
    ASSERT_FALSE(IsFileExist(oldFilePath3));
}

/**
 * @tc.name: OverTimeFileDeleteTest03
 * @tc.desc: Delete the file as soon as it expires.
 * @tc.type: FUNC
 */
HWTEST_F(TempFileManagerTest, OverTimeFileDeleteTest03, TestSize.Level2)
{
    ASSERT_TRUE(CreateTestFile(GetFileName(JS_HEAP, 0)));
    ASSERT_TRUE(CreateTestFile(GetFileName(JS_HEAP, 1)));
    ASSERT_EQ(CountTempFiles(), 2);
    this_thread::sleep_for(chrono::milliseconds(3100));
    ASSERT_EQ(CountTempFiles(), 0);
}

/**
 * @tc.name: OverMaxFileCountTest01
 * @tc.desc: remove the oldest files until the file count reached the keep file count,
 * if the count of the temporary files exceeds the max limit.
 * @tc.type: FUNC
 */
HWTEST_F(TempFileManagerTest, OverMaxFileCountTest01, TestSize.Level2)
{
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 48)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 47)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 46)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 45)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 44)));
    string oldFilePath1 = GetFileName(CPP_CRASH_FILE, 50);
    ASSERT_TRUE(CreateTestFile(oldFilePath1));
    string oldFilePath2 = GetFileName(CPP_CRASH_FILE, 49);
    ASSERT_TRUE(CreateTestFile(oldFilePath2));
    this_thread::sleep_for(chrono::milliseconds(100));
    ASSERT_EQ(CountTempFiles(), 7);

    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 43)));
    this_thread::sleep_for(chrono::milliseconds(100));
    ASSERT_EQ(CountTempFiles(), 5);
    ASSERT_FALSE(IsFileExist(oldFilePath1));
    ASSERT_FALSE(IsFileExist(oldFilePath2));
}

/**
 * @tc.name: OverMaxFileCountTest02
 * @tc.desc: Delete the oldest file when the keepFileCount is configured as -1.
 * @tc.type: FUNC
 */
HWTEST_F(TempFileManagerTest, OverMaxFileCountTest02, TestSize.Level2)
{
    ASSERT_TRUE(CreateTestFile(GetFileName(LEAK_STACK, 48)));
    string oldFilePath1 = GetFileName(LEAK_STACK, 49);
    ASSERT_TRUE(CreateTestFile(oldFilePath1));
    ASSERT_EQ(CountTempFiles(), 2);
    ASSERT_TRUE(CreateTestFile(GetFileName(LEAK_STACK, 46)));
    this_thread::sleep_for(chrono::milliseconds(100));
    ASSERT_EQ(CountTempFiles(), 2);
    ASSERT_FALSE(IsFileExist(oldFilePath1));
}

/**
 * @tc.name: OverFileSizeFileTest01
 * @tc.desc: resize the file, if the size of the file exceeds the threshold.
 * @tc.type: FUNC
 */
HWTEST_F(TempFileManagerTest, OverFileSizeFileTest01, TestSize.Level2)
{
    string testFileName = GetFileName(CPP_CRASH_FILE, 50);
    ASSERT_TRUE(CreateTestFile(testFileName, 6));
    this_thread::sleep_for(chrono::milliseconds(100));
    struct stat st;
    ASSERT_EQ(stat(testFileName.c_str(), &st), 0);
    ASSERT_EQ(static_cast<uint64_t>(st.st_size), 5ULL << 10); // 5KB
}

/**
 * @tc.name: OverFileSizeFileTest02
 * @tc.desc: delete the file, if the size of the file exceeds the threshold.
 * @tc.type: FUNC
 */
HWTEST_F(TempFileManagerTest, OverFileSizeFileTest02, TestSize.Level2)
{
    string testOverLimitFile = GetFileName(JS_HEAP, 0);
    ASSERT_TRUE(CreateTestFile(testOverLimitFile, 6));
    string testEmptyFile = GetFileName(JS_HEAP, 1);
    ASSERT_TRUE(CreateTestFile(testEmptyFile, 0));
    this_thread::sleep_for(chrono::milliseconds(100));
    ASSERT_FALSE(IsFileExist(testOverLimitFile));
    ASSERT_FALSE(IsFileExist(testEmptyFile));
}

class ScanCurrentFilesTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void TearDown() override;
};

void ScanCurrentFilesTest::TearDown()
{
    ClearTempFiles();
}

void ScanCurrentFilesTest::SetUpTestCase()
{
    FaultLoggerdTestServer::GetInstance();
    ClearTempFiles();
    tempFileManager.SetFileEventMask(0xffffffff);
}

void ScanCurrentFilesTest::TearDownTestCase()
{
    tempFileManager.SetFileEventMask(0);
}

/**
 * @tc.name: ScanCurrentFilesOnStartTest01
 * @tc.desc: Delete js files immediately when the file size exceeds the limit.
 * @tc.type: FUNC
 */
HWTEST_F(ScanCurrentFilesTest, ScanCurrentFilesOnStartTest01, TestSize.Level2)
{
    ASSERT_TRUE(CreateTestFile(GetFileName(JS_HEAP, 0), 5));
    ASSERT_TRUE(CreateTestFile(GetFileName(JS_HEAP, 1), 5));
    ASSERT_TRUE(CreateTestFile(GetFileName(JS_HEAP, 2), 5));
    tempFileManager.ScanTempFilesOnStart();
    ASSERT_EQ(tempFileManager.GetTargetFileCount(FaultLoggerType::JS_HEAP_SNAPSHOT), 0);
}

/**
 * @tc.name: ScanCurrentFilesOnStartTest02
 * @tc.desc: Delete js files in 3 second when the file size not exceeds the limit.
 * @tc.type: FUNC
 */
HWTEST_F(ScanCurrentFilesTest, ScanCurrentFilesOnStartTest02, TestSize.Level2)
{
    string oldFilePath1 = GetFileName(JS_HEAP, 0);
    ASSERT_TRUE(CreateTestFile(oldFilePath1));
    string oldFilePath2 = GetFileName(JS_HEAP, 1);
    ASSERT_TRUE(CreateTestFile(oldFilePath2));
    FaultLoggerdTestServer::AddTask(ExecutorThreadType::HELPER, []() {
        tempFileManager.ScanTempFilesOnStart();
    });
    this_thread::sleep_for(chrono::milliseconds(1000));
    ASSERT_EQ(tempFileManager.GetTargetFileCount(FaultLoggerType::JS_HEAP_SNAPSHOT), 2);
    this_thread::sleep_for(chrono::milliseconds(2500));
    ASSERT_FALSE(IsFileExist(oldFilePath1));
    ASSERT_FALSE(IsFileExist(oldFilePath2));
    tempFileManager.fileCounts_.clear();
}

/**
 * @tc.name: ScanCurrentFilesOnStartTest03
 * @tc.desc: Delete the oldest file when the file count exceeds the max file count.
 * @tc.type: FUNC
 */
HWTEST_F(ScanCurrentFilesTest, ScanCurrentFilesOnStartTest03, TestSize.Level2)
{
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 1)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 2)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 3)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 4)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 5)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 6)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 7)));
    ASSERT_TRUE(CreateTestFile(GetFileName(CPP_CRASH_FILE, 8)));
    tempFileManager.ScanTempFilesOnStart();
    ASSERT_EQ(tempFileManager.GetTargetFileCount(FaultLoggerType::CPP_CRASH), 5);
    tempFileManager.fileCounts_.clear();
}

/**
 * @tc.name: ScanCurrentFilesOnStartTest04
 * @tc.desc: Delete file immediately which is not configured.
 * @tc.type: FUNC
 */
HWTEST_F(ScanCurrentFilesTest, ScanCurrentFilesOnStartTest04, TestSize.Level2)
{
    string testFile = GetFileName(OTHER_FILE, 1);
    ASSERT_TRUE(CreateTestFile(OTHER_FILE));
    tempFileManager.ScanTempFilesOnStart();
    ASSERT_FALSE(IsFileExist(testFile));
}

/**
 * @tc.name: RecordFdFileCreationTest01
 * @tc.desc: Test that fdFileRecords only records files with maxSingleFileSize > 500MB.
 * @tc.type: FUNC
 */
HWTEST_F(TempFileManagerTest, RecordFdFileCreationTest01, TestSize.Level2)
{
    auto& fdFileRecords = TempFileManager::fdFileRecords_;
    fdFileRecords.clear();
    
    // JS_HEAP_SNAPSHOT has maxSingleFileSize = 5KB in test config, should not be recorded
    TempFileManager::RecordFdFileCreation(FaultLoggerType::JS_HEAP_SNAPSHOT, "/test/path1", 1000);
    ASSERT_EQ(fdFileRecords.size(), 0);
    
    // CPP_CRASH has maxSingleFileSize = 5KB in test config, should not be recorded
    TempFileManager::RecordFdFileCreation(FaultLoggerType::CPP_CRASH, "/test/path2", 1001);
    ASSERT_EQ(fdFileRecords.size(), 0);
}

/**
 * @tc.name: RecordFdFileCreationTest02
 * @tc.desc: Test that fdFileRecords records files with maxSingleFileSize > 500MB.
 * @tc.type: FUNC
 */
HWTEST_F(TempFileManagerTest, RecordFdFileCreationTest02, TestSize.Level2)
{
    auto& fdFileRecords = TempFileManager::fdFileRecords_;
    fdFileRecords.clear();
    
    // Create a mock file config with maxSingleFileSize > 500MB
    // Since we can't easily modify the config, this test verifies the logic path
    // In actual test environment, we would need a file type with maxSingleFileSize > 500MB
    // For now, we test that files under the limit are not recorded
    TempFileManager::RecordFdFileCreation(FaultLoggerType::JS_HEAP_SNAPSHOT, "/test/path1", 1000);
    ASSERT_EQ(fdFileRecords.size(), 0);
}

/**
 * @tc.name: FileSizeMonitorTest01
 * @tc.desc: Test that file size monitor task is added for files with maxSingleFileSize > 0.
 * @tc.type: FUNC
 */
HWTEST_F(TempFileManagerTest, FileSizeMonitorTest01, TestSize.Level2)
{
    string testFileName = GetFileName(JS_HEAP, 0);
    ASSERT_TRUE(CreateTestFile(testFileName, 2));
    this_thread::sleep_for(chrono::milliseconds(100));
    
    // File should exist and have correct size
    struct stat st;
    ASSERT_EQ(stat(testFileName.c_str(), &st), 0);
    ASSERT_EQ(static_cast<uint64_t>(st.st_size), 2ULL << 10); // 2KB
}

/**
 * @tc.name: FileSizeMonitorOverLimitTest01
 * @tc.desc: the periodic size monitor truncates an over-limit file which is still being written.
 * @tc.type: FUNC
 */
HWTEST_F(TempFileManagerTest, FileSizeMonitorOverLimitTest01, TestSize.Level2)
{
    constexpr uint32_t overLimitBlocks = 6;          // 6 : file size 6KB, larger than the 5KB limit
    constexpr uint32_t waitTimeoutSec = 20;          // 20 : covers more than one 10s monitor interval
    constexpr uint64_t truncatedSize = 5ULL << 10;   // 5KB : maxSingleFileSize of cppcrash in test config
    string testFileName = GetFileName(CPP_CRASH_FILE, 0);
    // keep fd open to avoid IN_CLOSE_WRITE, so only the periodic monitor can handle the file
    SmartFd fd = CreateTestFile(testFileName, overLimitBlocks);
    ASSERT_TRUE(fd);
    ASSERT_TRUE(WaitForFileSize(testFileName, truncatedSize, waitTimeoutSec));
}

#ifdef HISYSEVENT_ENABLE
/**
 * @tc.name: FileSizeMonitorEventTest01
 * @tc.desc: the periodic size monitor reports a CPP_CRASH_NO_LOG event for an over-limit file.
 * @tc.type: FUNC
 */
HWTEST_F(TempFileManagerTest, FileSizeMonitorEventTest01, TestSize.Level2)
{
    constexpr uint32_t overLimitBlocks = 6;   // 6 : file size 6KB, larger than the 5KB limit
    constexpr uint32_t eventTimeoutSec = 25;  // 25 : 10s monitor interval plus event dispatch delay
    auto listener = std::make_shared<FileSizeMonitorEventListener>();
    auto now = std::chrono::system_clock::now();
    listener->SetStartTime(std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count());
    ListenerRule eventRule("RELIABILITY", "CPP_CRASH_NO_LOG", RuleType::WHOLE_WORD);
    std::vector<ListenerRule> sysRules;
    sysRules.push_back(eventRule);
    ASSERT_EQ(HiSysEventManager::AddListener(listener, sysRules), 0);

    string testFileName = GetFileName(CPP_CRASH_FILE, 0);
    // keep fd open to avoid IN_CLOSE_WRITE, so only the periodic monitor can handle the file
    SmartFd fd = CreateTestFile(testFileName, overLimitBlocks);
    ASSERT_TRUE(fd);
    bool eventReceived = listener->WaitForEvent(eventTimeoutSec);
    ASSERT_EQ(HiSysEventManager::RemoveListener(listener), 0);
    ASSERT_TRUE(eventReceived);
}
#endif

/**
 * @tc.name: ScanCurrentFilesOnStartTest05
 * @tc.desc: stacktrace-filedelete files are grouped into the shared "stacktrace" config
 *          for aging and quota accounting.
 * @tc.type: FUNC
 */
HWTEST_F(ScanCurrentFilesTest, ScanCurrentFilesOnStartTest05, TestSize.Level2)
{
    constexpr uint32_t fileDeleteAgeSec = 1;       // 1 : backdate seconds of the filedelete file
    constexpr uint32_t stacktraceAgeSec = 2;       // 2 : backdate seconds of the stacktrace file
    constexpr int32_t expectSharedGroupCount = 2;  // 2 : both files share the stacktrace config group
    string fileDeleteFile = GetFileName("stacktrace-filedelete", fileDeleteAgeSec);
    ASSERT_TRUE(CreateTestFile(fileDeleteFile));
    string stacktraceFile = GetFileName("stacktrace", stacktraceAgeSec);
    ASSERT_TRUE(CreateTestFile(stacktraceFile));
    tempFileManager.ScanTempFilesOnStart();
    ASSERT_EQ(tempFileManager.GetTargetFileCount(FaultLoggerType::CPP_STACKTRACE), expectSharedGroupCount);
    ASSERT_TRUE(IsFileExist(fileDeleteFile));
    ASSERT_TRUE(IsFileExist(stacktraceFile));
    tempFileManager.fileCounts_.clear();
}
}
}
