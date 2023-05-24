/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include <cerrno>
#include <fstream>
#include <gtest/gtest.h>
#include <map>
#include <securec.h>
#include <string>
#include <sys/mman.h>
#include <thread>
#include <unistd.h>
#include <vector>

#include "dfx_test_util.h"
#include "directory_ex.h"

using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace HiviewDFX {
class FaultLoggerdSystemTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp();
    void TearDown();
};

void FaultLoggerdSystemTest::SetUpTestCase(void)
{
    chmod("/data/crasher_c", 0755); // 0755 : -rwxr-xr-x
    chmod("/data/crasher_cpp", 0755); // 0755 : -rwxr-xr-x
}

void FaultLoggerdSystemTest::TearDownTestCase(void)
{
}

void FaultLoggerdSystemTest::SetUp(void)
{
}

void FaultLoggerdSystemTest::TearDown(void)
{
}

namespace {
static const int CPPCRASH_FILENAME_MIN_LENGTH = 36; // 36 : length of /data/log/faultlog/temp/cppcrash-x-x
static const int SIGNAL_TEST_NUM = 50;
}

static pid_t ForkAndExecuteCrasher(const string& option, const CrasherType type)
{
    pid_t pid = fork();
    if (pid < 0) {
        GTEST_LOG_(ERROR) << "Fork failed";
        return pid;
    } else if (pid == 0) {
        if (type == CRASHER_C) {
            execl("/data/crasher_c", "crasher_c", option.c_str(), nullptr);
        } else {
            execl("/data/crasher_cpp", "crasher_cpp", option.c_str(), nullptr);
        }
    }

    GTEST_LOG_(INFO) << "forked pid:" << pid;
    constexpr time_t maxWaitingTime = 60; // 60 : 60s timeout
    time_t remainedTime = maxWaitingTime;
    while (remainedTime > 0) {
        time_t startTime = time(nullptr);
        int status = 0;
        waitpid(pid, &status, WNOHANG);
        if (WIFEXITED(status)) {
            break;
        }
        sleep(1);
        time_t duration = time(nullptr) - startTime;
        remainedTime = (remainedTime > duration) ? (remainedTime - duration) : 0;
    }
    return pid;
}

static pid_t TriggerCrasherAndGetFileName(const string& option, const CrasherType type, string& crashFileName,
                                          int waitSec = 1)
{
    auto pid = ForkAndExecuteCrasher(option, type);
    sleep(waitSec); // sleep for log generation
    crashFileName = GetCppCrashFileName(pid);
    return pid;
}

static bool CheckCountNum(const string& filePath, const pid_t& pid, const string& option)
{
    map<string, string> optionReasonMap = {
#if defined(__LP64__)
        { string("triSIGTRAP"), string("SIGILL") },
#else
        { string("triSIGTRAP"), string("SIGTRAP") },
#endif
        { string("triSIGILL"), string("SIGILL") },
        { string("triSIGSEGV"), string("SIGSEGV") },
        { string("MaxStack"), string("SIGSEGV") },
        { string("MaxMethod"), string("SIGSEGV") },
        { string("STACKOF"), string("SIGSEGV") },
        { string("OOM"), string("SIGABRT") },
    };
    string reason = option;
    auto iter = optionReasonMap.find(option);
    if (iter != optionReasonMap.end()) {
        GTEST_LOG_(INFO) << "optionReasonMap matched";
        reason = iter->second;
    }
    string log[] = {
        "Pid:" + to_string(pid), "Uid", ":crasher", reason, "Tid:", "#00", "Registers:", REGISTERS, "FaultStack:",
        "Maps:", "/crasher"
    };
    int minRegIdx = 6; // 6 : index of first REGISTERS - 1
    int expectNum = sizeof(log) / sizeof(log[0]);
    return CheckKeyWords(filePath, log, expectNum, minRegIdx) == expectNum;
}

static bool CheckCountNumAbort(const string& filePath, const pid_t& pid)
{
    string log[] = {
        "Pid:" + to_string(pid), "Uid", ":crasher", "SIGABRT", "LastFatalMessage:", "ABORT!", "Tid:", "#00",
        "Registers:", REGISTERS, "FaultStack:", "Maps:", "/crasher"
    };
    int minRegIdx = 8; // 8 : index of first REGISTERS - 1
    int expectNum = sizeof(log) / sizeof(log[0]);
    return CheckKeyWords(filePath, log, expectNum, minRegIdx) == expectNum;
}

static bool CheckCountNumPCZero(const string& filePath, const pid_t& pid)
{
    string log[] = {
        "Pid:" + to_string(pid), "Uid", ":crasher", "SIGSEGV", "Tid:", "#00", "Registers:", REGISTERS, "FaultStack:",
        "Maps:", "/crasher"
    };
    int minRegIdx = 6; // 6 : index of first REGISTERS - 1
    int expectNum = sizeof(log) / sizeof(log[0]);
    return CheckKeyWords(filePath, log, expectNum, minRegIdx) == expectNum;
}

static bool CheckCountNumOverStack(const string& filePath, const pid_t& pid)
{
    string log[] = {
        "Pid:" + to_string(pid), "Uid", ":crasher", "SIGSEGV", "Tid:", "#56", "Registers:", REGISTERS, "FaultStack:",
        "Maps:", "/crasher"
    };
    int minRegIdx = 6; // 6 : index of first REGISTERS - 1
    int expectNum = sizeof(log) / sizeof(log[0]);
    return CheckKeyWords(filePath, log, expectNum, minRegIdx) == expectNum;
}

static bool CheckCountNumMultiThread(const string& filePath, const pid_t& pid)
{
    string log[] = {
        "Pid:" + to_string(pid), "Uid", ":crasher", "SIGSEGV", "Tid:", "#00",
        "Registers:", REGISTERS, "FaultStack:", "Maps:",
        "/crasher"
    };
    int minRegIdx = 6; // 6 : index of first REGISTERS - 1
    int expectNum = sizeof(log) / sizeof(log[0]);
    return CheckKeyWords(filePath, log, expectNum, minRegIdx) == expectNum;
}

static string GetStackTop(void)
{
    ifstream spFile;
    spFile.open("/data/sp");
    string sp;
    spFile >> sp;
    spFile.close();
    int ret = remove("/data/sp");
    if (ret != 0) {
        printf("remove failed!");
    }
    int leftZero = REGISTER_FORMAT_LENGTH - sp.length();
    while (leftZero > 0) {
        sp = "0" + sp;
        leftZero--;
    }
    GTEST_LOG_(INFO) << "sp:" << sp;
    return sp;
}

static bool CheckCountNumStackTop(const string& filePath, const pid_t& pid)
{
    string log[] = {
        "Pid:" + to_string(pid), "Uid", ":crasher", "SIGSEGV", "Tid:", "#00", "Registers:", REGISTERS, "FaultStack:",
        "Maps:", "/crasher"
    };
    string sp = GetStackTop();
    for (auto& keyword : log) {
        if (keyword == "sp:") {
            keyword += sp;
        }
    }
    int minRegIdx = 6; // 6 : index of first REGISTERS - 1
    int expectNum = sizeof(log) / sizeof(log[0]);
    return CheckKeyWords(filePath, log, expectNum, minRegIdx) == expectNum;
}

/**
 * @tc.name: FaultLoggerdSystemTest001
 * @tc.desc: test C crasher application: SIGFPE
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest001: start.";
    string cmd = "SIGFPE";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "ProcessDfxRequestTest001 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest001: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest002
 * @tc.desc: test CPP crasher application: SIGFPE
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest002: start.";
    string cmd = "SIGFPE";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest002 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest002: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest003
 * @tc.desc: test C crasher application: SIGILL
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest003, TestSize.Level2)
{

    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest003: start.";
    string cmd = "SIGILL";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest003 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest003: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest004
 * @tc.desc: test CPP crasher application: SIGILL
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest004, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest004: start.";
    string cmd = "SIGILL";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest004 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest004: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest005
* @tc.desc: test C crasher application: triSIGILL
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest005, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest005: start.";
    string cmd = "triSIGILL";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest005 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest005: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest006
* @tc.desc: test CPP crasher application: triSIGILL
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest006, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest006: start.";
    string cmd = "triSIGILL";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest006 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest006: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest007
 * @tc.desc: test C crasher application: SIGSEGV
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest007, TestSize.Level2)
{

    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest007: start.";
    string cmd = "SIGSEGV";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest007 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest007: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest008
 * @tc.desc: test CPP crasher application: SIGSEGV
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest008, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest008: start.";
    string cmd = "SIGSEGV";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest008 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest008: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest009
* @tc.desc: test C crasher application: triSIGSEGV
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest009, TestSize.Level2)
{

    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest009: start.";
    string cmd = "triSIGSEGV";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest009 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest009: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest010
* @tc.desc: test CPP crasher application: triSIGSEGV
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest010, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest010: start.";
    string cmd = "triSIGSEGV";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest010 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest010: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest011
 * @tc.desc: test C crasher application: SIGTRAP
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest011, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest011: start.";
    string cmd = "SIGTRAP";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest011 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest011: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest012
 * @tc.desc: test CPP crasher application: SIGTRAP
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest012, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest012: start.";
    string cmd = "SIGTRAP";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest012 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest012: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest013
* @tc.desc: test C crasher application: triSIGTRAP
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest013, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest013: start.";
    string cmd = "triSIGTRAP";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest013 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest013: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest014
* @tc.desc: test CPP crasher application: triSIGTRAP
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest014, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest014: start.";
    string cmd = "triSIGTRAP";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest014 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest014: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest015
 * @tc.desc: test C crasher application: SIGABRT
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest015, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest015: start.";
    string cmd = "SIGABRT";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNumAbort(fileName, pid)) << "FaultLoggerdSystemTest015 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest015: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest016
 * @tc.desc: test CPP crasher application: SIGABRT
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest016, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest016: start.";
    string cmd = "SIGABRT";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNumAbort(fileName, pid)) << "FaultLoggerdSystemTest016 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest016: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest017
* @tc.desc: test C crasher application: triSIGABRT
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest017, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest017: start.";
    string cmd = "triSIGABRT";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNumAbort(fileName, pid)) << "FaultLoggerdSystemTest017 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest017: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest018
* @tc.desc: test CPP crasher application: triSIGABRT
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest018, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest018: start.";
    string cmd = "triSIGABRT";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNumAbort(fileName, pid)) << "FaultLoggerdSystemTest018 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest018: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest019
* @tc.desc: test C crasher application: SIGBUS
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest019, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest019: start.";
    string cmd = "SIGBUS";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest019 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest019: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest020
* @tc.desc: test CPP crasher application: SIGBUS
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest020, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest020: start.";
    string cmd = "SIGBUS";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest020 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest020: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest021
* @tc.desc: test C crasher application: MaxStack
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest021, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest021: start.";
    string cmd = "MaxStack";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest021 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest021: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest022
* @tc.desc: test CPPcrasher application: MaxStack
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest022, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest022: start.";
    string cmd = "MaxStack";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest022 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest022: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest023
* @tc.desc: test C crasher application: MaxMethod
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest023, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest023: start.";
    string cmd = "MaxMethod";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest023 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest023: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest024
* @tc.desc: test CPP crasher application: MaxMethod
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest024, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest024: start.";
    string cmd = "MaxMethod";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest024 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest024: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest025
* @tc.desc: test C crasher application: STACKOF
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest025, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest025: start.";
    string cmd = "STACKOF";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest025 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest025: end.";
}

/**
* @tc.name: FaultLoggerdSystemTest026
* @tc.desc: test CPP crasher application: STACKOF
* @tc.type: FUNC
*/
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest026, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest026: start.";
    string cmd = "STACKOF";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest026 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest026: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest027
 * @tc.desc: test CPP crasher application: OOM
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest027, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest027: start.";
    string cmd = "OOM";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest027 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest027: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest028
 * @tc.desc: test C crasher application: OOM
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest028, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest028: start.";
    string cmd = "OOM";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNum(fileName, pid, cmd)) << "FaultLoggerdSystemTest028 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest028: end.";
}
/**
 * @tc.name: FaultLoggerdSystemTest029
 * @tc.desc: test CPP crasher application: PCZero
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest029, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest029: start.";
    string cmd = "PCZero";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNumPCZero(fileName, pid)) << "FaultLoggerdSystemTest029 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest029: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest030
 * @tc.desc: test C crasher application: PCZero
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest030, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest030: start.";
    string cmd = "PCZero";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNumPCZero(fileName, pid)) << "FaultLoggerdSystemTest030 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest030: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest031
 * @tc.desc: test C crasher application: MTCrash
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest031, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest031: start.";
    string cmd = "MTCrash";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName, 2); // 2 : sleep 2s for waiting cppcrash file
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNumMultiThread(fileName, pid)) << "FaultLoggerdSystemTest031 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest031: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest032
 * @tc.desc: test CPP crasher application: MTCrash
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest032, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest032: start.";
    string cmd = "MTCrash";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName, 2); // 2 : sleep 2s for waiting cppcrash file
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNumMultiThread(fileName, pid)) << "FaultLoggerdSystemTest032 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest032: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest033
 * @tc.desc: test CPP crasher application: StackOver64
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest033, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest033: start.";
    string cmd = "StackOver64";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNumOverStack(fileName, pid)) << "FaultLoggerdSystemTest033 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest033: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest034
 * @tc.desc: test C crasher application: StackOver64
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest034, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest034: start.";
    string cmd = "StackOver64";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNumOverStack(fileName, pid)) << "FaultLoggerdSystemTest034 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest034: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest035
 * @tc.desc: test C crasher application: StackTop
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest035, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest035: start.";
    string cmd = "StackTop";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_C, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNumStackTop(fileName, pid)) << "FaultLoggerdSystemTest035 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest035: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest036
 * @tc.desc: test CPP crasher application: StackTop
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest036, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest036: start.";
    string cmd = "StackTop";
    string fileName;
    pid_t pid = TriggerCrasherAndGetFileName(cmd, CRASHER_CPP, fileName);
    GTEST_LOG_(INFO) << "test pid(" << pid << ")"  << " cppcrash file name : " << fileName;
    if (pid < 0 || fileName.size() < CPPCRASH_FILENAME_MIN_LENGTH) {
        GTEST_LOG_(ERROR) << "Trigger Crash Failed.";
        FAIL();
    }
    EXPECT_TRUE(CheckCountNumStackTop(fileName, pid)) << "FaultLoggerdSystemTest036 Failed";
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest036: end.";
}

/**
 * @tc.name: FaultLoggerdSystemTest101
 * @tc.desc: test C crasher application: 50 Abnormal signal
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest101, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest0009: start.";
    string clearTempFilesCmd = "rm -rf /data/log/faultlog/temp/*";
    system(clearTempFilesCmd.c_str());
    for (int i = 0; i < SIGNAL_TEST_NUM; i++) {
        system("/data/crasher_c CrashTest &");
    }
    sleep(10); // 10 : sleep for 10 seconds
    vector<string> files;
    OHOS::GetDirFiles("/data/log/faultlog/temp/", files);
    GTEST_LOG_(INFO) << files.size();
    EXPECT_EQ(files.size(), SIGNAL_TEST_NUM) << "FaultLoggerdSystemTest101 Failed";
}

static void CrashInChildThread()
{
    GTEST_LOG_(INFO) << "CrashInChildThread(): TID = " << gettid();
    raise(SIGSEGV);
}

static int RunInNewPidNs(void* arg)
{
    (void)arg;
    GTEST_LOG_(INFO) << "RunInNewPidNs(): PID = " << getpid();
    GTEST_LOG_(INFO) << "RunInNewPidNs(): TID = " << gettid();
    GTEST_LOG_(INFO) << "RunInNewPidNs(): PPID = " << getppid();
    thread childThread(CrashInChildThread);
    childThread.join();
    _exit(0);
}

/**
 * @tc.name: FaultLoggerdSystemTest102
 * @tc.desc: test crash in process with pid namespace
 * @tc.type: FUNC
 */
HWTEST_F(FaultLoggerdSystemTest, FaultLoggerdSystemTest102, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest102: start.";
    const int stackSz = 1024 * 1024 * 1024; // 1M
    void* cloneStack = mmap(nullptr, stackSz,
        PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, 1, 0);
    if (cloneStack == nullptr) {
        FAIL();
    }
    cloneStack = static_cast<void *>(static_cast<uint8_t *>(cloneStack) + stackSz - 1);
    int childPid = clone(RunInNewPidNs, cloneStack, CLONE_NEWPID | SIGCHLD, nullptr);
    if (childPid <= 0) {
        GTEST_LOG_(INFO) << "FaultLoggerdSystemTest102: Failed to clone new process. errno:" << errno;
        return;
    }
    // wait for log generation
    sleep(4); // 4 : sleep 4s
    string fileName = GetCppCrashFileName(childPid);
    EXPECT_NE(0, fileName.size());
    printf("PidNs Crash File:%s\n", fileName.c_str());
    string log[] = {
        "Pid:", "Uid", "SIGSEGV", "Tid:", "#00",
        "Registers:", REGISTERS, "FaultStack:", "Maps:"
    };
    int minRegIdx = 5; // 5 : index of first REGISTERS - 1
    int expectNum = sizeof(log) / sizeof(log[0]);
    int count = CheckKeyWords(fileName, log, expectNum, minRegIdx);
    EXPECT_EQ(count, expectNum);
    GTEST_LOG_(INFO) << "FaultLoggerdSystemTest102: end.";
}
} // namespace HiviewDFX
} // namespace OHOS