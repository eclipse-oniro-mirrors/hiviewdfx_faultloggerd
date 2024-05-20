/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>

#include <string>
#include <thread>
#include <vector>

#include <unistd.h>

#include "dfx_define.h"
#include "dfx_dump_catcher.h"
#include "dfx_json_formatter.h"
#include "dfx_test_util.h"
#include "faultloggerd_client.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace HiviewDFX {
class DumpCatcherInterfacesTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

static const int THREAD_ALIVE_TIME = 2;

static const int CREATE_THREAD_TIMEOUT = 300000;

static pid_t g_threadId = 0;

static pid_t g_processId = 0;

int g_testPid = 0;

void DumpCatcherInterfacesTest::SetUpTestCase()
{
    InstallTestHap("/data/FaultloggerdJsTest.hap");
    std::string testBundleName = TEST_BUNDLE_NAME;
    std::string testAbiltyName = testBundleName + ".MainAbility";
    g_testPid = LaunchTestHap(testAbiltyName, testBundleName);
}

void DumpCatcherInterfacesTest::TearDownTestCase()
{
    StopTestHap(TEST_BUNDLE_NAME);
    UninstallTestHap(TEST_BUNDLE_NAME);
}

void DumpCatcherInterfacesTest::SetUp()
{}

void DumpCatcherInterfacesTest::TearDown()
{}

static void TestFunRecursive(int recursiveCount)
{
    GTEST_LOG_(INFO) << "Enter TestFunRecursive recursiveCount:" << recursiveCount;
    if (recursiveCount <= 0) {
        GTEST_LOG_(INFO) << "start enter sleep" << gettid();
        sleep(THREAD_ALIVE_TIME);
        GTEST_LOG_(INFO) << "sleep end.";
    } else {
        TestFunRecursive(recursiveCount - 1);
    }
}

static void* CreateRecursiveThread(void *argv)
{
    g_threadId = gettid();
    GTEST_LOG_(INFO) << "create Recursive MultiThread " << gettid();
    TestFunRecursive(266); // 266: set recursive count to 266, used for dumpcatcher get stack info
    GTEST_LOG_(INFO) << "Recursive MultiThread thread sleep end.";
    return nullptr;
}

static int RecursiveMultiThreadConstructor(void)
{
    pthread_t thread;
    pthread_create(&thread, nullptr, CreateRecursiveThread, nullptr);
    pthread_detach(thread);
    usleep(CREATE_THREAD_TIMEOUT);
    return 0;
}

static void* CreateThread(void *argv)
{
    g_threadId = gettid();
    GTEST_LOG_(INFO) << "create MultiThread " << gettid();
    sleep(THREAD_ALIVE_TIME);
    GTEST_LOG_(INFO) << "create MultiThread thread sleep end.";
    return nullptr;
}

static int MultiThreadConstructor(void)
{
    pthread_t thread;
    pthread_create(&thread, nullptr, CreateThread, nullptr);
    pthread_detach(thread);
    usleep(CREATE_THREAD_TIMEOUT);
    return 0;
}

static void ForkMultiThreadProcess(void)
{
    int pid = fork();
    if (pid == 0) {
        MultiThreadConstructor();
        _exit(0);
    } else if (pid < 0) {
        GTEST_LOG_(INFO) << "ForkMultiThreadProcess fail. ";
    } else {
        g_processId = pid;
        GTEST_LOG_(INFO) << "ForkMultiThreadProcess success, pid: " << pid;
        usleep(CREATE_THREAD_TIMEOUT);
        GTEST_LOG_(INFO) << "ForkMultiThreadProcess success, thread id: " << g_threadId;
    }
}

/**
 * @tc.name: DumpCatcherInterfacesTest001
 * @tc.desc: test DumpCatchMultiPid API: multiPid{PID(accountmgr), PID(foundation)}
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest001: start.";
    std::string testProcess1 = "accountmgr";
    int testPid1 = GetProcessPid(testProcess1);
    GTEST_LOG_(INFO) << "testPid1:" << testPid1;
    std::string testProcess2 = "foundation";
    int testPid2 = GetProcessPid(testProcess2);
    GTEST_LOG_(INFO) << "testPid2:" << testPid2;
    std::vector<int> multiPid {testPid1, testPid2};
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchMultiPid(multiPid, msg);
    GTEST_LOG_(INFO) << ret;
    string log[] = {"Tid:", "Name:", "Tid:", "Name:"};
    log[0] = log[0] + std::to_string(testPid1);
    log[1] = log[1] + testProcess1;
    log[2] = log[2] + std::to_string(testPid2);
    log[3] = log[3] + testProcess2;
    int len = sizeof(log) / sizeof(log[0]);
    int count = GetKeywordsNum(msg, log, len);
    EXPECT_EQ(count, len) << msg << "DumpCatcherInterfacesTest001 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest001: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest002
 * @tc.desc: test DumpCatchMultiPid API: multiPid{0, 0}
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest002: start.";
    int testPid1 = 0;
    GTEST_LOG_(INFO) << "testPid1:" << testPid1;
    int testPid2 = 0;
    GTEST_LOG_(INFO) << "testPid2:" << testPid2;
    std::vector<int> multiPid {testPid1, testPid2};
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchMultiPid(multiPid, msg);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, false) << "DumpCatcherInterfacesTest002 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest002: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest003
 * @tc.desc: test DumpCatchMultiPid API: multiPid{-11, -11}
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest003, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest003: start.";
    int testPid1 = -11;
    GTEST_LOG_(INFO) << "testPid1:" << testPid1;
    int testPid2 = -11;
    GTEST_LOG_(INFO) << "testPid2:" << testPid2;
    std::vector<int> multiPid {testPid1, testPid2};
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchMultiPid(multiPid, msg);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, false) << "DumpCatcherInterfacesTest003 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest003: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest004
 * @tc.desc: test DumpCatchMultiPid API: multiPid{PID(accountmgr), 0}
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest004, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest004: start.";
    std::string testProcess = "accountmgr";
    int applyPid1 = GetProcessPid(testProcess);
    GTEST_LOG_(INFO) << "applyPid1:" << applyPid1;
    int applyPid2 = 0;
    GTEST_LOG_(INFO) << "applyPid2:" << applyPid2;
    std::vector<int> multiPid {applyPid1, applyPid2};
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchMultiPid(multiPid, msg);
    GTEST_LOG_(INFO) << ret;
    string log[] = { "Tid:", "Name:", "Failed" };
    log[0] = log[0] + std::to_string(applyPid1);
    log[1] = log[1] + "accountmgr";
    int len = sizeof(log) / sizeof(log[0]);
    int count = GetKeywordsNum(msg, log, len);
    EXPECT_EQ(count, len) << msg << "DumpCatcherInterfacesTest004 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest004: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest005
 * @tc.desc: test DumpCatchMultiPid API: multiPid{PID(accountmgr),PID(foundation),PID(systemui)}
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest005, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest005: start.";
    std::vector<string> testProcessName = { "accountmgr", "foundation", "com.ohos.systemui" };
    string matchProcessName[] = { "accountmgr", "foundation", "m.ohos.systemui" };
    std::vector<int> multiPid;
    std::vector<string> matchLog;
    int index = 0;
    for (string oneProcessName : testProcessName) {
        int testPid = GetProcessPid(oneProcessName);
        if (testPid == 0) {
            GTEST_LOG_(INFO) << "process:" << oneProcessName << " pid is empty, skip";
            index++;
            continue;
        }
        multiPid.emplace_back(testPid);
        matchLog.emplace_back("Tid:" + std::to_string(testPid));
        matchLog.emplace_back("Name:" + matchProcessName[index]);
        index++;
    }

    // It is recommended that the number of effective pids be greater than 1,
    // otherwise the testing purpose will not be achieved
    EXPECT_GT(multiPid.size(), 1) << "DumpCatcherInterfacesTest005 Failed";

    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchMultiPid(multiPid, msg);
    GTEST_LOG_(INFO) << "ret:" << ret;

    int matchLogCount = matchLog.size();
    auto matchLogArray = std::make_unique<string[]>(matchLogCount);
    index = 0;
    for (string info : matchLog) {
        matchLogArray[index] = info;
        index++;
    }
    int count = GetKeywordsNum(msg, matchLogArray.get(), matchLogCount);
    EXPECT_EQ(count, matchLogCount) << msg << "DumpCatcherInterfacesTest005 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest005: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest006
 * @tc.desc: test DumpCatchMultiPid API: multiPid{PID(accountmgr), -11}
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest006, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest006: start.";
    std::string testProcess = "accountmgr";
    int testPid1 = GetProcessPid(testProcess);
    GTEST_LOG_(INFO) << "applyPid1:" << testPid1;
    int testPid2 = -11;
    GTEST_LOG_(INFO) << "applyPid2:" << testPid2;
    std::vector<int> multiPid {testPid1, testPid2};
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchMultiPid(multiPid, msg);
    GTEST_LOG_(INFO) << ret;
    string log[] = { "Tid:", "Name:", "Failed"};
    log[0] = log[0] + std::to_string(testPid1);
    log[1] = log[1] + "accountmgr";
    int len = sizeof(log) / sizeof(log[0]);
    int count = GetKeywordsNum(msg, log, len);
    EXPECT_EQ(count, len) << msg << "DumpCatcherInterfacesTest006 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest006: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest007
 * @tc.desc: test DumpCatchMultiPid API: multiPid{9999, 9999}
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest007, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest007: start.";
    int applyPid = 9999;
    GTEST_LOG_(INFO) << "applyPid1:" << applyPid;
    std::vector<int> multiPid {applyPid, applyPid};
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchMultiPid(multiPid, msg);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, false) << "DumpCatcherInterfacesTest007 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest007: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest008
 * @tc.desc: test DumpCatchMultiPid API: multiPid{PID(accountmgr), 9999}
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest008, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest008: start.";
    std::string apply = "accountmgr";
    int applyPid1 = GetProcessPid(apply);
    GTEST_LOG_(INFO) << "applyPid1:" << applyPid1;
    int applyPid2 = 9999;
    GTEST_LOG_(INFO) << "applyPid2:" << applyPid2;
    std::vector<int> multiPid {applyPid1, applyPid2};
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchMultiPid(multiPid, msg);
    GTEST_LOG_(INFO) << ret;
    string log[] = { "Tid:", "Name:", "Failed"};
    log[0] = log[0] + std::to_string(applyPid1);
    log[1] = log[1] + apply;
    int len = sizeof(log) / sizeof(log[0]);
    int count = GetKeywordsNum(msg, log, len);
    EXPECT_EQ(count, len) << msg << "DumpCatcherInterfacesTest008 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest008: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest014
 * @tc.desc: test DumpCatchMix API: PID(test hap), TID(0)
 * @tc.type: FUNC
 * @tc.require: issueI5PJ9O
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest014, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest014: start.";
    if (g_testPid == 0) {
        GTEST_LOG_(ERROR) << "Failed to launch target hap.";
        return;
    }
    if (!CheckProcessComm(g_testPid, TRUNCATE_TEST_BUNDLE_NAME)) {
        GTEST_LOG_(ERROR) << "Error process comm";
        return;
    }
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchMix(g_testPid, 0, msg);
    GTEST_LOG_(INFO) << ret;
    string log[] = { "Tid:", "Name:", "#00", "/system/bin/appspawn", "Name:OS_DfxWatchdog" };
    log[0] += std::to_string(g_testPid);
    log[1] += TRUNCATE_TEST_BUNDLE_NAME;
    int len = sizeof(log) / sizeof(log[0]);
    int count = GetKeywordsNum(msg, log, len);
    EXPECT_EQ(count, len) << msg << "DumpCatcherInterfacesTest014 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest014: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest015
 * @tc.desc: test DumpCatchMix API: PID(test hap), TID(test hap main thread)
 * @tc.type: FUNC
 * @tc.require: issueI5PJ9O
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest015, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest015: start.";
    if (g_testPid == 0) {
        GTEST_LOG_(ERROR) << "Failed to launch target hap.";
        return;
    }
    if (!CheckProcessComm(g_testPid, TRUNCATE_TEST_BUNDLE_NAME)) {
        GTEST_LOG_(ERROR) << "Error process comm";
        return;
    }
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchMix(g_testPid, g_testPid, msg);
    GTEST_LOG_(INFO) << ret;
    string log[] = { "Tid:", "Name:", "#00", "/system/bin/appspawn"};
    log[0] += std::to_string(g_testPid);
    log[1] += TRUNCATE_TEST_BUNDLE_NAME;
    int len = sizeof(log) / sizeof(log[0]);
    int count = GetKeywordsNum(msg, log, len);
    GTEST_LOG_(INFO) << msg;
    EXPECT_EQ(count, len) << msg << "DumpCatcherInterfacesTest015 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest015: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest016
 * @tc.desc: test DumpCatchMix API: PID(test hap), TID(-1)
 * @tc.type: FUNC
 * @tc.require: issueI5PJ9O
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest016, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest016: start.";
    if (g_testPid == 0) {
        GTEST_LOG_(ERROR) << "Failed to launch target hap.";
        return;
    }
    if (!CheckProcessComm(g_testPid, TRUNCATE_TEST_BUNDLE_NAME)) {
        GTEST_LOG_(ERROR) << "Error process comm";
        return;
    }
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchMix(g_testPid, -1, msg);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, false) << "DumpCatcherInterfacesTest016 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest016: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest017
 * @tc.desc: test DumpCatchMix API: PID(-1), TID(-1)
 * @tc.type: FUNC
 * @tc.require: issueI5PJ9O
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest017, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest017: start.";
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchMix(-1, -1, msg);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, false) << "DumpCatcherInterfacesTest017 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest017: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest018
 * @tc.desc: test DumpCatchFd API: PID(getpid()), TID(gettid())
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest018, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest018: start.";
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchFd(getpid(), gettid(), msg, 1);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, true) << "DumpCatcherInterfacesTest018 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest018: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest019
 * @tc.desc: test DumpCatchFd API: PID(getpid()), TID(0)
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest019, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest019: start.";
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchFd(getpid(), 0, msg, 1);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, true) << "DumpCatcherInterfacesTest019 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest019: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest020
 * @tc.desc: test DumpCatchFd API: PID(getpid()), TID(-1)
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest020, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest020: start.";
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchFd(getpid(), -1, msg, 1);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, false) << "DumpCatcherInterfacesTest020 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest020: end.";
}


/**
 * @tc.name: DumpCatcherInterfacesTest021
 * @tc.desc: test DumpCatchFd API: PID(accountmgr), TID(0)
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest021, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest021: start.";
    std::string apply = "accountmgr";
    int applyPid = GetProcessPid(apply);
    GTEST_LOG_(INFO) << "apply:" << apply << ", pid:" << applyPid;
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchFd(applyPid, 0, msg, 1);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, true) << "DumpCatcherInterfacesTest021 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest021: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest022
 * @tc.desc: test DumpCatchFd API: PID(accountmgr), TID(accountmgr main thread)
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest022, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest022: start.";
    std::string apply = "accountmgr";
    int applyPid = GetProcessPid(apply);
    GTEST_LOG_(INFO) << "apply:" << apply << ", pid:" << applyPid;
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchFd(applyPid, applyPid, msg, 1);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, true) << "DumpCatcherInterfacesTest022 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest022: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest023
 * @tc.desc: test DumpCatchFd API: PID(accountmgr), TID(-1)
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest023, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest023: start.";
    std::string apply = "accountmgr";
    int applyPid = GetProcessPid(apply);
    GTEST_LOG_(INFO) << "apply:" << apply << ", pid:" << applyPid;
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchFd(applyPid, -1, msg, 1);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, false) << "DumpCatcherInterfacesTest023 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest023: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest024
 * @tc.desc: test DumpCatchFd API: PID(accountmgr), TID(9999)
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest024, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest024: start.";
    std::string apply = "accountmgr";
    int applyPid = GetProcessPid(apply);
    GTEST_LOG_(INFO) << "apply:" << apply << ", pid:" << applyPid;
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchFd(applyPid, 9999, msg, 1);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, true) << "DumpCatcherInterfacesTest024 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest024: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest025
 * @tc.desc: test DumpCatchFd API: PID(getpid()), TID(9999)
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest025, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest025: start.";
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchFd(getpid(), 9999, msg, 1);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, true) << "DumpCatcherInterfacesTest025 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest025: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest026
 * @tc.desc: test DumpCatchFd API: PID(getpid()), TID(child thread)
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest026, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest026: start.";
    MultiThreadConstructor();
    DfxDumpCatcher dumplog;
    std::string msg = "";
    GTEST_LOG_(INFO) << "dump local process, "  << " tid:" << g_threadId;
    bool ret = dumplog.DumpCatchFd(getpid(), g_threadId, msg, 1);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, true) << "DumpCatcherInterfacesTest026 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest026: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest027
 * @tc.desc: test DumpCatchFd API: PID(child process), TID(child thread of child process)
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest027, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest027: start.";
    ForkMultiThreadProcess();
    GTEST_LOG_(INFO) << "dump remote process, "  << " pid:" << g_processId << ", tid:" << g_threadId;
    DfxDumpCatcher dumplog;
    std::string msg = "";
    bool ret = dumplog.DumpCatchFd(g_processId, g_threadId, msg, 1);
    GTEST_LOG_(INFO) << ret;
    EXPECT_EQ(ret, true) << "DumpCatcherInterfacesTest027 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest027: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest028
 * @tc.desc: test DumpCatchFd API: PID(getpid()), TID(child thread) and config FrameNum
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest028, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest028: start.";
    RecursiveMultiThreadConstructor();
    DfxDumpCatcher dumplog;
    std::string msg = "";
    GTEST_LOG_(INFO) << "dump local process, "  << " tid:" << g_threadId;
    bool ret = dumplog.DumpCatchFd(getpid(), g_threadId, msg, 1, 10); // 10 means backtrace frames is 10
    GTEST_LOG_(INFO) << "message:"  << msg;
    GTEST_LOG_(INFO) << ret;
    EXPECT_TRUE(msg.find("#09") != std::string::npos);
    EXPECT_EQ(ret, true) << "DumpCatcherInterfacesTest028 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest028: end.";
}

/**
 * @tc.name: DumpCatcherInterfacesTest029
 * @tc.desc: test DumpCatchFd API: PID(getpid()), TID(child thread) and DEFAULT_MAX_FRAME_NUM
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest029, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest029: start.";
    RecursiveMultiThreadConstructor();
    usleep(CREATE_THREAD_TIMEOUT);
    DfxDumpCatcher dumplog;
    std::string msg = "";
    GTEST_LOG_(INFO) << "dump local process, "  << " tid:" << g_threadId;
    bool ret = dumplog.DumpCatchFd(getpid(), g_threadId, msg, 1);
    GTEST_LOG_(INFO) << "message:"  << msg;
    GTEST_LOG_(INFO) << ret;
#if defined(__aarch64__)
    std::string stackKeyword = std::string("#") + std::to_string(DEFAULT_MAX_LOCAL_FRAME_NUM - 1);
#else
    std::string stackKeyword = std::string("#") + std::to_string(DEFAULT_MAX_FRAME_NUM - 1);
#endif
    GTEST_LOG_(INFO) << "stackKeyword:"  << stackKeyword;
    EXPECT_TRUE(msg.find(stackKeyword.c_str()) != std::string::npos);
    EXPECT_EQ(ret, true) << "DumpCatcherInterfacesTest029 Failed";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest029: end.";
}

#ifndef is_ohos_lite
/**
 * @tc.name: DumpCatcherInterfacesTest030
 * @tc.desc: test DumpCatch remote API: PID(getpid()), TID(child thread)
 *     and maxFrameNums(DEFAULT_MAX_FRAME_NUM), isJson(true)
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest030, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest030: start.";
    pid_t pid = fork();
    if (pid == 0) {
        std::this_thread::sleep_for(std::chrono::seconds(10));
        _exit(0);
    }
    GTEST_LOG_(INFO) << "dump remote process, "  << " pid:" << pid << ", tid:" << 0;
    DfxDumpCatcher dumplog;
    DfxJsonFormatter format;
    string msg = "";
    bool ret = dumplog.DumpCatch(pid, 0, msg);
    EXPECT_TRUE(ret) << "DumpCatch remote msg Failed.";
    string jsonMsg = "";
    bool jsonRet = dumplog.DumpCatch(pid, 0, jsonMsg, DEFAULT_MAX_FRAME_NUM, true);
    std::cout << jsonMsg << std::endl;
    EXPECT_TRUE(jsonRet) << "DumpCatch remote json Failed.";
    string stackMsg = "";
    bool formatRet = format.FormatJsonStack(jsonMsg, stackMsg);
    EXPECT_TRUE(formatRet) << "FormatJsonStack Failed.";
    size_t pos = msg.find("Process name:");
    if (pos != std::string::npos) {
        msg = msg.erase(0, pos);
        msg = msg.erase(0, msg.find("\n") + 1);
    } else {
        msg = msg.erase(0, msg.find("\n") + 1);
    }
    EXPECT_EQ(stackMsg == msg, true) << "stackMsg != msg";
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest030: end.";
}
#endif

/**
 * @tc.name: DumpCatcherInterfacesTest031
 * @tc.desc: testDump after crashed
 * @tc.type: FUNC
 */
HWTEST_F(DumpCatcherInterfacesTest, DumpCatcherInterfacesTest031, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DumpCatcherInterfacesTest031: start.";
    GTEST_LOG_(INFO) << "dump remote process, "  << " pid:" << getpid() << ", tid:" << gettid();
    int32_t fd = RequestFileDescriptor(FaultLoggerType::CPP_CRASH);
    ASSERT_GT(fd, 0);
    close(fd);
    DfxDumpCatcher dumplog;
    string msg = "";
    EXPECT_FALSE(dumplog.DumpCatchMix(getpid(), gettid(), msg));
    constexpr int validTime = 8;
    sleep(validTime);
    msg = "";
    EXPECT_TRUE(dumplog.DumpCatchMix(getpid(), gettid(), msg));
}
} // namespace HiviewDFX
} // namepsace OHOS