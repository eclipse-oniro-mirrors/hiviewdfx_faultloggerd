/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "minidump_dumper_test_helper.h"

using namespace OHOS::HiviewDFX;
using namespace testing::ext;
using namespace std;

/**
 * @tc.name: MinidumpDumperTest001
 * @tc.desc: test Dump with invalid pipeFd returns false
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest001, TestSize.Level2)
{
    MinidumpDumper dumper;
    bool ret = dumper.Dump(getpid(), -1, true, false);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: MinidumpDumperTest002
 * @tc.desc: test Dump with GenerateMinidump failure returns false
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest002, TestSize.Level2)
{
    MinidumpDumper dumper;
    int pipeFds[2] = {-1, -1};
    pipe2(pipeFds, O_NONBLOCK);
    bool ret = dumper.Dump(getpid(), pipeFds[0], true, false);
    EXPECT_FALSE(ret);
    close(pipeFds[0]);
    close(pipeFds[1]);
}

/**
 * @tc.name: MinidumpDumperTest003
 * @tc.desc: test CollectDumpHeaderInfo sets request fields correctly
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest003, TestSize.Level2)
{
    MinidumpDumper dumper;
    pid_t pid = getpid();
    dumper.CollectDumpHeaderInfo(pid);
    EXPECT_EQ(dumper.request_.type, ProcessDumpType::DUMP_TYPE_CPP_CRASH);
    EXPECT_EQ(dumper.request_.pid, pid);
    EXPECT_EQ(dumper.request_.nsPid, pid);
    EXPECT_TRUE(dumper.process_.GetLogSource() == "pdump");
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetNeedFormatFlag());
}

/**
 * @tc.name: MinidumpDumperTest004
 * @tc.desc: test TransferData with valid pipe fds
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest004, TestSize.Level2)
{
    MinidumpDumper dumper;
    int pipeFds[2] = {-1, -1};
    pipe(pipeFds);
    std::string testData = "hello minidump transfer test";
    write(pipeFds[1], testData.c_str(), testData.size());
    close(pipeFds[1]);

    int tmpFd = open("/data/test/minidump_transfer_test", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    bool ret = dumper.TransferData(pipeFds[0], tmpFd);
    EXPECT_TRUE(ret);
    close(pipeFds[0]);
    close(tmpFd);
    unlink("/data/test/minidump_transfer_test");
}

/**
 * @tc.name: MinidumpDumperTest005
 * @tc.desc: test TransferData with invalid src fd returns false
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest005, TestSize.Level2)
{
    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_transfer_invalid", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    bool ret = dumper.TransferData(-1, tmpFd);
    EXPECT_FALSE(ret);
    close(tmpFd);
    unlink("/data/test/minidump_transfer_invalid");
}

/**
 * @tc.name: MinidumpDumperTest006
 * @tc.desc: test TransferData with invalid dst fd returns false
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest006, TestSize.Level2)
{
    MinidumpDumper dumper;
    int pipeFds[2] = {-1, -1};
    pipe(pipeFds);
    std::string testData = "test data";
    write(pipeFds[1], testData.c_str(), testData.size());
    close(pipeFds[1]);
    bool ret = dumper.TransferData(pipeFds[0], -1);
    EXPECT_FALSE(ret);
    close(pipeFds[0]);
}

/**
 * @tc.name: MinidumpDumperTest007
 * @tc.desc: test GenerateMinidump with invalid pipeFd returns false
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest007, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.request_ = {};
    dumper.request_.pid = getpid();
    dumper.request_.timeStamp = GetTimeMilliSeconds();
    bool ret = dumper.GenerateMinidump(getpid(), -1, true);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: MinidumpDumperTest008
 * @tc.desc: test ParseMinidump with empty/invalid data returns false
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest008, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.request_ = {};
    dumper.request_.pid = getpid();
    dumper.request_.timeStamp = GetTimeMilliSeconds();
    int tmpFd = open("/data/test/minidump_parse_test", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "this is not a valid minidump file";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    dumper.outputFdGuard_ = SmartFd(tmpFd);
    bool ret = dumper.ParseMinidump();
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: MinidumpDumperTest030
 * @tc.desc: test Report is callable
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest030, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.request_.type = ProcessDumpType::DUMP_TYPE_CPP_CRASH;
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    EXPECT_EQ(dumper.request_.type, ProcessDumpType::DUMP_TYPE_CPP_CRASH);
    dumper.Report();
}

/**
 * @tc.name: MinidumpDumperTest031
 * @tc.desc: test CppCrashInfoCollector SetMinidumpLog flag
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest031, TestSize.Level2)
{
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    CppCrashInfoCollector::Instance().SetMinidumpLog(true);
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetMinidumpLog());
    CppCrashInfoCollector::Instance().SetMinidumpLog(false);
    EXPECT_FALSE(CppCrashInfoCollector::Instance().GetMinidumpLog());
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(false);
    CppCrashInfoCollector::Instance().SetMinidumpLog(true);
    EXPECT_FALSE(CppCrashInfoCollector::Instance().GetMinidumpLog());
}

/**
 * @tc.name: MinidumpDumperTest043
 * @tc.desc: test CppCrashInfoCollector Reset clears all fields
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest043, TestSize.Level2)
{
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    CppCrashInfoCollector::Instance().SetBuildInfo("test_build");
    CppCrashInfoCollector::Instance().SetPid(1234);
    CppCrashInfoCollector::Instance().SetPname("test_proc");
    CppCrashInfoCollector::Instance().SetMinidumpLog(true);
    CppCrashInfoCollector::Instance().Reset();
    EXPECT_FALSE(CppCrashInfoCollector::Instance().GetNeedFormatFlag());
    EXPECT_EQ(CppCrashInfoCollector::Instance().GetPid(), 0);
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetPname().empty());
    EXPECT_FALSE(CppCrashInfoCollector::Instance().GetMinidumpLog());
}

/**
 * @tc.name: MinidumpDumperTest044
 * @tc.desc: test CppCrashInfoCollector Set methods skip when needFormatFlag is false
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest044, TestSize.Level2)
{
    CppCrashInfoCollector::Instance().Reset();
    EXPECT_FALSE(CppCrashInfoCollector::Instance().GetNeedFormatFlag());
    CppCrashInfoCollector::Instance().SetBuildInfo("test_build");
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetBuildInfo().empty());
    CppCrashInfoCollector::Instance().SetTimestamp("2026-01-01");
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetTimestamp().empty());
    CppCrashInfoCollector::Instance().SetPid(999);
    EXPECT_EQ(CppCrashInfoCollector::Instance().GetPid(), 0);
    CppCrashInfoCollector::Instance().SetUid(999);
    EXPECT_EQ(CppCrashInfoCollector::Instance().GetUid(), 0);
}

/**
 * @tc.name: MinidumpDumperTest055
 * @tc.desc: test CollectDumpHeaderInfo with initialized request sets correct type and pid
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest055, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.request_ = {};
    dumper.request_.pid = getpid();
    dumper.request_.timeStamp = GetTimeMilliSeconds();
    dumper.CollectDumpHeaderInfo(getpid());
    EXPECT_EQ(dumper.request_.type, ProcessDumpType::DUMP_TYPE_CPP_CRASH);
    EXPECT_EQ(dumper.request_.pid, getpid());
}

/**
 * @tc.name: MinidumpDumperTest063
 * @tc.desc: test GenerateMinidump with valid pipe fds returns true
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest063, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.request_ = {};
    dumper.request_.pid = getpid();
    dumper.request_.timeStamp = GetTimeMilliSeconds();
    int pipeFds[2] = {-1, -1};
    pipe2(pipeFds, O_NONBLOCK);
    std::string testData = "test minidump data";
    write(pipeFds[1], testData.c_str(), testData.size());
    close(pipeFds[1]);
    bool ret = dumper.GenerateMinidump(getpid(), pipeFds[0], true);
    EXPECT_TRUE(ret);
    close(pipeFds[0]);
    if (dumper.outputFdGuard_) {
        close(dumper.outputFdGuard_.GetFd());
    }
}

/**
 * @tc.name: MinidumpDumperTest100
 * @tc.desc: test Dump with valid pipe fds and false format flag verifies collector state
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest100, TestSize.Level2)
{
    MinidumpDumper dumper;
    int pipeFds[2] = {-1, -1};
    pipe2(pipeFds, O_NONBLOCK);
    std::string testData = "minidump data for false flag test";
    write(pipeFds[1], testData.c_str(), testData.size());
    close(pipeFds[1]);
    bool ret = dumper.Dump(getpid(), pipeFds[0], true, false);
    if (ret) {
        EXPECT_TRUE(CppCrashInfoCollector::Instance().GetNeedFormatFlag());
        EXPECT_TRUE(CppCrashInfoCollector::Instance().GetRegisters().empty());
        EXPECT_TRUE(CppCrashInfoCollector::Instance().GetMaps().empty());
    }
}

/**
 * @tc.name: MinidumpDumperTest110
 * @tc.desc: test IsCrashSignal returns true for all crash signals in SIGCHAIN_CRASH_SIGNAL_LIST
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest110, TestSize.Level2)
{
    MinidumpDumper dumper;
    EXPECT_TRUE(dumper.IsCrashSignal(SIGILL));
    EXPECT_TRUE(dumper.IsCrashSignal(SIGABRT));
    EXPECT_TRUE(dumper.IsCrashSignal(SIGBUS));
    EXPECT_TRUE(dumper.IsCrashSignal(SIGFPE));
    EXPECT_TRUE(dumper.IsCrashSignal(SIGSEGV));
    EXPECT_TRUE(dumper.IsCrashSignal(SIGSTKFLT));
    EXPECT_TRUE(dumper.IsCrashSignal(SIGSYS));
    EXPECT_TRUE(dumper.IsCrashSignal(SIGTRAP));
}

/**
 * @tc.name: MinidumpDumperTest111
 * @tc.desc: test IsCrashSignal returns false for non-crash signals
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest111, TestSize.Level2)
{
    MinidumpDumper dumper;
    EXPECT_FALSE(dumper.IsCrashSignal(SIGKILL));
    EXPECT_FALSE(dumper.IsCrashSignal(SIGTERM));
    EXPECT_FALSE(dumper.IsCrashSignal(SIGCHLD));
    EXPECT_FALSE(dumper.IsCrashSignal(SIGPIPE));
    EXPECT_FALSE(dumper.IsCrashSignal(SIGHUP));
    EXPECT_FALSE(dumper.IsCrashSignal(SIGALRM));
    EXPECT_FALSE(dumper.IsCrashSignal(SIGTSTP));
    EXPECT_FALSE(dumper.IsCrashSignal(SIGUSR1));
}

/**
 * @tc.name: MinidumpDumperTest112
 * @tc.desc: test IsCrashSignal returns false for invalid signal values
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest112, TestSize.Level2)
{
    MinidumpDumper dumper;
    EXPECT_FALSE(dumper.IsCrashSignal(0));
    EXPECT_FALSE(dumper.IsCrashSignal(-1));
    EXPECT_FALSE(dumper.IsCrashSignal(999));
}

/**
 * @tc.name: MinidumpDumperTest113
 * @tc.desc: test ReportCrashNoLog is callable with summary string
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest113, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.request_ = {};
    dumper.request_.pid = getpid();
    dumper.request_.uid = getuid();
    dumper.request_.timeStamp = GetTimeMilliSeconds();
    (void)strcpy_s(dumper.request_.processName, sizeof(dumper.request_.processName), "test_proc");
    dumper.ReportCrashNoLog("invalid core signal:9");
}

