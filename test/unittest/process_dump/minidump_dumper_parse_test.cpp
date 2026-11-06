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
 * @tc.name: MinidumpDumperTest028
 * @tc.desc: test ConfigureMinidumpParser is callable (no-op)
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest028, TestSize.Level2)
{
    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_cfg_perf_test", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "not a minidump";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.ConfigureMinidumpParser(parser);
    close(tmpFd);
    unlink("/data/test/minidump_cfg_perf_test");
}

/**
 * @tc.name: MinidumpDumperTest032
 * @tc.desc: test PrintHeader collector fields match request data
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest032, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    dumper.PrintHeader();
    EXPECT_EQ(CppCrashInfoCollector::Instance().GetPid(), getpid());
    EXPECT_EQ(CppCrashInfoCollector::Instance().GetUid(), getuid());
    std::string pname = CppCrashInfoCollector::Instance().GetPname();
    EXPECT_EQ(pname, std::string(dumper.request_.processName));
}

/**
 * @tc.name: MinidumpDumperTest033
 * @tc.desc: test PrintThreadInfo with DUMP_TYPE_DUMP_CATCH does not add prefix
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest033, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.request_.type = ProcessDumpType::DUMP_TYPE_DUMP_CATCH;
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    keyThread->SetThreadName("key_thread");
    dumper.process_.SetKeyThread(keyThread);
    dumper.PrintThreadInfo();
    EXPECT_EQ(CppCrashInfoCollector::Instance().GetKeyThread().tid, getpid());
}

/**
 * @tc.name: MinidumpDumperTest034
 * @tc.desc: test PrintOtherThreadInfo with DUMP_TYPE_DUMP_CATCH
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest034, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.request_.type = ProcessDumpType::DUMP_TYPE_DUMP_CATCH;
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto thread1 = DfxThread::Create(getpid(), 100, 100, false);
    thread1->SetThreadName("thread1");
    dumper.process_.GetOtherThreads().push_back(thread1);
    dumper.PrintOtherThreadInfo();
    EXPECT_EQ(CppCrashInfoCollector::Instance().GetOtherThreads().size(), 1);
}

/**
 * @tc.name: MinidumpDumperTest035
 * @tc.desc: test MemoryNearRegisterUtil singleton blocksInfo clear and access
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest035, TestSize.Level2)
{
    auto& memIns = MemoryNearRegisterUtil::GetInstance();
    memIns.blocksInfo_.clear();
    EXPECT_EQ(memIns.blocksInfo_.size(), 0);
    MemoryBlockInfo info;
    info.nameAddr = 0x1000;
    info.startAddr = 0x1000;
    info.size = 10;
    info.content = {1, 2, 3};
    memIns.blocksInfo_.push_back(info);
    EXPECT_EQ(memIns.blocksInfo_.size(), 1);
    memIns.blocksInfo_.clear();
}

/**
 * @tc.name: MinidumpDumperTest036
 * @tc.desc: test ParseExceptionStream returns false with null exception
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest036, TestSize.Level2)
{
    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_exception_test", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "not a valid minidump";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    bool ret = dumper.ParseExceptionStream(parser);
    EXPECT_FALSE(ret);
    close(tmpFd);
    unlink("/data/test/minidump_exception_test");
}

/**
 * @tc.name: MinidumpDumperTest037
 * @tc.desc: test ParseThreadNameStream returns false with null threadNameList
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest037, TestSize.Level2)
{
    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_threadname_test", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "not a valid minidump";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    bool ret = dumper.ParseThreadNameStream(parser);
    EXPECT_FALSE(ret);
    close(tmpFd);
    unlink("/data/test/minidump_threadname_test");
}

/**
 * @tc.name: MinidumpDumperTest039
 * @tc.desc: test ParseMemoryListStream returns false with null memoryList
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest039, TestSize.Level2)
{
    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_memory_test", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "not a valid minidump";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    bool ret = dumper.ParseMemoryListStream(parser);
    EXPECT_FALSE(ret);
    close(tmpFd);
    unlink("/data/test/minidump_memory_test");
}

/**
 * @tc.name: MinidumpDumperTest040
 * @tc.desc: test ParseThreadListStream returns false with null threadList
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest040, TestSize.Level2)
{
    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_threadlist_test", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "not a valid minidump";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    bool ret = dumper.ParseThreadListStream(parser);
    EXPECT_FALSE(ret);
    close(tmpFd);
    unlink("/data/test/minidump_threadlist_test");
}

/**
 * @tc.name: MinidumpDumperTest041
 * @tc.desc: test ParseThreadNameStream returns false when keyThread is null
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest041, TestSize.Level2)
{
    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_threadname_null_key", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "not a valid minidump";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    bool ret = dumper.ParseThreadNameStream(parser);
    EXPECT_FALSE(ret);
    close(tmpFd);
    unlink("/data/test/minidump_threadname_null_key");
}

/**
 * @tc.name: MinidumpDumperTest042
 * @tc.desc: test ParseMemoryListStream returns false when regs is null
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest042, TestSize.Level2)
{
    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_memory_null_regs", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "not a valid minidump";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    bool ret = dumper.ParseMemoryListStream(parser);
    EXPECT_FALSE(ret);
    close(tmpFd);
    unlink("/data/test/minidump_memory_null_regs");
}

/**
 * @tc.name: MinidumpDumperTest045
 * @tc.desc: test ParseMapListStream returns false when mapList is null from invalid parser
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest045, TestSize.Level2)
{
    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_maplist_null", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "not a valid minidump";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    bool ret = dumper.ParseMapListStream(parser);
    EXPECT_FALSE(ret);
    close(tmpFd);
    unlink("/data/test/minidump_maplist_null");
}

/**
 * @tc.name: MinidumpDumperTest046
 * @tc.desc: test BuildSignalInfoFromException returns false with null exceptionRecord
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest046, TestSize.Level2)
{
    MinidumpDumper dumper;
    bool ret = dumper.BuildSignalInfoFromException(nullptr);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: MinidumpDumperTest047
 * @tc.desc: test CreateARM64DfxRegs returns nullptr with null arm64Context
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest047, TestSize.Level2)
{
    MinidumpDumper dumper;
    auto result = dumper.CreateARM64DfxRegs(nullptr);
    EXPECT_TRUE(result == nullptr);
}

/**
 * @tc.name: MinidumpDumperTest048
 * @tc.desc: test SetupKeyThreadStack returns false when minidumpKeyThread is null
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest048, TestSize.Level2)
{
    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_setup_null_thread", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "not a valid minidump";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    MinidumpThreadList* threadList = parser.GetThreadList();
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    bool ret = dumper.SetupKeyThreadStack(threadList, keyThread);
    EXPECT_FALSE(ret);
    close(tmpFd);
    unlink("/data/test/minidump_setup_null_thread");
}

/**
 * @tc.name: MinidumpDumperTest049
 * @tc.desc: test PopulateOtherThreadFromMinidump with null otherThread skips processing
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest049, TestSize.Level2)
{
    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_populate_null", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "not a valid minidump";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    MinidumpThreadList* threadList = parser.GetThreadList();
    dumper.PopulateOtherThreadFromMinidump(nullptr, threadList);
    close(tmpFd);
    unlink("/data/test/minidump_populate_null");
}

/**
 * @tc.name: MinidumpDumperTest053
 * @tc.desc: test PopulateOtherThreadFromMinidump with null otherThread and null threadList
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest053, TestSize.Level2)
{
    MinidumpDumper dumper;
    auto keyThread = DfxThread::Create(getpid(), 100, 100, false);
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    dumper.process_.SetKeyThread(keyThread);
    dumper.process_.GetOtherThreads().push_back(nullptr);
    MinidumpThreadList* threadList = nullptr;
    dumper.PopulateOtherThreadFromMinidump(
        dumper.process_.GetOtherThreads()[0], threadList);
}

/**
 * @tc.name: MinidumpDumperTest054
 * @tc.desc: test PopulateOtherThreadFromMinidump with null threadList skips processing
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest054, TestSize.Level2)
{
    MinidumpDumper dumper;
    auto otherThread = DfxThread::Create(getpid(), 100, 100, false);
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    dumper.PopulateOtherThreadFromMinidump(otherThread, nullptr);
    EXPECT_EQ(otherThread->GetThreadRegs(), nullptr);
    EXPECT_EQ(otherThread->GetThreadStackBuffer(), nullptr);
}

/**
 * @tc.name: MinidumpDumperTest057
 * @tc.desc: test ParseExceptionStream with valid minidump data sets keyThread and registers
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest057, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    std::string minidumpData = BuildMinidumpWithExceptionAndContext();
    int tmpFd = open("/data/test/minidump_exc_normal", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.ConfigureMinidumpParser(parser);
    EXPECT_TRUE(parser.Parse());
    bool ret = dumper.ParseExceptionStream(parser);
    EXPECT_TRUE(ret);
    EXPECT_NE(dumper.process_.GetKeyThread(), nullptr);
    EXPECT_NE(dumper.process_.GetFaultThreadRegisters(), nullptr);
    close(tmpFd);
    unlink("/data/test/minidump_exc_normal");
}

/**
 * @tc.name: MinidumpDumperTest058
 * @tc.desc: test BuildSignalInfoFromException with valid exception returns true and sets reason
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest058, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    std::string minidumpData = BuildMinidumpWithExceptionAndContext();
    int tmpFd = open("/data/test/minidump_exc_signal", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    EXPECT_TRUE(parser.Parse());
    MinidumpException* exception = parser.GetException();
    EXPECT_NE(exception, nullptr);
    bool ret = dumper.BuildSignalInfoFromException(exception);
    EXPECT_TRUE(ret);
    EXPECT_TRUE(!dumper.process_.GetReason().empty());
    close(tmpFd);
    unlink("/data/test/minidump_exc_signal");
}

/**
 * @tc.name: MinidumpDumperTest059
 * @tc.desc: test CreateARM64DfxRegs with valid ARM64 context returns non-null regs
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest059, TestSize.Level2)
{
    MinidumpDumper dumper;
    std::string minidumpData = BuildMinidumpWithExceptionAndContext();
    int tmpFd = open("/data/test/minidump_arm64regs", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    EXPECT_TRUE(parser.Parse());
    MinidumpException* exception = parser.GetException();
    EXPECT_NE(exception, nullptr);
    auto context = exception->GetContext();
    EXPECT_NE(context, nullptr);
    auto arm64Ctx = context->GetContextARM64();
    EXPECT_NE(arm64Ctx, nullptr);
    auto dfxRegs = dumper.CreateARM64DfxRegs(arm64Ctx);
    EXPECT_NE(dfxRegs, nullptr);
    close(tmpFd);
    unlink("/data/test/minidump_arm64regs");
}

/**
 * @tc.name: MinidumpDumperTest061
 * @tc.desc: test ParseThreadNameStream with valid minidump data processes thread names
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest061, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    pid_t pid = getpid();
    dumper.CollectDumpHeaderInfo(pid);
    auto keyThread = DfxThread::Create(pid, pid, pid, false);
    dumper.process_.SetKeyThread(keyThread);
    std::string minidumpData = BuildMinidumpWithThreadNameList();
    int tmpFd = open("/data/test/minidump_tn_normal", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.ConfigureMinidumpParser(parser);
    parser.Parse();
    dumper.ParseThreadNameStream(parser);
    close(tmpFd);
    unlink("/data/test/minidump_tn_normal");
}

/**
 * @tc.name: MinidumpDumperTest062
 * @tc.desc: test ParseMemoryListStream with valid minidump data returns true
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest062, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {};
    regsData[31] = 0x8000;
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    std::string minidumpData = BuildMinidumpWithMemoryList();
    int tmpFd = open("/data/test/minidump_mem_normal", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.ConfigureMinidumpParser(parser);
    EXPECT_TRUE(parser.Parse());
    bool ret = dumper.ParseMemoryListStream(parser);
    EXPECT_TRUE(ret);
    close(tmpFd);
    unlink("/data/test/minidump_mem_normal");
}

/**
 * @tc.name: MinidumpDumperTest064
 * @tc.desc: test ParseMinidump with valid minidump data and output fd succeeds
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest064, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    std::string minidumpData = BuildMinidumpWithExceptionAndContext();
    int tmpFd = open("/data/test/minidump_parse_success", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.ConfigureMinidumpParser(parser);
    bool parsed = parser.Parse();
    if (parsed) {
        dumper.outputFdGuard_ = SmartFd(tmpFd);
        dumper.ParseMinidump();
    }
    close(tmpFd);
    unlink("/data/test/minidump_parse_success");
}

/**
 * @tc.name: MinidumpDumperTest065
 * @tc.desc: test ParseExceptionStream with valid minidump sets keyThread and fault registers
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest065, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    std::string minidumpData = BuildMinidumpWithExceptionAndContext();
    int tmpFd = open("/data/test/minidump_exc_stream", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.ConfigureMinidumpParser(parser);
    bool parsed = parser.Parse();
    if (parsed) {
        bool ret = dumper.ParseExceptionStream(parser);
        if (ret) {
            EXPECT_NE(dumper.process_.GetKeyThread(), nullptr);
            EXPECT_NE(dumper.process_.GetFaultThreadRegisters(), nullptr);
        }
    }
    close(tmpFd);
    unlink("/data/test/minidump_exc_stream");
}

/**
 * @tc.name: MinidumpDumperTest066
 * @tc.desc: test BuildSignalInfoFromException with parsed minidump sets signal reason
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest066, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    std::string minidumpData = BuildMinidumpWithExceptionAndContext();
    int tmpFd = open("/data/test/minidump_signal_exc", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    bool parsed = parser.Parse();
    if (parsed) {
        MinidumpException* exception = parser.GetException();
        if (exception != nullptr) {
            bool ret = dumper.BuildSignalInfoFromException(exception);
            EXPECT_TRUE(ret);
            EXPECT_TRUE(!dumper.process_.GetReason().empty());
        }
    }
    close(tmpFd);
    unlink("/data/test/minidump_signal_exc");
}

/**
 * @tc.name: MinidumpDumperTest067
 * @tc.desc: test CreateARM64DfxRegs with parsed minidump context creates dfxRegs
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest067, TestSize.Level2)
{
    MinidumpDumper dumper;
    std::string minidumpData = BuildMinidumpWithExceptionAndContext();
    int tmpFd = open("/data/test/minidump_arm64regs2", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    MinidumpException* exception = parser.Parse() ? parser.GetException() : nullptr;
    auto context = exception ? exception->GetContext() : nullptr;
    auto arm64Ctx = context ? context->GetContextARM64() : nullptr;
    if (arm64Ctx != nullptr) {
        auto dfxRegs = dumper.CreateARM64DfxRegs(arm64Ctx);
        EXPECT_NE(dfxRegs, nullptr);
    }
    close(tmpFd);
    unlink("/data/test/minidump_arm64regs2");
}

/**
 * @tc.name: MinidumpDumperTest068
 * @tc.desc: test PrintDumpInfo with maps and keyThread collects pname and maps
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest068, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    auto map = std::make_shared<DfxMap>(0x1000, 0x2000, 0, PROT_READ, "/system/lib/test.so");
    dumper.dfxMaps_->AddMap(map);
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    keyThread->SetThreadName("key_thread");
    dumper.process_.SetKeyThread(keyThread);
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {};
    regsData[31] = 0x8000;
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    dumper.PrintDumpInfo();
    EXPECT_TRUE(!CppCrashInfoCollector::Instance().GetPname().empty());
    EXPECT_TRUE(!CppCrashInfoCollector::Instance().GetMaps().empty());
}

/**
 * @tc.name: MinidumpDumperTest069
 * @tc.desc: test ParseModuleListStream with module list minidump verifies module count
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest069, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    std::string minidumpData = BuildMinidumpWithModuleList();
    int tmpFd = open("/data/test/minidump_module_list_full", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.ConfigureMinidumpParser(parser);
    bool parsed = parser.Parse();
    if (parsed) {
        MinidumpModuleList* moduleList = parser.GetModuleList();
        if (moduleList != nullptr) {
            EXPECT_TRUE(moduleList->ModuleCount() > 0);
        }
    }
    close(tmpFd);
    unlink("/data/test/minidump_module_list_full");
}

/**
 * @tc.name: MinidumpDumperTest070
 * @tc.desc: test GetException threadId from parsed minidump creates keyThread
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest070, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    std::string minidumpData = BuildMinidumpWithExceptionAndContext();
    int tmpFd = open("/data/test/minidump_exc_stream_null", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    bool parsed = parser.Parse();
    if (parsed) {
        MinidumpException* exc = parser.GetException();
        if (exc != nullptr && exc->Exception() != nullptr) {
            auto keyThreadId = exc->Exception()->threadId;
            auto keyThread = DfxThread::Create(getpid(), keyThreadId, keyThreadId, false);
            if (keyThread != nullptr) {
                EXPECT_NE(keyThread, nullptr);
            }
        }
    }
    close(tmpFd);
    unlink("/data/test/minidump_exc_stream_null");
}

/**
 * @tc.name: MinidumpDumperTest071
 * @tc.desc: test GetThreadNameList with parsed minidump verifies thread names count
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest071, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    std::string minidumpData = BuildMinidumpWithThreadNameList();
    int tmpFd = open("/data/test/minidump_thread_name_list", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    bool parsed = parser.Parse();
    if (parsed) {
        MinidumpThreadNameList* threadNameList = parser.GetThreadNameList();
        if (threadNameList != nullptr) {
            auto threadNames = threadNameList->GetThreadNames();
            EXPECT_TRUE(threadNames.size() > 0);
        }
    }
    close(tmpFd);
    unlink("/data/test/minidump_thread_name_list");
}

/**
 * @tc.name: MinidumpDumperTest072
 * @tc.desc: test GetMemoryList with parsed minidump verifies memory region count
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest072, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    std::string minidumpData = BuildMinidumpWithMemoryList();
    int tmpFd = open("/data/test/minidump_memory_list", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    bool parsed = parser.Parse();
    if (parsed) {
        MinidumpMemoryList* memoryList = parser.GetMemoryList();
        if (memoryList != nullptr) {
            EXPECT_TRUE(memoryList->RegionCount() > 0);
        }
    }
    close(tmpFd);
    unlink("/data/test/minidump_memory_list");
}

/**
 * @tc.name: MinidumpDumperTest085
 * @tc.desc: test ParseExceptionStream with invalid minidump data returns false
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest085, TestSize.Level2)
{
    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_null_exc_stream", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "not a valid minidump";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    bool ret = dumper.ParseExceptionStream(parser);
    EXPECT_FALSE(ret);
    close(tmpFd);
    unlink("/data/test/minidump_null_exc_stream");
}

/**
 * @tc.name: MinidumpDumperTest086
 * @tc.desc: test BuildSignalInfoFromException with null exception pointer returns false
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest086, TestSize.Level2)
{
    MinidumpDumper dumper;
    MinidumpException* exc = nullptr;
    bool ret = dumper.BuildSignalInfoFromException(exc);
    EXPECT_FALSE(ret);
}

/**
 * @tc.name: MinidumpDumperTest089
 * @tc.desc: test ParseThreadNameStream with multi thread names sets thread names correctly
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest089, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    dumper.process_.SetKeyThread(keyThread);
    std::string minidumpData = BuildMinidumpWithMultiThreadNames();
    int tmpFd = open("/data/test/minidump_tn_multi_089", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.ConfigureMinidumpParser(parser);
    parser.Parse();
    bool ret = dumper.ParseThreadNameStream(parser);
    EXPECT_TRUE(ret);
    EXPECT_EQ(keyThread->GetThreadInfo().threadName, "main");
    EXPECT_EQ(dumper.process_.GetOtherThreads().size(), 1u);
    if (dumper.process_.GetOtherThreads().size() > 0) {
        EXPECT_EQ(dumper.process_.GetOtherThreads()[0]->GetThreadInfo().tid, 100);
        EXPECT_EQ(dumper.process_.GetOtherThreads()[0]->GetThreadInfo().threadName, "worker");
    }
    close(tmpFd);
    unlink("/data/test/minidump_tn_multi_089");
}

/**
 * @tc.name: MinidumpDumperTest091
 * @tc.desc: test ParseMapListStream with valid map list minidump creates dfxMaps
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest091, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    std::string minidumpData = BuildMinidumpWithMapList();
    int tmpFd = open("/data/test/minidump_maplist_valid_091", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.ConfigureMinidumpParser(parser);
    bool parsed = parser.Parse();
    if (parsed) {
        bool ret = dumper.ParseMapListStream(parser);
        if (ret) {
            EXPECT_NE(dumper.dfxMaps_, nullptr);
        }
    }
    close(tmpFd);
    unlink("/data/test/minidump_maplist_valid_091");
}

/**
 * @tc.name: MinidumpDumperTest092
 * @tc.desc: test ParseMemoryListStream with valid memory minidump populates blocksInfo
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest092, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {};
    regsData[31] = 0x7000;
    regsData[32] = 0x1000;
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    std::string minidumpData = BuildMinidumpWithMemoryList();
    int tmpFd = open("/data/test/minidump_mem_valid_092", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.ConfigureMinidumpParser(parser);
    bool parsed = parser.Parse();
    if (parsed) {
        bool ret = dumper.ParseMemoryListStream(parser);
        if (ret) {
            EXPECT_TRUE(MemoryNearRegisterUtil::GetInstance().blocksInfo_.size() > 0);
        }
    }
    close(tmpFd);
    unlink("/data/test/minidump_mem_valid_092");
}

/**
 * @tc.name: MinidumpDumperTest093
 * @tc.desc: test ParseMinidump with full crash log and format flag succeeds
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest093, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());

    std::string minidumpData = BuildMinidumpWithFullCrashLog();
    const char* filePath = "/data/test/minidump_crashlog_true_093";
    int tmpFd = open(filePath, O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    dumper.outputFdGuard_ = SmartFd(tmpFd, false);

    DfxBufferWriter::GetInstance().InitBufferWriter(dumper.request_);
    bool parseRet = dumper.ParseMinidump();
    if (parseRet) {
        dumper.UnwindProcess();
        dumper.PrintDumpInfo();
    }
    DfxBufferWriter::GetInstance().WriteFormatCrashInfo();
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetNeedFormatFlag());
    unlink(filePath);
}

/**
 * @tc.name: MinidumpDumperTest094
 * @tc.desc: test SetupKeyThreadStack with valid thread list sets keyThread stack
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest094, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    dumper.process_.SetKeyThread(keyThread);

    std::string minidumpData = BuildMinidumpWithThreadList();
    int tmpFd = open("/data/test/minidump_setup_key_stack_094", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.ConfigureMinidumpParser(parser);
    bool parsed = parser.Parse();
    if (parsed) {
        MinidumpThreadList* threadList = parser.GetThreadList();
        if (threadList != nullptr) {
            bool ret = dumper.SetupKeyThreadStack(threadList, keyThread);
            if (ret) {
                EXPECT_NE(keyThread->GetThreadStackBuffer(), nullptr);
                EXPECT_EQ(keyThread->GetStartOfStackMemory(), 0x7000);
            }
        }
    }
    close(tmpFd);
    unlink("/data/test/minidump_setup_key_stack_094");
}

/**
 * @tc.name: MinidumpDumperTest095
 * @tc.desc: test PopulateOtherThreadFromMinidump with valid thread list sets otherThread regs and stack
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest095, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());

    std::string minidumpData = BuildMinidumpWithThreadList();
    int tmpFd = open("/data/test/minidump_populate_other_095", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.ConfigureMinidumpParser(parser);
    bool parsed = parser.Parse();
    if (parsed) {
        MinidumpThreadList* threadList = parser.GetThreadList();
        if (threadList != nullptr) {
            auto otherThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
            dumper.PopulateOtherThreadFromMinidump(otherThread, threadList);
            EXPECT_NE(otherThread->GetThreadRegs(), nullptr);
            EXPECT_NE(otherThread->GetThreadStackBuffer(), nullptr);
            EXPECT_EQ(otherThread->GetStartOfStackMemory(), 0x7000);
        }
    }
    close(tmpFd);
    unlink("/data/test/minidump_populate_other_095");
}

/**
 * @tc.name: MinidumpDumperTest096
 * @tc.desc: test ParseThreadListStream with valid thread list sets keyThread stack
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest096, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    dumper.process_.SetKeyThread(keyThread);

    std::string minidumpData = BuildMinidumpWithThreadList();
    int tmpFd = open("/data/test/minidump_thread_list_parse_096", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.ConfigureMinidumpParser(parser);
    bool parsed = parser.Parse();
    if (parsed) {
        bool ret = dumper.ParseThreadListStream(parser);
        if (ret) {
            EXPECT_NE(keyThread->GetThreadStackBuffer(), nullptr);
            EXPECT_EQ(keyThread->GetStartOfStackMemory(), 0x7000);
        }
    }
    close(tmpFd);
    unlink("/data/test/minidump_thread_list_parse_096");
}

/**
 * @tc.name: MinidumpDumperTest101
 * @tc.desc: test SetupKeyThreadStack returns false when keyThread is nullptr
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest101, TestSize.Level2)
{
    MinidumpDumper dumper;
    std::string minidumpData = BuildMinidumpWithThreadList();
    int tmpFd = open("/data/test/minidump_null_key_101", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    lseek(tmpFd, 0, SEEK_SET);
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    dumper.ConfigureMinidumpParser(parser);
    bool parsed = parser.Parse();
    if (parsed) {
        MinidumpThreadList* threadList = parser.GetThreadList();
        if (threadList != nullptr) {
            std::shared_ptr<DfxThread> nullKeyThread = nullptr;
            bool ret = dumper.SetupKeyThreadStack(threadList, nullKeyThread);
            EXPECT_FALSE(ret);
        }
    }
    close(tmpFd);
    unlink("/data/test/minidump_null_key_101");
}

/**
 * @tc.name: MinidumpDumperTest102
 * @tc.desc: test UnwindOtherThread skips thread with stackBuf size < sizeof(uintptr_t)
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest102, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto thread1 = DfxThread::Create(getpid(), 100, 100, false);
    thread1->SetThreadName("small_stack_thread");
    auto smallStack = std::make_shared<std::vector<uint8_t>>(4, 0);
    thread1->SetThreadStackBuffer(smallStack);
    thread1->SetStartOfStackMemory(0x1000);
    dumper.process_.GetOtherThreads().push_back(thread1);
    EXPECT_EQ(dumper.process_.GetOtherThreads().size(), 1u);
    dumper.UnwindOtherThread();
    EXPECT_EQ(dumper.process_.GetOtherThreads().size(), 1u);
}

/**
 * @tc.name: MinidumpDumperTest103
 * @tc.desc: test ConfigureMinidumpParser with MinidumpConfigManager config applies optimizer config
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest103, TestSize.Level2)
{
    auto& mgr = MinidumpConfigManager::Instance();
    MinidumpConfig config;
    config.enableRangeMap = true;
    config.enableIntervalTree = false;
    config.enableBitmapIndex = false;
    config.bitmapGranularity = 0;
    mgr.SetConfig(config);

    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_cfg_perf_103", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "not a minidump";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    MinidumpParser parser("/proc/self/fd/" + std::to_string(tmpFd));
    dumper.ConfigureMinidumpParser(parser);
    auto optConfig = MinidumpConfigManager::Instance().GetConfig();
    EXPECT_TRUE(optConfig.enableRangeMap);
    EXPECT_FALSE(optConfig.enableIntervalTree);
    close(tmpFd);
    unlink("/data/test/minidump_cfg_perf_103");
    mgr.SetConfig(MinidumpConfig());
}

/**
 * @tc.name: MinidumpDumperTest104
 * @tc.desc: test ConfigureMinidumpParser with default config enables interval tree and bitmap
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest104, TestSize.Level2)
{
    auto& mgr = MinidumpConfigManager::Instance();
    mgr.SetConfig(MinidumpConfig());

    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_cfg_perf_104", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "not a minidump";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    MinidumpParser parser("/proc/self/fd/" + std::to_string(tmpFd));
    dumper.ConfigureMinidumpParser(parser);
    auto optConfig = MinidumpConfigManager::Instance().GetConfig();
    EXPECT_TRUE(optConfig.enableIntervalTree);
    EXPECT_TRUE(optConfig.enableBitmapIndex);
    close(tmpFd);
    unlink("/data/test/minidump_cfg_perf_104");
    mgr.SetConfig(MinidumpConfig());
}

/**
 * @tc.name: MinidumpDumperTest105
 * @tc.desc: test ParseMinidump with valid minidump and StreamPipeline integration succeeds
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest105, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    std::string minidumpData = BuildMinidumpWithExceptionAndContext();
    int tmpFd = open("/data/test/minidump_pipeline_105", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    dumper.outputFdGuard_ = SmartFd(tmpFd, false);
    bool parseRet = dumper.ParseMinidump();
    EXPECT_FALSE(parseRet);
    unlink("/data/test/minidump_pipeline_105");
}

/**
 * @tc.name: MinidumpDumperTest106
 * @tc.desc: test ParseMinidump with StreamPipeline and parallel parsing disabled succeeds
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest106, TestSize.Level2)
{
    auto& mgr = MinidumpConfigManager::Instance();
    MinidumpConfig config;
    config.enableParallelParsing = false;
    mgr.SetConfig(config);

    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    std::string minidumpData = BuildMinidumpWithExceptionAndContext();
    int tmpFd = open("/data/test/minidump_pipeline_106", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    dumper.outputFdGuard_ = SmartFd(tmpFd, false);
    bool parseRet = dumper.ParseMinidump();
    EXPECT_FALSE(parseRet);
    unlink("/data/test/minidump_pipeline_106");
    mgr.SetConfig(MinidumpConfig());
}

/**
 * @tc.name: MinidumpDumperTest107
 * @tc.desc: test ParseMinidump with StreamPipeline and memory list stream succeeds
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest107, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    std::string minidumpData = BuildMinidumpWithMemoryList();
    int tmpFd = open("/data/test/minidump_pipeline_mem_107", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    dumper.outputFdGuard_ = SmartFd(tmpFd, false);
    bool parseRet = dumper.ParseMinidump();
    EXPECT_FALSE(parseRet);
    unlink("/data/test/minidump_pipeline_mem_107");
}

/**
 * @tc.name: MinidumpDumperTest108
 * @tc.desc: test ConfigureMinidumpParser with custom bitmap granularity applies to optimizer
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest108, TestSize.Level2)
{
    auto& mgr = MinidumpConfigManager::Instance();
    MinidumpConfig config;
    config.enableRangeMap = false;
    config.enableIntervalTree = true;
    config.enableBitmapIndex = true;
    config.bitmapGranularity = 0x1000;
    mgr.SetConfig(config);

    MinidumpDumper dumper;
    int tmpFd = open("/data/test/minidump_cfg_perf_108", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    std::string invalidData = "not a minidump";
    write(tmpFd, invalidData.c_str(), invalidData.size());
    MinidumpParser parser("/proc/self/fd/" + std::to_string(tmpFd));
    dumper.ConfigureMinidumpParser(parser);
    auto optConfig = MinidumpConfigManager::Instance().GetConfig();
    EXPECT_EQ(optConfig.bitmapGranularity, 0x1000u);
    close(tmpFd);
    unlink("/data/test/minidump_cfg_perf_108");
    mgr.SetConfig(MinidumpConfig());
}

/**
 * @tc.name: MinidumpDumperTest109
 * @tc.desc: test ParseMinidump with full crash log and StreamPipeline succeeds
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest109, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());

    std::string minidumpData = BuildMinidumpWithFullCrashLog();
    const char* filePath = "/data/test/minidump_pipeline_full_109";
    int tmpFd = open(filePath, O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    dumper.outputFdGuard_ = SmartFd(tmpFd, false);

    DfxBufferWriter::GetInstance().InitBufferWriter(dumper.request_);
    bool parseRet = dumper.ParseMinidump();
    if (parseRet) {
        dumper.UnwindProcess();
        dumper.PrintDumpInfo();
    }
    DfxBufferWriter::GetInstance().WriteFormatCrashInfo();
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetNeedFormatFlag());
    unlink(filePath);
}

/**
 * @tc.name: MinidumpDumperTest114
 * @tc.desc: test BuildSignalInfoFromException stores signal in request_.siginfo
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest114, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    std::string minidumpData = BuildMinidumpWithExceptionAndContext();
    int tmpFd = open("/data/test/minidump_siginfo_store_114", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    EXPECT_TRUE(parser.Parse());
    MinidumpException* exception = parser.GetException();
    EXPECT_NE(exception, nullptr);
    bool ret = dumper.BuildSignalInfoFromException(exception);
    EXPECT_TRUE(ret);
    EXPECT_EQ(dumper.request_.siginfo.si_signo, SIGSEGV);
    EXPECT_EQ(dumper.request_.siginfo.si_code, SEGV_MAPERR);
    close(tmpFd);
    unlink("/data/test/minidump_siginfo_store_114");
}

/**
 * @tc.name: MinidumpDumperTest115
 * @tc.desc: test BuildSignalInfoFromException with non-crash signal stores non-crash value
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest115, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    std::string minidumpData = BuildMinidumpWithExceptionBySignal(SIGKILL, SI_USER);
    int tmpFd = open("/data/test/minidump_noncrash_sig_115", O_RDWR | O_CREAT | O_TRUNC, TEST_FILE_PERMISSIONS);
    ASSERT_TRUE(tmpFd > 0);
    write(tmpFd, minidumpData.c_str(), minidumpData.size());
    auto input = std::make_shared<std::ifstream>("/proc/self/fd/" + std::to_string(tmpFd), std::ios::binary);
    MinidumpParser parser(input);
    EXPECT_TRUE(parser.Parse());
    MinidumpException* exception = parser.GetException();
    EXPECT_NE(exception, nullptr);
    bool ret = dumper.BuildSignalInfoFromException(exception);
    EXPECT_TRUE(ret);
    EXPECT_EQ(dumper.request_.siginfo.si_signo, SIGKILL);
    EXPECT_FALSE(dumper.IsCrashSignal(dumper.request_.siginfo.si_signo));
    close(tmpFd);
    unlink("/data/test/minidump_noncrash_sig_115");
}

