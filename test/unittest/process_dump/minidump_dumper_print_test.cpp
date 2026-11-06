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
 * @tc.name: MinidumpDumperTest009
 * @tc.desc: test UnwindProcess with nullptr dfxMaps returns early
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest009, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.dfxMaps_ = nullptr;
    dumper.UnwindProcess();
    EXPECT_EQ(dumper.unwinder_, nullptr);
}

/**
 * @tc.name: MinidumpDumperTest010
 * @tc.desc: test UnwindProcess with nullptr keyThread returns early
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest010, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    dumper.UnwindProcess();
    EXPECT_EQ(dumper.unwinder_, nullptr);
}

/**
 * @tc.name: MinidumpDumperTest011
 * @tc.desc: test UnwindOtherThread with nullptr unwinder returns early
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest011, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.unwinder_ = nullptr;
    size_t otherThreadCount = dumper.process_.GetOtherThreads().size();
    dumper.UnwindOtherThread();
    EXPECT_EQ(dumper.process_.GetOtherThreads().size(), otherThreadCount);
}

/**
 * @tc.name: MinidumpDumperTest012
 * @tc.desc: test PrintThreadInfo with nullptr unwinder returns early
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest012, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.unwinder_ = nullptr;
    dumper.request_.type = ProcessDumpType::DUMP_TYPE_CPP_CRASH;
    dumper.PrintThreadInfo();
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetKeyThread().frames.empty());
}

/**
 * @tc.name: MinidumpDumperTest013
 * @tc.desc: test PrintThreadInfo with nullptr keyThread returns early
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest013, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.request_.type = ProcessDumpType::DUMP_TYPE_CPP_CRASH;
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    dumper.PrintThreadInfo();
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetKeyThread().frames.empty());
}

/**
 * @tc.name: MinidumpDumperTest014
 * @tc.desc: test PrintRegisters with nullptr regs returns early
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest014, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    dumper.PrintRegisters();
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetRegisters().empty());
}

/**
 * @tc.name: MinidumpDumperTest015
 * @tc.desc: test PrintRegsNearMemory with nullptr unwinder returns early
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest015, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.unwinder_ = nullptr;
    dumper.PrintRegsNearMemory();
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetMemoryNearRegister().empty());
}

/**
 * @tc.name: MinidumpDumperTest016
 * @tc.desc: test PrintFaultStack with nullptr unwinder returns early
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest016, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.unwinder_ = nullptr;
    dumper.PrintFaultStack();
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetFaultStack().empty());
}

/**
 * @tc.name: MinidumpDumperTest017
 * @tc.desc: test PrintMaps with nullptr dfxMaps returns early
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest017, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.dfxMaps_ = nullptr;
    dumper.PrintMaps();
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetMaps().empty());
}

/**
 * @tc.name: MinidumpDumperTest018
 * @tc.desc: test PrintHeader collects data into CppCrashInfoCollector
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest018, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    dumper.PrintHeader();
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetNeedFormatFlag());
    EXPECT_EQ(CppCrashInfoCollector::Instance().GetPid(), getpid());
    EXPECT_TRUE(!CppCrashInfoCollector::Instance().GetPname().empty() ||
        CppCrashInfoCollector::Instance().GetPname() == dumper.request_.processName);
    EXPECT_TRUE(!CppCrashInfoCollector::Instance().GetTimestamp().empty());
}

/**
 * @tc.name: MinidumpDumperTest019
 * @tc.desc: test PrintMaps with valid dfxMaps collects into CppCrashInfoCollector
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest019, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    auto map = std::make_shared<DfxMap>(0x1000, 0x2000, 0, PROT_READ, "/system/lib/test.so");
    dumper.dfxMaps_->AddMap(map);
    dumper.PrintMaps();
    EXPECT_TRUE(!CppCrashInfoCollector::Instance().GetMaps().empty());
}

/**
 * @tc.name: MinidumpDumperTest020
 * @tc.desc: test PrintOtherThreadInfo with CPP_CRASH type and threads
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest020, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.request_.type = ProcessDumpType::DUMP_TYPE_CPP_CRASH;
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto thread1 = DfxThread::Create(getpid(), 100, 100, false);
    thread1->SetThreadName("test_thread_1");
    auto thread2 = DfxThread::Create(getpid(), 200, 200, false);
    thread2->SetThreadName("test_thread_2");
    dumper.process_.GetOtherThreads().push_back(thread1);
    dumper.process_.GetOtherThreads().push_back(thread2);
    dumper.PrintOtherThreadInfo();
    EXPECT_EQ(CppCrashInfoCollector::Instance().GetOtherThreads().size(), 2);
}

/**
 * @tc.name: MinidumpDumperTest021
 * @tc.desc: test PrintThreadInfo with valid keyThread collects into CppCrashInfoCollector
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest021, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.request_.type = ProcessDumpType::DUMP_TYPE_CPP_CRASH;
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    keyThread->SetThreadName("test_key_thread");
    dumper.process_.SetKeyThread(keyThread);
    dumper.PrintThreadInfo();
    EXPECT_EQ(CppCrashInfoCollector::Instance().GetKeyThread().tid, getpid());
}

/**
 * @tc.name: MinidumpDumperTest022
 * @tc.desc: test PrintRegisters with valid regs collects into CppCrashInfoCollector
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest022, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {0};
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    dumper.PrintRegisters();
    EXPECT_TRUE(!CppCrashInfoCollector::Instance().GetRegisters().empty());
}

/**
 * @tc.name: MinidumpDumperTest023
 * @tc.desc: test PrintRegisters strips "Registers:\n" prefix for collector
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest023, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {0};
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    dumper.PrintRegisters();
    std::string collectedRegs = CppCrashInfoCollector::Instance().GetRegisters();
    EXPECT_TRUE(collectedRegs.find("Registers:\n") != 0);
}

/**
 * @tc.name: MinidumpDumperTest024
 * @tc.desc: test PrintDumpInfo calls all print methods
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest024, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.request_.type = ProcessDumpType::DUMP_TYPE_CPP_CRASH;
    std::string processName = "test_proc";
    (void)strcpy_s(dumper.request_.processName, sizeof(dumper.request_.processName), processName.c_str());
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), processName);
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    auto map = std::make_shared<DfxMap>(0x1000, 0x2000, 0, PROT_READ, "/test.so");
    dumper.dfxMaps_->AddMap(map);
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    keyThread->SetThreadName("key_thread");
    dumper.process_.SetKeyThread(keyThread);
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {0};
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    dumper.PrintDumpInfo();
    EXPECT_TRUE(!CppCrashInfoCollector::Instance().GetPname().empty());
    EXPECT_TRUE(!CppCrashInfoCollector::Instance().GetMaps().empty());
}

/**
 * @tc.name: MinidumpDumperTest026
 * @tc.desc: test UnwindOtherThread with null other thread elements skips
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest026, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    dumper.process_.GetOtherThreads().push_back(nullptr);
    EXPECT_EQ(dumper.process_.GetOtherThreads().size(), 1u);
    dumper.UnwindOtherThread();
    EXPECT_EQ(dumper.process_.GetOtherThreads().size(), 1u);
}

/**
 * @tc.name: MinidumpDumperTest027
 * @tc.desc: test UnwindOtherThread with thread without stack/regs skips
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest027, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto thread1 = DfxThread::Create(getpid(), 100, 100, false);
    thread1->SetThreadName("test_thread_no_stack");
    dumper.process_.GetOtherThreads().push_back(thread1);
    EXPECT_EQ(dumper.process_.GetOtherThreads().size(), 1u);
    dumper.UnwindOtherThread();
    EXPECT_EQ(dumper.process_.GetOtherThreads().size(), 1u);
}

/**
 * @tc.name: MinidumpDumperTest050
 * @tc.desc: test PrintRegisters with populated regsData collects non-empty registers string
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest050, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {0};
    regsData[31] = 0x8000;
    regsData[32] = 0x1000;
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    dumper.PrintRegisters();
    std::string collectedRegs = CppCrashInfoCollector::Instance().GetRegisters();
    EXPECT_TRUE(!collectedRegs.empty());
}

/**
 * @tc.name: MinidumpDumperTest051
 * @tc.desc: test PrintRegsNearMemory with unwinder and keyThread collects memory near registers
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest051, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    keyThread->SetThreadName("key_thread");
    dumper.process_.SetKeyThread(keyThread);
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {0};
    regsData[31] = 0x8000;
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    dumper.PrintRegsNearMemory();
}

/**
 * @tc.name: MinidumpDumperTest052
 * @tc.desc: test PrintFaultStack with unwinder and keyThread collects fault stack
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest052, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    keyThread->SetThreadName("key_thread");
    dumper.process_.SetKeyThread(keyThread);
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {0};
    regsData[31] = 0x8000;
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    dumper.PrintFaultStack();
}

/**
 * @tc.name: MinidumpDumperTest056
 * @tc.desc: test PrintMaps with two maps entries collects non-empty maps string
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest056, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    auto map1 = std::make_shared<DfxMap>(0x1000, 0x2000, 0, PROT_READ, "/system/lib/a.so");
    auto map2 = std::make_shared<DfxMap>(0x3000, 0x4000, 0, PROT_READ, "/system/lib/b.so");
    dumper.dfxMaps_->AddMap(map1);
    dumper.dfxMaps_->AddMap(map2);
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.PrintMaps();
    std::string mapsStr = CppCrashInfoCollector::Instance().GetMaps();
    EXPECT_TRUE(!mapsStr.empty());
}

/**
 * @tc.name: MinidumpDumperTest073
 * @tc.desc: test PrintMaps with two maps collects non-empty maps string into collector
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest073, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    auto map1 = std::make_shared<DfxMap>(0x1000, 0x2000, 0, PROT_READ, "/system/lib/a.so");
    auto map2 = std::make_shared<DfxMap>(0x3000, 0x4000, 0, PROT_WRITE, "/system/lib/b.so");
    dumper.dfxMaps_->AddMap(map1);
    dumper.dfxMaps_->AddMap(map2);
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.PrintMaps();
    std::string mapsStr = CppCrashInfoCollector::Instance().GetMaps();
    EXPECT_TRUE(!mapsStr.empty());
}

/**
 * @tc.name: MinidumpDumperTest074
 * @tc.desc: test PrintThreadInfo with CPP_CRASH type and keyThread collects tid
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest074, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.request_.type = ProcessDumpType::DUMP_TYPE_CPP_CRASH;
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    keyThread->SetThreadName("test_key_thread");
    dumper.process_.SetKeyThread(keyThread);
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {};
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    dumper.PrintThreadInfo();
    EXPECT_EQ(CppCrashInfoCollector::Instance().GetKeyThread().tid, getpid());
}

/**
 * @tc.name: MinidumpDumperTest075
 * @tc.desc: test PrintRegisters with regs and collector collects non-empty registers string
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest075, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {};
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    dumper.PrintRegisters();
    std::string collectedRegs = CppCrashInfoCollector::Instance().GetRegisters();
    EXPECT_TRUE(!collectedRegs.empty());
}

/**
 * @tc.name: MinidumpDumperTest076
 * @tc.desc: test PrintOtherThreadInfo with CPP_CRASH type collects two other threads
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest076, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.request_.type = ProcessDumpType::DUMP_TYPE_CPP_CRASH;
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto thread1 = DfxThread::Create(getpid(), 100, 100, false);
    thread1->SetThreadName("test_other_thread_1");
    auto thread2 = DfxThread::Create(getpid(), 200, 200, false);
    thread2->SetThreadName("test_other_thread_2");
    dumper.process_.GetOtherThreads().push_back(thread1);
    dumper.process_.GetOtherThreads().push_back(thread2);
    dumper.PrintOtherThreadInfo();
    EXPECT_EQ(CppCrashInfoCollector::Instance().GetOtherThreads().size(), 2);
}

/**
 * @tc.name: MinidumpDumperTest077
 * @tc.desc: test PrintRegsNearMemory with unwinder and keyThread processes memory near registers
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest077, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    keyThread->SetThreadName("key_thread");
    dumper.process_.SetKeyThread(keyThread);
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {};
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    dumper.PrintRegsNearMemory();
}

/**
 * @tc.name: MinidumpDumperTest078
 * @tc.desc: test PrintFaultStack with unwinder and keyThread processes fault stack
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest078, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    keyThread->SetThreadName("key_thread");
    dumper.process_.SetKeyThread(keyThread);
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {};
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    dumper.PrintFaultStack();
}

/**
 * @tc.name: MinidumpDumperTest079
 * @tc.desc: test PrintDumpInfo with full setup collects non-zero pid
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest079, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    keyThread->SetThreadName("key_thread");
    dumper.process_.SetKeyThread(keyThread);
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {};
    regsData[31] = 0x8000;
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.PrintDumpInfo();
    EXPECT_TRUE(CppCrashInfoCollector::Instance().GetPid() != 0);
}

/**
 * @tc.name: MinidumpDumperTest080
 * @tc.desc: test UnwindProcess with unwinder and other threads runs without crash
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest080, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    dumper.process_.SetKeyThread(keyThread);
    dumper.unwinder_ = std::make_shared<Unwinder>();
    auto otherThread = DfxThread::Create(getpid(), 100, 100, false);
    otherThread->SetThreadName("other_thread");
    dumper.process_.GetOtherThreads().push_back(otherThread);
    dumper.UnwindProcess();
}

/**
 * @tc.name: MinidumpDumperTest081
 * @tc.desc: test UnwindOtherThread with unwinder and other thread runs without crash
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest081, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto otherThread = DfxThread::Create(getpid(), 100, 100, false);
    otherThread->SetThreadName("other_thread");
    dumper.process_.GetOtherThreads().push_back(otherThread);
    dumper.UnwindOtherThread();
}

/**
 * @tc.name: MinidumpDumperTest082
 * @tc.desc: test PrintHeader with long process name matches collector fields
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest082, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.CollectDumpHeaderInfo(getpid());
    std::string processName = "test_proc_long_name_for_strcpy";
    (void)strcpy_s(dumper.request_.processName, sizeof(dumper.request_.processName), processName.c_str());
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), processName);
    dumper.PrintHeader();
    EXPECT_EQ(CppCrashInfoCollector::Instance().GetPid(), getpid());
    EXPECT_EQ(CppCrashInfoCollector::Instance().GetUid(), getuid());
    std::string pname = CppCrashInfoCollector::Instance().GetPname();
    EXPECT_EQ(pname, std::string(dumper.request_.processName));
}

/**
 * @tc.name: MinidumpDumperTest083
 * @tc.desc: test PrintOtherThreadInfo with DUMP_TYPE_DUMP_CATCH runs without crash
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest083, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.request_.type = ProcessDumpType::DUMP_TYPE_DUMP_CATCH;
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto thread1 = DfxThread::Create(getpid(), 100, 100, false);
    thread1->SetThreadName("thread1");
    dumper.process_.GetOtherThreads().push_back(thread1);
    dumper.PrintOtherThreadInfo();
}

/**
 * @tc.name: MinidumpDumperTest084
 * @tc.desc: test UnwindOtherThread with other thread having regs and stack runs without crash
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest084, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto otherThread = DfxThread::Create(getpid(), 100, 100, false);
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {};
    regsData[31] = 0x7000;
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    otherThread->SetThreadRegs(regs);
    auto stackBuf = std::make_shared<std::vector<uint8_t>>(TEST_BUFFER_SIZE, 0);
    otherThread->SetThreadStackBuffer(stackBuf);
    otherThread->SetStartOfStackMemory(0x7000);
    dumper.process_.GetOtherThreads().push_back(otherThread);
    dumper.UnwindOtherThread();
    EXPECT_FALSE(otherThread->GetFrames().empty());
}

/**
 * @tc.name: MinidumpDumperTest087
 * @tc.desc: test PrintMaps with empty DfxMaps collects empty maps string
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest087, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.PrintMaps();
    std::string mapsStr = CppCrashInfoCollector::Instance().GetMaps();
    EXPECT_TRUE(mapsStr.empty());
}

/**
 * @tc.name: MinidumpDumperTest088
 * @tc.desc: test PrintRegisters strips Registers prefix from collector output
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest088, TestSize.Level2)
{
    MinidumpDumper dumper;
    dumper.request_.type = ProcessDumpType::DUMP_TYPE_CPP_CRASH;
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    keyThread->SetThreadName("test_key_thread");
    dumper.process_.SetKeyThread(keyThread);
    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {};
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    dumper.process_.SetFaultThreadRegisters(regs);
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.PrintRegisters();
    std::string collectedRegs = CppCrashInfoCollector::Instance().GetRegisters();
    EXPECT_TRUE(collectedRegs.find("Registers:\n") != 0);
}

/**
 * @tc.name: MinidumpDumperTest097
 * @tc.desc: test UnwindProcess with keyThread having regs and stack succeeds
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest097, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");
    auto keyThread = DfxThread::Create(getpid(), getpid(), getpid(), false);
    keyThread->SetThreadName("key_thread");

    uintptr_t regsData[MD_CONTEXT_ARM64_GPR_COUNT] = {};
    regsData[31] = 0x7000;
    regsData[32] = 0x1000;
    auto regs = DfxRegs::CreateFromRegs(UnwindMode::DWARF_UNWIND, regsData, MD_CONTEXT_ARM64_GPR_COUNT);
    keyThread->SetThreadRegs(regs);

    auto stackBuf = std::make_shared<std::vector<uint8_t>>(TEST_BUFFER_SIZE, 0);
    keyThread->SetThreadStackBuffer(stackBuf);
    keyThread->SetStartOfStackMemory(0x7000);

    dumper.process_.SetKeyThread(keyThread);
    dumper.UnwindProcess();
    EXPECT_NE(dumper.unwinder_, nullptr);
}

/**
 * @tc.name: MinidumpDumperTest098
 * @tc.desc: test UnwindOtherThread with otherThread having stack preserves thread count
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest098, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.unwinder_ = std::make_shared<Unwinder>();
    dumper.dfxMaps_ = std::make_shared<DfxMaps>();
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");

    auto otherThread = DfxThread::Create(getpid(), 100, 100, false);
    otherThread->SetThreadName("other_thread");
    auto stackBuf = std::make_shared<std::vector<uint8_t>>(TEST_BUFFER_SIZE, 0);
    otherThread->SetThreadStackBuffer(stackBuf);
    otherThread->SetStartOfStackMemory(0x7000);

    dumper.process_.GetOtherThreads().push_back(otherThread);
    size_t prevSize = dumper.process_.GetOtherThreads().size();
    dumper.UnwindOtherThread();
    EXPECT_EQ(dumper.process_.GetOtherThreads().size(), prevSize);
    EXPECT_TRUE(otherThread->GetFrames().empty());
}

/**
 * @tc.name: MinidumpDumperTest099
 * @tc.desc: test PrintRegisters with MockDfxRegsNoPrefix strips prefix from collector output
 * @tc.type: FUNC
 */
HWTEST_F(MinidumpDumperTest, MinidumpDumperTest099, TestSize.Level2)
{
    MinidumpDumper dumper;
    CppCrashInfoCollector::Instance().SetNeedFormatFlag(true);
    dumper.process_.InitProcessInfo(getpid(), getpid(), getuid(), "test_proc");

    auto mockRegs = std::make_shared<MockDfxRegsNoPrefix>();
    dumper.process_.SetFaultThreadRegisters(mockRegs);
    dumper.PrintRegisters();

    std::string collectedRegs = CppCrashInfoCollector::Instance().GetRegisters();
    EXPECT_TRUE(!collectedRegs.empty());
    EXPECT_TRUE(collectedRegs.find("Registers:\n") != 0);
}

