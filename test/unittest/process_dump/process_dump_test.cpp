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

#include <gtest/gtest.h>
#include <memory>
#include <string>

#include "dfx_regs.h"
#include "dfx_regs_get.h"
#include "dfx_dump_request.h"
#include "dfx_thread.h"
#include "process_dumper.h"
#include "dfx_unwind_remote.h"
#include "dfx_util.h"
#include "dfx_test_util.h"

using namespace OHOS::HiviewDFX;
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace HiviewDFX {
class ProcessDumpTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() {}
    void TearDown() {}
};
} // namespace HiviewDFX
} // namespace OHOS

namespace {
/**
 * @tc.name: DfxProcessTest001
 * @tc.desc: test DfxProcess Create
 * @tc.type: FUNC
 */
HWTEST_F (ProcessDumpTest, DfxProcessTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxProcessTest001: start.";
    std::shared_ptr<DfxProcess> process = DfxProcess::Create(getpid(), getpid());
    EXPECT_EQ(false, process == nullptr) << "DfxProcessTest001 Failed";
    GTEST_LOG_(INFO) << "DfxProcessTest001: end.";
}

/**
 * @tc.name: DfxProcessTest002
 * @tc.desc: test init process threads
 * @tc.type: FUNC
 */
HWTEST_F (ProcessDumpTest, DfxProcessTest002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxProcessTest002: start.";
    pid_t accountmgrPid = GetProcessPid(ACCOUNTMGR_NAME);
    if (accountmgrPid == 0) {
        GTEST_LOG_(INFO) << "DfxProcessTest002: get pid failed.";
        return;
    }
    pid_t pid = accountmgrPid;
    pid_t tid = accountmgrPid;
    auto keyThread = DfxThread::Create(pid, tid, tid);
    auto process = DfxProcess::Create(pid, pid);
    EXPECT_EQ(true, process != nullptr) << "DfxProcessTest002 Failed";
    GTEST_LOG_(INFO) << "DfxProcessTest002: end.";
}

/**
 * @tc.name: DfxProcessTest003
 * @tc.desc: test init other threads
 * @tc.type: FUNC
 */
HWTEST_F (ProcessDumpTest, DfxProcessTest003, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxProcessTest003: start.";
    std::shared_ptr<DfxProcess> process = DfxProcess::Create(getpid(), getpid());
    auto ret = process->InitOtherThreads();
    EXPECT_EQ(true, ret) << "DfxProcessTest003 Failed";
    auto threads = process->GetOtherThreads();
    EXPECT_GT(threads.size(), 0) << "DfxProcessTest003 Failed";
    process->ClearOtherThreads();
    threads = process->GetOtherThreads();
    EXPECT_EQ(threads.size(), 0) << "DfxProcessTest003 Failed";
    GTEST_LOG_(INFO) << "DfxProcessTest003: end.";
}

/**
 * @tc.name: DfxProcessTest004
 * @tc.desc: test Attach Detach
 * @tc.type: FUNC
 */
HWTEST_F (ProcessDumpTest, DfxProcessTest004, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxProcessTest004: start.";
    std::shared_ptr<DfxProcess> process = DfxProcess::Create(getpid(), getpid());
    auto ret = process->InitOtherThreads();
    EXPECT_EQ(true, ret) << "DfxProcessTest004 Failed";
    process->Attach();
    process->Detach();
    GTEST_LOG_(INFO) << "DfxProcessTest004: end.";
}

/**
 * @tc.name: DfxThreadTest001
 * @tc.desc: test DfxThread Create
 * @tc.type: FUNC
 */
HWTEST_F (ProcessDumpTest, DfxThreadTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxThreadTest001: start.";
    int32_t pid = 1, tid = 1;
    auto thread = DfxThread::Create(pid, tid, tid);
    EXPECT_EQ(true, thread != nullptr) << "DfxThreadTest001 failed";
    GTEST_LOG_(INFO) << "DfxThreadTest001: end.";
}

/**
 * @tc.name: DfxThreadTest002
 * @tc.desc: test DfxThread GetThreadRegs
 * @tc.type: FUNC
 */
HWTEST_F (ProcessDumpTest, DfxThreadTest002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxThreadTest002: start.";
    int32_t pid = 243, tid = 243;
    std::shared_ptr<DfxThread> thread = std::make_shared<DfxThread>(pid, tid, tid);
    std::shared_ptr<DfxRegs> inputrefs;
    thread->SetThreadRegs(inputrefs);
    std::shared_ptr<DfxRegs> outputrefs = thread->GetThreadRegs();
    EXPECT_EQ(true, inputrefs == outputrefs) << "DfxThreadTest002 Failed";
    GTEST_LOG_(INFO) << "DfxThreadTest002: end.";
}

/**
 * @tc.name: DfxUnwindRemoteTest001
 * @tc.desc: test DfxUnwindRemote UnwindProcess
 * @tc.type: FUNC
 */
HWTEST_F (ProcessDumpTest, DfxUnwindRemoteTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxUnwindRemoteTest001: start.";
    pid_t pid = GetProcessPid(ACCOUNTMGR_NAME);
    pid_t tid = pid;
    std::shared_ptr<DfxThread> thread = DfxThread::Create(pid, tid, tid);
    std::shared_ptr<DfxProcess> process = DfxProcess::Create(pid, pid);
    auto unwinder = std::make_shared<Unwinder>(pid);
    process->keyThread_ = thread;
    thread->Attach();
    thread->SetThreadRegs(DfxRegs::CreateRemoteRegs(pid));
    std::shared_ptr<ProcessDumpRequest> request = std::make_shared<ProcessDumpRequest>();
    bool ret = DfxUnwindRemote::GetInstance().UnwindProcess(request, process, unwinder);
    thread->Detach();
    EXPECT_EQ(true, ret) << "DfxUnwindRemoteTest001 Failed";
    GTEST_LOG_(INFO) << "DfxUnwindRemoteTest001: end.";
}
}
