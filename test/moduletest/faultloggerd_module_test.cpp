/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include "faultloggerd_module_test.h"

#include <securec.h>
#include <sstream>
#include <unistd.h>

#include "dfx_test_util.h"
#include "faultloggerd_client.h"

using namespace OHOS::HiviewDFX;
using namespace testing::ext;

namespace {
void WaitForServiceReady(const std::string& serviceName)
{
    int pid = GetProcessPid(serviceName);
    if (pid <= 0) {
        std::string cmd = "start " + serviceName;
        ExecuteCommands(cmd);
        const int sleepTime = 10; // 10 seconds
        sleep(sleepTime);
        pid = GetProcessPid(serviceName);
    }
    ASSERT_GT(pid, 0);
    ASSERT_TRUE(CheckConnectStatus());
}

void CheckFdRequestFunction(FaultLoggerType type, bool isValidFd)
{
    int32_t fd = RequestFileDescriptor(static_cast<int32_t>(type));
    ASSERT_EQ((fd >= 0), isValidFd);
    if (fd >= 0) {
        close(fd);
    }
}

/**
 * @tc.name: FaultloggerdServiceTest001
 * @tc.desc: check faultloggerd running status and ensure it has been started
 * @tc.type: FUNC
 */
HWTEST_F(FaultloggerdModuleTest, FaultloggerdServiceTest001, TestSize.Level0)
{
    WaitForServiceReady("faultloggerd");
}

#if defined(__BIONIC__)
/**
 * @tc.name: FaultloggerdDfxHandlerPreloadTest001
 * @tc.desc: check whether libdfx_signalhandler.z.so is preloaded.
 * @tc.type: FUNC
 */
HWTEST_F(FaultloggerdModuleTest, FaultloggerdDfxHandlerPreloadTest001, TestSize.Level0)
{
    std::string cmd = "cat /proc/" + std::to_string(getpid()) + "/maps";
    std::string result = ExecuteCommands(cmd);
    ASSERT_EQ(result.find("libdfx_signalhandler.z.so") != std::string::npos, true);
}
#endif

/**
 * @tc.name: FaultloggerdClientFdRquestTest001
 * @tc.desc: check faultloggerd logging function
 * @tc.type: FUNC
 */
HWTEST_F(FaultloggerdModuleTest, FaultloggerdClientFdRquestTest001, TestSize.Level0)
{
    CheckFdRequestFunction(FaultLoggerType::CPP_CRASH, true);
    CheckFdRequestFunction(FaultLoggerType::CPP_STACKTRACE, true);
    CheckFdRequestFunction(FaultLoggerType::JS_STACKTRACE, true);
    CheckFdRequestFunction(FaultLoggerType::JS_HEAP_SNAPSHOT, true);
    CheckFdRequestFunction(FaultLoggerType::LEAK_STACKTRACE, true);
}

/**
 * @tc.name: FaultloggerdClientFdRquestTest002
 * @tc.desc: check faultloggerd RequestLogFileDescriptor function
 * @tc.type: FUNC
 */
HWTEST_F(FaultloggerdModuleTest, FaultloggerdClientFdRquestTest002, TestSize.Level0)
{
    struct FaultLoggerdRequest testRequest;
    if (memset_s(&testRequest, sizeof(testRequest), 0, sizeof(struct FaultLoggerdRequest)) != 0) {
        return;
    }
    testRequest.type = (int)FaultLoggerType::CPP_CRASH;
    testRequest.pid = getpid();
    testRequest.tid = gettid();
    testRequest.uid = getuid();
    int32_t fd = RequestLogFileDescriptor(&testRequest);
    ASSERT_TRUE(fd >= 0);
    if (fd >= 0) {
        close(fd);
    }
}

/**
 * @tc.name: FaultloggerdClientFdRquestTest003
 * @tc.desc: check faultloggerd RequestPrintTHilog function
 * @tc.type: FUNC
 */
HWTEST_F(FaultloggerdModuleTest, FaultloggerdClientFdRquestTest003, TestSize.Level0)
{
    char msg[] = "test log";
    size_t len = strlen(msg);
    ASSERT_EQ(RequestPrintTHilog(msg, len), 0);
}

/**
 * @tc.name: FaultloggerdClientFdRquestTest004
 * @tc.desc: check faultloggerd RequestFileDescriptorEx function
 * @tc.type: FUNC
 */
HWTEST_F(FaultloggerdModuleTest, FaultloggerdClientFdRquestTest004, TestSize.Level0)
{
    struct FaultLoggerdRequest testRequest;
    if (memset_s(&testRequest, sizeof(testRequest), 0, sizeof(struct FaultLoggerdRequest)) != 0) {
        return;
    }
    testRequest.type = (int)FaultLoggerType::CPP_CRASH;
    testRequest.pid = getpid();
    testRequest.tid = gettid();
    testRequest.uid = getuid();
    int32_t fd = RequestFileDescriptorEx(&testRequest);
    ASSERT_TRUE(fd >= 0);
    if (fd >= 0) {
        close(fd);
    }
}

/**
 * @tc.name: FaultloggerdClientPipeFdRquestTest001
 * @tc.desc: check faultloggerd RequestPipeFd function
 * @tc.type: FUNC
 */
HWTEST_F(FaultloggerdModuleTest, FaultloggerdClientPipeFdRquestTest001, TestSize.Level0)
{
    sleep(8); // 8 ：Wait 8s to ensure the last request to complete.
    RequestSdkDump(getpid(), getpid());
    int32_t pipeFd = RequestPipeFd(getpid(), FaultLoggerPipeType::PIPE_FD_READ_BUF);
    ASSERT_NE(pipeFd, -1);
    int32_t ret = RequestDelPipeFd(getpid());
    ASSERT_EQ(ret, 0);
    pipeFd = RequestPipeFd(getpid(), FaultLoggerPipeType::PIPE_FD_READ_BUF);
    ASSERT_EQ(pipeFd, -1);
}

/**
 * @tc.name: FaultloggerdClientPipeFdRquestTest002
 * @tc.desc: check faultloggerd RequestPipeFd function by param error
 * @tc.type: FUNC
 */
HWTEST_F(FaultloggerdModuleTest, FaultloggerdClientPipeFdRquestTest002, TestSize.Level0)
{
    RequestSdkDump(getpid(), getpid());
    int32_t pipeFd = RequestPipeFd(getpid(), -1);
    ASSERT_EQ(pipeFd, -1);
    pipeFd = RequestPipeFd(getpid(), FaultLoggerPipeType::PIPE_FD_DELETE);
    ASSERT_EQ(pipeFd, -1);
}

/**
 * @tc.name: FaultloggerdPermissionCheckTest001
 * @tc.desc: check faultloggerd RequestCheckPermission function
 * @tc.type: FUNC
 */
HWTEST_F(FaultloggerdModuleTest, FaultloggerdPermissionCheckTest001, TestSize.Level0)
{
    ASSERT_TRUE(RequestCheckPermission(getpid()));
}
}
