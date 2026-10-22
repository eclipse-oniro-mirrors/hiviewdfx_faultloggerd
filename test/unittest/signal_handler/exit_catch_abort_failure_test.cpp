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

#include <gtest/gtest.h>
#include <cstdint>

#include "dfx_define.h"
#include "dfx_dumprequest.h"
#include "dfx_signal_handler.h"

using namespace testing::ext;

namespace {
bool g_setDumpableResult = true;
bool g_setDieCatchResult = true;
uint32_t g_setDumpableCalls = 0;
uint32_t g_setDieCatchCalls = 0;
uint32_t g_restoreDumpableCalls = 0;
uint32_t g_lastFlag = 0;
bool g_lastEnable = false;
}

// These dependencies are linked only into the isolated API test executable.
extern "C" bool DFX_SetDumpableState(void)
{
    ++g_setDumpableCalls;
    return g_setDumpableResult;
}

extern "C" bool SetDieCatch(uint32_t flag, bool enable)
{
    ++g_setDieCatchCalls;
    g_lastFlag = flag;
    g_lastEnable = enable;
    return g_setDieCatchResult;
}

extern "C" void DFX_RestoreDumpableState(void)
{
    ++g_restoreDumpableCalls;
}

namespace OHOS {
namespace HiviewDFX {
class ExitCatchAbortFailureTest : public testing::Test {
protected:
    void SetUp() override
    {
        g_setDumpableResult = true;
        g_setDieCatchResult = true;
        g_setDumpableCalls = 0;
        g_setDieCatchCalls = 0;
        g_restoreDumpableCalls = 0;
        g_lastFlag = 0;
        g_lastEnable = false;
    }
};

/**
 * @tc.name: DfxNotifySetExitCatchAbort008
 * @tc.desc: A dumpable failure stops configuration before changing any flags.
 * @tc.type: FUNC
 */
HWTEST_F(ExitCatchAbortFailureTest, DfxNotifySetExitCatchAbort008, TestSize.Level2)
{
    g_setDumpableResult = false;
    EXPECT_EQ(DfxNotifySetExitCatchAbort(true, true), -1);
    EXPECT_EQ(g_setDumpableCalls, 1U);
    EXPECT_EQ(g_setDieCatchCalls, 0U);
    EXPECT_EQ(g_restoreDumpableCalls, 0U);
}

/**
 * @tc.name: DfxNotifySetExitCatchAbort009
 * @tc.desc: A successful request passes the exit mask and restores dumpable.
 * @tc.type: FUNC
 */
HWTEST_F(ExitCatchAbortFailureTest, DfxNotifySetExitCatchAbort009, TestSize.Level2)
{
    EXPECT_EQ(DfxNotifySetExitCatchAbort(true, true), 0);
    EXPECT_EQ(g_setDumpableCalls, 1U);
    EXPECT_EQ(g_setDieCatchCalls, 1U);
    EXPECT_EQ(g_lastFlag, EXIT_CATCH_ABORT_MASK);
    EXPECT_TRUE(g_lastEnable);
    EXPECT_EQ(g_restoreDumpableCalls, 1U);
}

/**
 * @tc.name: DfxNotifySetExitCatchAbort010
 * @tc.desc: A failed disable request still restores dumpable and returns failure.
 * @tc.type: FUNC
 */
HWTEST_F(ExitCatchAbortFailureTest, DfxNotifySetExitCatchAbort010, TestSize.Level2)
{
    g_setDieCatchResult = false;
    EXPECT_EQ(DfxNotifySetExitCatchAbort(false, true), -1);
    EXPECT_EQ(g_setDumpableCalls, 1U);
    EXPECT_EQ(g_setDieCatchCalls, 1U);
    EXPECT_EQ(g_lastFlag, EXIT_CATCH_ABORT_MASK);
    EXPECT_FALSE(g_lastEnable);
    EXPECT_EQ(g_restoreDumpableCalls, 1U);
}

/**
 * @tc.name: DfxNotifySetExitCatchAbort011
 * @tc.desc: Non-debug requests do not call the configuration dependencies.
 * @tc.type: FUNC
 */
HWTEST_F(ExitCatchAbortFailureTest, DfxNotifySetExitCatchAbort011, TestSize.Level2)
{
    g_setDumpableResult = false;
    EXPECT_EQ(DfxNotifySetExitCatchAbort(true, false), 0);
    EXPECT_EQ(g_setDumpableCalls, 0U);
    EXPECT_EQ(g_setDieCatchCalls, 0U);
    EXPECT_EQ(g_restoreDumpableCalls, 0U);
}
} // namespace HiviewDFX
} // namespace OHOS
