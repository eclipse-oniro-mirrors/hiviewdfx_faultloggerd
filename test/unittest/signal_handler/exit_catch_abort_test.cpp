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
#include <cerrno>
#include <cstdint>
#include <cstring>
#include <fcntl.h>
#include <initializer_list>
#include <securec.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "dfx_define.h"
#include "dfx_dumprequest.h"
#include "dfx_signal_handler.h"

using namespace testing::ext;

namespace OHOS {
namespace HiviewDFX {
class ExitCatchAbortTest : public testing::Test {
protected:
    void SetUp() override
    {
        originalDumpable_ = prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L);
        ASSERT_GE(originalDumpable_, 0);
        if (originalDumpable_ != 0 && originalDumpable_ != 1) {
            GTEST_SKIP() << "Original dumpable value cannot be restored with PR_SET_DUMPABLE";
        }
        restoreDumpable_ = true;
        ASSERT_EQ(prctl(PR_SET_DUMPABLE, 1L, 0L, 0L, 0L), 0);
        fd_ = open("/proc/self/unexpected_die_catch", O_RDWR | O_CLOEXEC);
        if (fd_ < 0 && (errno == ENOENT || errno == ENOTDIR)) {
            return;
        }
        ASSERT_GE(fd_, 0) << strerror(errno);
        ASSERT_TRUE(ReadFlags(originalFlags_));
        restoreFlags_ = true;
        ASSERT_EQ(prctl(PR_SET_DUMPABLE, static_cast<long>(originalDumpable_), 0L, 0L, 0L), 0);
    }

    void TearDown() override
    {
        if (restoreFlags_) {
            EXPECT_EQ(prctl(PR_SET_DUMPABLE, 1L, 0L, 0L, 0L), 0);
            EXPECT_TRUE(WriteFlags(originalFlags_));
            uint32_t actualFlags = 0;
            EXPECT_TRUE(ReadFlags(actualFlags));
            EXPECT_EQ(actualFlags, originalFlags_);
        }
        if (fd_ >= 0) {
            EXPECT_EQ(close(fd_), 0);
            fd_ = -1;
        }
        if (restoreDumpable_) {
            EXPECT_EQ(prctl(PR_SET_DUMPABLE, static_cast<long>(originalDumpable_), 0L, 0L, 0L), 0);
        }
    }

    bool ReadFlags(uint32_t& flags)
    {
        char value[32] = {0};
        if (lseek(fd_, 0, SEEK_SET) < 0) {
            return false;
        }
        ssize_t size = OHOS_TEMP_FAILURE_RETRY(read(fd_, value, sizeof(value) - 1));
        return size > 0 && sscanf_s(value, "%x", &flags) == 1;
    }

    bool WriteFlags(uint32_t flags)
    {
        char value[32] = {0};
        int length = snprintf_s(value, sizeof(value), sizeof(value) - 1, "0x%x", flags);
        if (length < 0) {
            return false;
        }
        if (lseek(fd_, 0, SEEK_SET) < 0) {
            return false;
        }
        size_t size = static_cast<size_t>(length) + 1;
        return OHOS_TEMP_FAILURE_RETRY(write(fd_, value, size)) == static_cast<ssize_t>(size);
    }

    int fd_ {-1};
    int originalDumpable_ {-1};
    uint32_t originalFlags_ {0};
    bool restoreDumpable_ {false};
    bool restoreFlags_ {false};
};

class DieCatchFlagTest : public testing::Test {};

/**
 * @tc.name: SetDieCatchRejectsInvalidFlags
 * @tc.desc: Reject unsupported masks before accessing the kernel node.
 * @tc.type: FUNC
 */
HWTEST_F(DieCatchFlagTest, SetDieCatchRejectsInvalidFlags, TestSize.Level2)
{
    for (uint32_t flag : {0U, CRASH_SNAPSHOT_FLAG | EXIT_CATCH_ABORT_MASK, UINT32_MAX}) {
        EXPECT_FALSE(SetDieCatch(flag, true));
        EXPECT_FALSE(SetDieCatch(flag, false));
    }
}

class ExitCatchAbortNodeTest : public ExitCatchAbortTest {
protected:
    void SetUp() override
    {
        ExitCatchAbortTest::SetUp();
        if (HasFatalFailure() || !restoreDumpable_) {
            return;
        }
        if (fd_ < 0) {
            GTEST_SKIP() << "Kernel does not expose unexpected_die_catch";
        }
        ASSERT_EQ(prctl(PR_SET_DUMPABLE, 1L, 0L, 0L, 0L), 0);
        baselineFlags_ = (originalFlags_ & ~EXIT_CATCH_ABORT_MASK) | CRASH_SNAPSHOT_FLAG;
        ASSERT_TRUE(WriteFlags(baselineFlags_));
        uint32_t actualFlags = 0;
        ASSERT_TRUE(ReadFlags(actualFlags));
        ASSERT_EQ(actualFlags, baselineFlags_);
    }

    uint32_t baselineFlags_ {0};
};

/**
 * @tc.name: DfxNotifySetExitCatchAbort001
 * @tc.desc: A non-debug enable request succeeds without changing dumpable.
 * @tc.type: FUNC
 */
HWTEST_F(ExitCatchAbortTest, DfxNotifySetExitCatchAbort001, TestSize.Level2)
{
    for (int dumpable : {0, 1}) {
        ASSERT_EQ(prctl(PR_SET_DUMPABLE, static_cast<long>(dumpable), 0L, 0L, 0L), 0);
        EXPECT_EQ(DfxNotifySetExitCatchAbort(true, false), 0);
        EXPECT_EQ(prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L), dumpable);
    }
}

/**
 * @tc.name: DfxNotifySetExitCatchAbort002
 * @tc.desc: A non-debug disable request succeeds without changing dumpable.
 * @tc.type: FUNC
 */
HWTEST_F(ExitCatchAbortTest, DfxNotifySetExitCatchAbort002, TestSize.Level2)
{
    for (int dumpable : {0, 1}) {
        ASSERT_EQ(prctl(PR_SET_DUMPABLE, static_cast<long>(dumpable), 0L, 0L, 0L), 0);
        EXPECT_EQ(DfxNotifySetExitCatchAbort(false, false), 0);
        EXPECT_EQ(prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L), dumpable);
    }
}

/**
 * @tc.name: DfxNotifySetExitCatchAbort003
 * @tc.desc: A debug enable request sets the exit mask and preserves other flags.
 * @tc.type: FUNC
 */
HWTEST_F(ExitCatchAbortNodeTest, DfxNotifySetExitCatchAbort003, TestSize.Level2)
{
    ASSERT_EQ(DfxNotifySetExitCatchAbort(true, true), 0);
    uint32_t flags = 0;
    ASSERT_TRUE(ReadFlags(flags));
    EXPECT_EQ(flags, baselineFlags_ | EXIT_CATCH_ABORT_MASK);
    EXPECT_EQ(prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L), 1);
}

/**
 * @tc.name: DfxNotifySetExitCatchAbort004
 * @tc.desc: A debug disable request clears only the exit mask.
 * @tc.type: FUNC
 */
HWTEST_F(ExitCatchAbortNodeTest, DfxNotifySetExitCatchAbort004, TestSize.Level2)
{
    ASSERT_EQ(DfxNotifySetExitCatchAbort(true, true), 0);
    uint32_t flags = 0;
    ASSERT_TRUE(ReadFlags(flags));
    ASSERT_EQ(flags, baselineFlags_ | EXIT_CATCH_ABORT_MASK);
    ASSERT_EQ(DfxNotifySetExitCatchAbort(false, true), 0);
    ASSERT_TRUE(ReadFlags(flags));
    EXPECT_EQ(flags, baselineFlags_);
    EXPECT_EQ(prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L), 1);
}

/**
 * @tc.name: DfxNotifySetExitCatchAbort005
 * @tc.desc: A non-debug enable request leaves the node unchanged.
 * @tc.type: FUNC
 */
HWTEST_F(ExitCatchAbortNodeTest, DfxNotifySetExitCatchAbort005, TestSize.Level2)
{
    ASSERT_EQ(DfxNotifySetExitCatchAbort(true, false), 0);
    uint32_t flags = 0;
    ASSERT_TRUE(ReadFlags(flags));
    EXPECT_EQ(flags, baselineFlags_);
    EXPECT_EQ(prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L), 1);
}

/**
 * @tc.name: DfxNotifySetExitCatchAbort006
 * @tc.desc: A non-debug disable request does not clear existing exit flags.
 * @tc.type: FUNC
 */
HWTEST_F(ExitCatchAbortNodeTest, DfxNotifySetExitCatchAbort006, TestSize.Level2)
{
    ASSERT_EQ(DfxNotifySetExitCatchAbort(true, true), 0);
    uint32_t flags = 0;
    ASSERT_TRUE(ReadFlags(flags));
    ASSERT_EQ(flags, baselineFlags_ | EXIT_CATCH_ABORT_MASK);
    ASSERT_EQ(DfxNotifySetExitCatchAbort(false, false), 0);
    ASSERT_TRUE(ReadFlags(flags));
    EXPECT_EQ(flags, baselineFlags_ | EXIT_CATCH_ABORT_MASK);
    EXPECT_EQ(prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L), 1);
}

/**
 * @tc.name: DfxNotifySetExitCatchAbort007
 * @tc.desc: Repeated requests preserve flags and restore dumpable values zero and one.
 * @tc.type: FUNC
 */
HWTEST_F(ExitCatchAbortNodeTest, DfxNotifySetExitCatchAbort007, TestSize.Level2)
{
    for (int dumpable : {0, 1}) {
        ASSERT_EQ(prctl(PR_SET_DUMPABLE, static_cast<long>(dumpable), 0L, 0L, 0L), 0);
        for (bool enable : {true, true, false, false}) {
            ASSERT_EQ(DfxNotifySetExitCatchAbort(enable, true), 0);
            EXPECT_EQ(prctl(PR_GET_DUMPABLE, 0L, 0L, 0L, 0L), dumpable);
            uint32_t flags = 0;
            ASSERT_TRUE(ReadFlags(flags));
            EXPECT_EQ(flags, enable ? (baselineFlags_ | EXIT_CATCH_ABORT_MASK) : baselineFlags_);
        }
    }
}
} // namespace HiviewDFX
} // namespace OHOS
