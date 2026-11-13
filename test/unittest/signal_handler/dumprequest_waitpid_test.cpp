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

#include <cerrno>
#include <chrono>
#include <csignal>
#include <gtest/gtest.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "dumprequest_waitpid_test.h"

using namespace testing::ext;

namespace {
using SteadyClock = std::chrono::steady_clock;

constexpr int WAIT_TIMEOUT_MS = 3000;
constexpr int SHORT_TIMEOUT_MS = 300;
constexpr int TIMEOUT_TOLERANCE_MS = 500;
// Lower-bound tolerance: the production returns as soon as the monotonic
// deadline is reached, but both the production clock and the test clock floor
// sub-millisecond time to ms, so the measured elapsed can be a few ms under
// the nominal timeout without indicating a premature return.
constexpr int TIMEOUT_LOWER_TOLERANCE_MS = 50;
constexpr int CHILD_LONG_SLEEP_SEC = 5;
constexpr int CHILD_ALARM_SEC = 1;
constexpr int EXIT_CODE_ONE = 1;
constexpr int EXIT_CODE_ZERO = 0;

enum class ChildBehavior {
    EXIT_ZERO,
    EXIT_ONE,
    EXIT_BY_ALARM,
    SLEEP_LONG,
    EXIT_BY_SIGSEGV,
};

struct ChildHandle {
    pid_t pid = 0;
    int releaseFd = -1; // write here to release the child from its initial wait
};

ChildHandle ForkChild(ChildBehavior behavior)
{
    ChildHandle handle;
    int pipefd[2] = {-1, -1};
    if (pipe(pipefd) != 0) {
        return handle;
    }
    pid_t pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return handle;
    }
    if (pid == 0) {
        close(pipefd[1]);
        char c = 0;
        ssize_t readRes = 0;
        do {
            readRes = read(pipefd[0], &c, 1);
        } while (readRes < 0 && errno == EINTR);
        close(pipefd[0]);
        switch (behavior) {
            case ChildBehavior::EXIT_ZERO:
                _exit(EXIT_CODE_ZERO);
            case ChildBehavior::EXIT_ONE:
                _exit(EXIT_CODE_ONE);
            case ChildBehavior::EXIT_BY_ALARM:
                signal(SIGALRM, SIG_DFL);
                alarm(CHILD_ALARM_SEC);
                pause();
                _exit(EXIT_CODE_ZERO);
            case ChildBehavior::SLEEP_LONG:
                sleep(CHILD_LONG_SLEEP_SEC);
                _exit(EXIT_CODE_ZERO);
            case ChildBehavior::EXIT_BY_SIGSEGV:
                signal(SIGSEGV, SIG_DFL);
                raise(SIGSEGV);
                _exit(EXIT_CODE_ZERO);
            default:
                _exit(EXIT_CODE_ZERO);
        }
    }
    close(pipefd[0]);
    handle.pid = pid;
    handle.releaseFd = pipefd[1];
    return handle;
}

void ReleaseChild(ChildHandle &handle)
{
    if (handle.releaseFd >= 0) {
        char c = 0;
        write(handle.releaseFd, &c, 1);
        close(handle.releaseFd);
        handle.releaseFd = -1;
    }
}

void KillAndReap(ChildHandle &handle)
{
    if (handle.releaseFd >= 0) {
        close(handle.releaseFd);
        handle.releaseFd = -1;
    }
    if (handle.pid <= 0) {
        return;
    }
    kill(handle.pid, SIGKILL);
    int status = 0;
    pid_t waitRes = 0;
    do {
        waitRes = waitpid(handle.pid, &status, 0);
    } while (waitRes < 0 && errno == EINTR);
    handle.pid = 0;
}

long ElapsedMs(SteadyClock::time_point t0, SteadyClock::time_point t1)
{
    return std::chrono::duration_cast<std::chrono::milliseconds>(t1 - t0).count();
}
}

/**
 * @tc.name: DfxDumpRequestWaitpidTest001
 * @tc.desc: WaitProcessExitTimeout maps a normal child exit to PROCESS_NORMAL_EXIT.
 * @tc.type: FUNC
 */
HWTEST(DfxDumpRequestWaitpidTest, DfxDumpRequestWaitpidTest001, TestSize.Level0)
{
    ChildHandle child = ForkChild(ChildBehavior::EXIT_ZERO);
    ASSERT_GT(child.pid, 0);
    ReleaseChild(child);
    EXPECT_EQ(DfxTestWaitProcessExitTimeout(child.pid, WAIT_TIMEOUT_MS, true),
              DFX_TEST_PROCESS_NORMAL_EXIT);
}

/**
 * @tc.name: DfxDumpRequestWaitpidTest002
 * @tc.desc: WaitProcessExitTimeout maps a SIGALRM-killed child to PROCESS_ALARM_EXIT.
 * @tc.type: FUNC
 */
HWTEST(DfxDumpRequestWaitpidTest, DfxDumpRequestWaitpidTest002, TestSize.Level0)
{
    ChildHandle child = ForkChild(ChildBehavior::EXIT_BY_ALARM);
    ASSERT_GT(child.pid, 0);
    ReleaseChild(child);
    EXPECT_EQ(DfxTestWaitProcessExitTimeout(child.pid, WAIT_TIMEOUT_MS, true),
              DFX_TEST_PROCESS_ALARM_EXIT);
}

/**
 * @tc.name: DfxDumpRequestWaitpidTest003
 * @tc.desc: WaitProcessExitTimeout maps a non-zero exit code to PROCESS_ABNORMAL_EXIT.
 * @tc.type: FUNC
 */
HWTEST(DfxDumpRequestWaitpidTest, DfxDumpRequestWaitpidTest003, TestSize.Level0)
{
    ChildHandle child = ForkChild(ChildBehavior::EXIT_ONE);
    ASSERT_GT(child.pid, 0);
    ReleaseChild(child);
    EXPECT_EQ(DfxTestWaitProcessExitTimeout(child.pid, WAIT_TIMEOUT_MS, true),
              DFX_TEST_PROCESS_ABNORMAL_EXIT);
}

/**
 * @tc.name: DfxDumpRequestWaitpidTest004
 * @tc.desc: WaitProcessExitTimeout times out within the deadline (isPrvi=true skips
 *           FillCrashExceptionAndReport which would otherwise touch g_request).
 * @tc.type: FUNC
 */
HWTEST(DfxDumpRequestWaitpidTest, DfxDumpRequestWaitpidTest004, TestSize.Level1)
{
    ChildHandle child = ForkChild(ChildBehavior::SLEEP_LONG);
    ASSERT_GT(child.pid, 0);
    auto t0 = SteadyClock::now();
    int ret = DfxTestWaitProcessExitTimeout(child.pid, SHORT_TIMEOUT_MS, true);
    auto t1 = SteadyClock::now();
    long elapsed = ElapsedMs(t0, t1);
    EXPECT_EQ(ret, DFX_TEST_PROCESS_ABNORMAL_EXIT);
    EXPECT_GE(elapsed, SHORT_TIMEOUT_MS - TIMEOUT_LOWER_TOLERANCE_MS);
    EXPECT_LE(elapsed, SHORT_TIMEOUT_MS + TIMEOUT_TOLERANCE_MS);
    GTEST_LOG_(INFO) << "WaitProcessExitTimeout timeout elapsed=" << elapsed << "ms";
    KillAndReap(child);
}

/**
 * @tc.name: DfxDumpRequestWaitpidTest005
 * @tc.desc: WaitProcessExitTimeout maps a waitpid error (non-child pid →
 *           ECHILD) to PROCESS_ABNORMAL_EXIT without waiting for the timeout,
 *           matching the pre-refactor behavior (error must not be reported as
 *           a timeout exception).
 * @tc.type: FUNC
 */
HWTEST(DfxDumpRequestWaitpidTest, DfxDumpRequestWaitpidTest005, TestSize.Level1)
{
    auto t0 = SteadyClock::now();
    int ret = DfxTestWaitProcessExitTimeout(getpid(), SHORT_TIMEOUT_MS, true);
    auto t1 = SteadyClock::now();
    long elapsed = ElapsedMs(t0, t1);
    EXPECT_EQ(ret, DFX_TEST_PROCESS_ABNORMAL_EXIT);
    EXPECT_LT(elapsed, SHORT_TIMEOUT_MS);
    GTEST_LOG_(INFO) << "waitpid error path elapsed=" << elapsed << "ms";
}

/**
 * @tc.name: DfxDumpRequestWaitpidTest006
 * @tc.desc: WaitProcessExitTimeout maps a child killed by SIGSEGV (non-SIGALRM
 *           signal) to PROCESS_ABNORMAL_EXIT.
 * @tc.type: FUNC
 */
HWTEST(DfxDumpRequestWaitpidTest, DfxDumpRequestWaitpidTest006, TestSize.Level0)
{
    ChildHandle child = ForkChild(ChildBehavior::EXIT_BY_SIGSEGV);
    ASSERT_GT(child.pid, 0);
    ReleaseChild(child);
    EXPECT_EQ(DfxTestWaitProcessExitTimeout(child.pid, WAIT_TIMEOUT_MS, true),
              DFX_TEST_PROCESS_ABNORMAL_EXIT);
}
