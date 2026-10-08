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

#include "time_task.h"

#include <atomic>
#include <chrono>
#include <functional>
#include <future>
#include <gtest/gtest.h>
#include <thread>
#include <vector>

#include "faultloggerd_test_server.h"

using namespace OHOS::HiviewDFX;
using namespace testing::ext;
using namespace std;

static constexpr uint64_t MAX_DELAY_TIME = 7ULL * 24 * 60 * 60 * 1000 * 1000;

class TimeTaskTest : public testing::Test {
public:
    static void SetUpTestCase() { FaultLoggerdTestServer::GetInstance(); }
};

#define RUN_ON_HELPER(testBody) \
    do { \
        std::promise<bool> helperDone_; \
        ASSERT_TRUE(FaultLoggerdTestServer::AddTask(ExecutorThreadType::HELPER, [&]() { \
            testBody; \
            helperDone_.set_value(true); \
        })); \
        ASSERT_TRUE(helperDone_.get_future().get()); \
    } while (0)

/**
 * @tc.name: PeriodicTaskExecuteNullAndValid
 * @tc.desc: Execute returns 0 for a null callback and returns the callback result for a valid callback.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, PeriodicTaskExecuteNullAndValid, TestSize.Level2)
{
    PeriodicTask taskNull(nullptr);
    ASSERT_EQ(taskNull.Execute(), 0u);
    PeriodicTask taskValid([]() -> uint64_t { return 42; });
    ASSERT_EQ(taskValid.Execute(), 42u);
}

/**
 * @tc.name: DelayTaskExecuteNull
 * @tc.desc: Execute returns 0 when the DelayTask callback is null.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, DelayTaskExecuteNull, TestSize.Level2)
{
    DelayTask taskNull(nullptr);
    ASSERT_EQ(taskNull.Execute(), 0u);
}

/**
 * @tc.name: DelayTaskExecuteNullAndValid
 * @tc.desc: Execute returns 0 for a null callback and invokes the callback for a valid DelayTask.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, DelayTaskExecuteNullAndValid, TestSize.Level2)
{
    DelayTask taskNull(nullptr);
    ASSERT_EQ(taskNull.Execute(), 0u);
    atomic<bool> called{false};
    atomic<uint64_t> ret{1};
    RUN_ON_HELPER({
        DelayTask task([&called] { called = true; });
        ret = task.Execute();
    });
    ASSERT_EQ(ret, 0u);
    ASSERT_TRUE(called);
}

/**
 * @tc.name: AddTaskNullTask
 * @tc.desc: AddTask returns 0 when the task pointer is null.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, AddTaskNullTask, TestSize.Level2)
{
    atomic<uint64_t> ret{1};
    RUN_ON_HELPER({
        ret = TimerTaskQueue::GetInstance().AddTask(nullptr, 1000);
    });
    ASSERT_EQ(ret, 0u);
}

/**
 * @tc.name: AddTaskExceedMaxDelay
 * @tc.desc: AddTask returns 0 when the delay exceeds MAX_DELAY_TIME.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, AddTaskExceedMaxDelay, TestSize.Level2)
{
    atomic<uint64_t> ret{1};
    RUN_ON_HELPER({
        auto task = std::make_unique<DelayTask>([] {});
        ret = TimerTaskQueue::GetInstance().AddTask(std::move(task), MAX_DELAY_TIME + 1);
    });
    ASSERT_EQ(ret, 0u);
}

/**
 * @tc.name: AddTaskInitExecutorFails
 * @tc.desc: AddTask returns 0 and leaves no executor when InitExecutor fails on the main thread.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, AddTaskInitExecutorFails, TestSize.Level2)
{
    auto& queue = TimerTaskQueue::GetInstance();
    auto task = std::make_unique<DelayTask>([] {});
    ASSERT_EQ(queue.AddTask(std::move(task), 1000000), 0u);
    ASSERT_TRUE(queue.tasks_.empty());
    ASSERT_EQ(queue.executor_, nullptr);
}

/**
 * @tc.name: AdapterAddDelayTaskNullFunc
 * @tc.desc: TaskQueueAdapter::AddDelayTask returns 0 when the delay task function is null.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, AdapterAddDelayTaskNullFunc, TestSize.Level2)
{
    atomic<uint64_t> ret{1};
    RUN_ON_HELPER({
        ret = TaskQueueAdapter::AddDelayTask(std::function<void()>(), 1);
    });
    ASSERT_EQ(ret, 0u);
}

/**
 * @tc.name: AdapterAddPeriodicTaskZeroInterval
 * @tc.desc: TaskQueueAdapter::AddPeriodicTask returns 0 when the periodic task interval is zero.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, AdapterAddPeriodicTaskZeroInterval, TestSize.Level2)
{
    atomic<uint64_t> ret{1};
    RUN_ON_HELPER({
        ret = TaskQueueAdapter::AddPeriodicTask([] { return PeriodicTaskResult::KEEP; }, 1, 0);
    });
    ASSERT_EQ(ret, 0u);
}

/**
 * @tc.name: AdapterAddPeriodicTaskNullFunc
 * @tc.desc: TaskQueueAdapter::AddPeriodicTask returns 0 when the periodic task function is null.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, AdapterAddPeriodicTaskNullFunc, TestSize.Level2)
{
    atomic<uint64_t> ret{1};
    RUN_ON_HELPER({
        ret = TaskQueueAdapter::AddPeriodicTask(nullptr, 1, 1);
    });
    ASSERT_EQ(ret, 0u);
}

/**
 * @tc.name: AddTaskFirstTaskSucceeds
 * @tc.desc: AddTask returns a valid task id and executes the first task when InitExecutor succeeds on
 * the helper thread.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, AddTaskFirstTaskSucceeds, TestSize.Level2)
{
    atomic<uint64_t> taskId{0};
    std::promise<bool> done;
    RUN_ON_HELPER({
        auto& queue = TimerTaskQueue::GetInstance();
        auto t = std::make_unique<DelayTask>([&] {
            done.set_value(true);
        });
        taskId = queue.AddTask(std::move(t), 0);
    });
    ASSERT_TRUE(done.get_future().get());
    ASSERT_GT(taskId, 0u);
}

/**
 * @tc.name: AddTaskSecondNotAtBegin
 * @tc.desc: The second task with a larger delay executes after the first task.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, AddTaskSecondNotAtBegin, TestSize.Level2)
{
    std::promise<uint64_t> executeTime1;
    std::promise<uint64_t> executeTime2;
    RUN_ON_HELPER({
        auto& queue = TimerTaskQueue::GetInstance();
        auto t1 = std::make_unique<DelayTask>([&] {
            GTEST_LOG_(INFO) << "Execute taask1: end.";
            executeTime1.set_value(GetMicroSecondsSinceBoot());
        });
        auto t2 = std::make_unique<DelayTask>([&] {
            GTEST_LOG_(INFO) << "Execute taask2: end.";
            executeTime2.set_value(GetMicroSecondsSinceBoot());
        });
        uint64_t delay = 1 * 1000 * 1000;
        queue.AddTask(std::move(t1), delay);
        queue.AddTask(std::move(t2), delay + 1000);
    });
    ASSERT_LT(executeTime1.get_future().get(), executeTime2.get_future().get());
}

/**
 * @tc.name: AddTaskSecondAtBegin
 * @tc.desc: The second task with a smaller delay executes before the first task.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, AddTaskSecondAtBegin, TestSize.Level2)
{
    std::promise<uint64_t> executeTime1;
    std::promise<uint64_t> executeTime2;
    RUN_ON_HELPER({
        auto& queue = TimerTaskQueue::GetInstance();
        auto t1 = std::make_unique<DelayTask>([&] {
            executeTime1.set_value(GetMicroSecondsSinceBoot());
        });
        auto t2 = std::make_unique<DelayTask>([&] {
            executeTime2.set_value(GetMicroSecondsSinceBoot());
        });
        uint64_t delay = 1 * 1000 * 1000;
        queue.AddTask(std::move(t1), delay);
        queue.AddTask(std::move(t2), delay / 2);
    });
    ASSERT_GT(executeTime1.get_future().get(), executeTime2.get_future().get());
}

/**
 * @tc.name: RemoveTaskNotAtBegin
 * @tc.desc: RemoveTask removes a queued non-front task before it executes.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, RemoveTaskNotAtBegin, TestSize.Level2)
{
    atomic<int> taskExecuteCount;
    std::promise<bool> done;
    RUN_ON_HELPER({
        auto& queue = TimerTaskQueue::GetInstance();
        auto t1 = std::make_unique<DelayTask>([&] {
            taskExecuteCount += 1;
        });
        uint64_t delay = 1 * 1000 * 1000;
        auto taskId = queue.AddTask(std::move(t1), delay);
        auto t2 = std::make_unique<DelayTask>([&, taskId = taskId] {
            taskExecuteCount += 2;
            queue.RemoveTask(taskId);
        });
        queue.AddTask(std::move(t2), delay / 2);
        auto t3 = std::make_unique<DelayTask>([&] {
            done.set_value(true);
        });
        queue.AddTask(std::move(t3), delay + 1000);
    });
    ASSERT_TRUE(done.get_future().get());
    ASSERT_EQ(taskExecuteCount, 2);
}

/**
 * @tc.name: RemoveTaskNotFound
 * @tc.desc: RemoveTask returns false when the task id does not exist.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, RemoveTaskNotFound, TestSize.Level2)
{
    ASSERT_FALSE(TimerTaskQueue::GetInstance().RemoveTask(0));
}

/**
 * @tc.name: RemoveTaskAtBeginWithExecutor
 * @tc.desc: RemoveTask removes the front task when the executor exists, preventing its execution.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, RemoveTaskAtBeginWithExecutor, TestSize.Level2)
{
    atomic<int> taskExecuteCount;
    std::promise<bool> done;
    RUN_ON_HELPER({
        auto& queue = TimerTaskQueue::GetInstance();
        auto t1 = std::make_unique<DelayTask>([&] {
            taskExecuteCount += 1;
        });
        auto taskId = queue.AddTask(std::move(t1), 0);
        queue.RemoveTask(taskId);
        auto t2 = std::make_unique<DelayTask>([&] {
            done.set_value(true);
        });
        queue.AddTask(std::move(t2), 1000);
    });
    ASSERT_TRUE(done.get_future().get());
    ASSERT_EQ(taskExecuteCount, 0);
}

/**
 * @tc.name: PeriodicTaskStopsOnFalse
 * @tc.desc: A periodic task stops executing after its callback returns REMOVE.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, PeriodicTaskStopsOnFalse, TestSize.Level2)
{
    atomic<int> count;
    RUN_ON_HELPER({
        TaskQueueAdapter::AddPeriodicTask([&]() -> PeriodicTaskResult {
            return ++count < 2 ? PeriodicTaskResult::KEEP : PeriodicTaskResult::REMOVE;
        }, 0, 1);
    });
    std::this_thread::sleep_for(std::chrono::seconds(3));
    ASSERT_EQ(count, 2);
}

/**
 * @tc.name: DelayTaskOrdering
 * @tc.desc: Delay tasks execute in ascending order of their delay values.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, DelayTaskOrdering, TestSize.Level2)
{
    vector<uint32_t> record;
    RUN_ON_HELPER({
        TaskQueueAdapter::AddDelayTask([&record] { record.push_back(3); }, 3);
        TaskQueueAdapter::AddDelayTask([&record] { record.push_back(1); }, 1);
        TaskQueueAdapter::AddDelayTask([&record] { record.push_back(2); }, 2);
    });
    this_thread::sleep_for(chrono::seconds(4));
    ASSERT_EQ(record.size(), 3u);
    if (record.size() == 3) {
        ASSERT_EQ(record[0], 1u);
        ASSERT_EQ(record[1], 2u);
        ASSERT_EQ(record[2], 3u);
    }
}

/**
 * @tc.name: TaskIdUniqueness
 * @tc.desc: AddTask returns unique task ids for different tasks.
 * @tc.type: FUNC
 */
HWTEST_F(TimeTaskTest, TaskIdUniqueness, TestSize.Level2)
{
    atomic<uint64_t> id1{0};
    atomic<uint64_t> id2{0};
    RUN_ON_HELPER({
        auto& queue = TimerTaskQueue::GetInstance();
        auto t1 = std::make_unique<DelayTask>([] {});
        auto t2 = std::make_unique<DelayTask>([] {});
        uint64_t delay = 10 * 1000 * 1000;
        id1 = queue.AddTask(std::move(t1), delay);
        id2 = queue.AddTask(std::move(t2), delay);
        queue.RemoveTask(id1);
        queue.RemoveTask(id2);
    });
    ASSERT_NE(id1, id2);
}
