/*
* Copyright (c) 2026 Huawei Device Co., Ltd.
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
#include "time_task.h"

#include <algorithm>
#include <atomic>
#include <cerrno>
#include <cinttypes>
#include <sys/timerfd.h>

#include "dfx_define.h"
#include "dfx_log.h"

namespace OHOS {
namespace HiviewDFX {

namespace {
constexpr const char *const TIMER_TASK = "TIME_TASK";

constexpr uint8_t TIMESTAMP_BITS = 60;
constexpr uint8_t SEQUENCE_START_BIT = TIMESTAMP_BITS;
constexpr uint64_t MAX_DELAY_TIME = 7 * 24 * 60 * 60 * US_PER_S;

/**
 * @brief Combined uint64_t value with dual-field encoding
 * @details Bit allocation for the 64-bit unsigned integer:
 *          - Bits 60-63 (4 high-order bits): Sequence number (range: 0~15, for batch/instance identification)
 *          - Bits 0-59 (60 low-order bits): microSecond-level timestamp (unsigned 60-bit value)
 *          - Timestamp range: 0 to ~36500 years (max value: 2^60 - 1 us ≈ 1.15×10^18 us = 36534 years)
 * @note To parse:
 *       - Sequence number = (value >> 60) & 0x0F;
 *       - Timestamp (us) = value & ((1ULL << 60) - 1);
 */
inline uint64_t CalculateTaskId(uint64_t createTime)
{
    static std::atomic<uint8_t> taskSequence{0};
    return (static_cast<uint64_t>(taskSequence.fetch_add(1)) << SEQUENCE_START_BIT) | createTime;
}
}

uint64_t PeriodicTask::Execute()
{
    return task_ ? task_() : 0;
}

uint64_t DelayTask::Execute()
{
    if (task_) {
        task_();
    }
    return 0;
}

TimerTaskQueue& TimerTaskQueue::GetInstance()
{
    static thread_local TimerTaskQueue queue;
    return queue;
}

uint64_t TimerTaskQueue::AddTask(std::unique_ptr<TimerTask> task, uint64_t delayTime)
{
    if (!task || delayTime > MAX_DELAY_TIME) {
        return 0;
    }
    uint64_t currentTime = GetMicroSecondsSinceBoot();
    uint64_t executeTime = currentTime + delayTime;
    auto insertPos = std::find_if(tasks_.begin(), tasks_.end(),
        [&](const TimerQueueTask& existingTask) {
            return existingTask.executeTime > executeTime;
        });
    bool isBegin = (insertPos == tasks_.begin());
    auto taskId = CalculateTaskId(currentTime);
    tasks_.insert(insertPos, TimerQueueTask{taskId, executeTime, std::move(task)});
    if (isBegin) {
        if (executor_ == nullptr && !InitExecutor()) {
            DFXLOGD("%{public}s :: add task failed, InitExecutor failed", TIMER_TASK);
            tasks_.pop_front();
            return 0;
        }
        executor_->SetNextDelayTime(delayTime == 0 ? 1 : delayTime);
    }
    DFXLOGD("%{public}s :: add task success, taskId %{public}" PRIu64 ", delay %{public}" PRIu64,
        TIMER_TASK, taskId, delayTime);
    return taskId;
}

bool TimerTaskQueue::RemoveTask(uint64_t taskId)
{
    auto it = std::find_if(tasks_.begin(), tasks_.end(),
        [&](const TimerQueueTask& item) {
            return item.taskId == taskId;
        });
    if (it == tasks_.end()) {
        DFXLOGD("%{public}s :: remove task %{public}" PRIu64 " not found", TIMER_TASK, taskId);
        return false;
    }
    bool isBegin = (it == tasks_.begin());
    tasks_.erase(it);
    DFXLOGD("%{public}s :: remove task %{public}" PRIu64 " success", TIMER_TASK, taskId);
    if (!isBegin || executor_ == nullptr) {
        return true;
    }
    executor_->SetNextDelayTime();
    return true;
}


TimerTaskQueue::~TimerTaskQueue()
{
    if (executor_ != nullptr) {
        EpollManager::GetInstance().RemoveListener(executor_->GetFd());
    }
}

bool TimerTaskQueue::InitExecutor()
{
    SmartFd timeFd{timerfd_create(CLOCK_MONOTONIC, 0)};
    if (!timeFd) {
        DFXLOGE("%{public}s :: failed to create time fd, errno: %{public}d", TIMER_TASK, errno);
        return false;
    }
    auto executor = std::unique_ptr<TaskExecutor>(new(std::nothrow) TaskExecutor(*this, std::move(timeFd)));
    if (executor == nullptr) {
        DFXLOGE("%{public}s :: failed to create TaskExecutor", TIMER_TASK);
        return false;
    }
    executor_ = executor.get();
    if (!EpollManager::GetInstance().AddListener(std::move(executor))) {
        DFXLOGE("%{public}s :: failed to add executor listener", TIMER_TASK);
        return false;
    }
    DFXLOGD("%{public}s :: InitExecutor success, fd %{public}d", TIMER_TASK, executor_->GetFd());
    return true;
}

void TimerTaskQueue::TaskExecutor::SetNextDelayTime() const
{
    if (taskQueue_.tasks_.empty()) {
        SetNextDelayTime(1);
        return;
    }
    auto currentTime = GetMicroSecondsSinceBoot();
    auto frontExecuteTime = taskQueue_.tasks_.front().executeTime;
    if (currentTime < frontExecuteTime) {
        auto delayTime = frontExecuteTime - currentTime;
        DFXLOGD("%{public}s :: SetNextDelayTime, next delay %{public}" PRIu64 "us", TIMER_TASK, delayTime);
        SetNextDelayTime(delayTime);
    } else {
        DFXLOGD("%{public}s :: SetNextDelayTime, front task expired, set 1us", TIMER_TASK);
        SetNextDelayTime(1);
    }
}

void TimerTaskQueue::TaskExecutor::SetNextDelayTime(uint64_t nextDelayTime) const
{
    struct itimerspec timeOption{};
    timeOption.it_value.tv_sec =
        static_cast<decltype(timeOption.it_value.tv_sec)>(nextDelayTime / US_PER_S);
    timeOption.it_value.tv_nsec =
        static_cast<decltype(timeOption.it_value.tv_nsec)>((nextDelayTime * NS_PER_US) % NS_PER_S);
    timeOption.it_interval.tv_sec = 1;
    if (timerfd_settime(GetFd(), 0, &timeOption, nullptr) == -1) {
        DFXLOGE("%{public}s :: failed to set delay time for fd, errno: %{public}d.", TIMER_TASK, errno);
    }
}

EventResult TimerTaskQueue::TaskExecutor::OnEventPoll()
{
    uint64_t exp = 0;
    auto ret = OHOS_TEMP_FAILURE_RETRY(read(GetFd(), &exp, sizeof(exp)));
    if (ret < 0 || static_cast<uint64_t>(ret) != sizeof(exp)) {
        DFXLOGE("%{public}s :: failed read time fd %{public}" PRId32, TIMER_TASK, GetFd());
        return EventResult::REMOVE;
    }
    while (!taskQueue_.tasks_.empty()) {
        auto currentTimeInMicroSecond = GetMicroSecondsSinceBoot();
        auto executeTime = taskQueue_.tasks_.front().executeTime;
        if (executeTime > currentTimeInMicroSecond) {
            DFXLOGD("%{public}s :: front task not due, next delay %{public}" PRIu64 "us, keep",
                TIMER_TASK, executeTime - currentTimeInMicroSecond);
            SetNextDelayTime(executeTime - currentTimeInMicroSecond);
            return EventResult::KEEP;
        }
        auto frontTaskId = taskQueue_.tasks_.front().taskId;
        DFXLOGD("%{public}s :: execute task %{public}" PRIu64, TIMER_TASK, frontTaskId);
        auto frontTask = std::move(taskQueue_.tasks_.front());
        taskQueue_.tasks_.pop_front();
        auto delayTime = frontTask.task->Execute();
        DFXLOGD("%{public}s :: task %{public}" PRIu64 " executed, next delay %{public}" PRIu64,
            TIMER_TASK, frontTaskId, delayTime);
        if (delayTime > 0) {
            frontTask.executeTime = currentTimeInMicroSecond + delayTime;
            auto insertPos = std::find_if(taskQueue_.tasks_.begin(), taskQueue_.tasks_.end(),
                [&frontTask](const TimerQueueTask& existingTask) {
                    return existingTask.executeTime > frontTask.executeTime;
                });
            taskQueue_.tasks_.insert(insertPos, std::move(frontTask));
        }
    }
    DFXLOGD("%{public}s :: all tasks done, remove executor", TIMER_TASK);
    return EventResult::REMOVE;
}

TimerTaskQueue::TaskExecutor::~TaskExecutor()
{
    taskQueue_.executor_ = nullptr;
}


uint64_t TaskQueueAdapter::AddDelayTask(std::function<void()> workFunc, uint32_t delayTimeInS)
{
    if (!workFunc) {
        return 0;
    }
    auto delayTimeInMicroSeconds = static_cast<uint64_t>(delayTimeInS) * MS_PER_S * US_PER_MS;
    auto task = std::unique_ptr<DelayTask>(new(std::nothrow) DelayTask(std::move(workFunc)));
    return TimerTaskQueue::GetInstance().AddTask(std::move(task), delayTimeInMicroSeconds);
}

uint64_t TaskQueueAdapter::AddPeriodicTask(std::function<PeriodicTaskResult()> workFunc, uint32_t delayTimeInS,
    uint32_t intervalTimeInS)
{
    if (intervalTimeInS == 0 || !workFunc) {
        return 0;
    }
    auto task = std::unique_ptr<PeriodicTask>(new(std::nothrow) PeriodicTask(
        [workFunc = std::move(workFunc), intervalTimeInS]() -> uint64_t {
            return workFunc() == PeriodicTaskResult::KEEP
                ? static_cast<uint64_t>(intervalTimeInS) * MS_PER_S * US_PER_MS : 0;
        }));
    return TimerTaskQueue::GetInstance().AddTask(std::move(task),
        static_cast<uint64_t>(delayTimeInS) * MS_PER_S * US_PER_MS);
}

bool TaskQueueAdapter::RemoveTask(uint64_t taskId)
{
    return TimerTaskQueue::GetInstance().RemoveTask(taskId);
}
}
}
