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

#ifndef TIME_TASK_H_
#define TIME_TASK_H_

#include <functional>
#include <list>
#include <memory>

#include "epoll_manager.h"
namespace OHOS {
namespace HiviewDFX {

enum class PeriodicTaskResult {
    KEEP,   // Keep the periodic task for next execution
    REMOVE  // Remove the periodic task after current execution
};

class TimerTask {
public:
    virtual ~TimerTask() = default;

    /**
     * Execute the task and return the delay time (in microseconds) until the next execution.
     * - Return > 0: The task will be re-scheduled with the returned delay.
     * - Return 0: The task is completed and will not be re-scheduled.
     */
    virtual uint64_t Execute() = 0;
};

class PeriodicTask : public TimerTask {
public:
    explicit PeriodicTask(std::function<uint64_t()> task) : TimerTask(), task_(std::move(task)) {};
    uint64_t Execute() override;
private:
    std::function<uint64_t()> task_;
};

class DelayTask : public TimerTask {
public:
    explicit DelayTask(std::function<void()> task) : TimerTask(), task_(std::move(task)){};
    uint64_t Execute() override;
private:
    std::function<void()> task_;
};

struct TimerQueueTask {
    uint64_t taskId;
    uint64_t executeTime;
    std::unique_ptr<TimerTask> task;
};

class TimerTaskQueue {
public:
    static TimerTaskQueue& GetInstance();
    TimerTaskQueue& operator=(const TimerTaskQueue&) = delete;
    TimerTaskQueue(const TimerTaskQueue&) = delete;
    TimerTaskQueue(TimerTaskQueue&&) = delete;
    TimerTaskQueue& operator=(TimerTaskQueue&&) = delete;
    uint64_t AddTask(std::unique_ptr<TimerTask> task, uint64_t delayTime);
    bool RemoveTask(uint64_t taskId);
private:
    class TaskExecutor final : public EpollListener {
    public:
        explicit TaskExecutor(TimerTaskQueue& queue, SmartFd timeFd)
            : EpollListener(std::move(timeFd)), taskQueue_(queue) {}
        void SetNextDelayTime(uint64_t nextDelayTime) const;
        void SetNextDelayTime() const;
        ~TaskExecutor() override;
    protected:
        EventResult OnEventPoll() final;
        TimerTaskQueue& taskQueue_;
    };
    TimerTaskQueue() = default;
    ~TimerTaskQueue();
    bool InitExecutor();
    /**
     * Used to check if there is already an executor and retrieve the fd bound to this executor.
     */
    const TaskExecutor* executor_{};
    std::list<TimerQueueTask> tasks_;
};

class TaskQueueAdapter final {
public:
    static uint64_t AddDelayTask(std::function<void()> workFunc, uint32_t delayTimeInS);
    static uint64_t AddPeriodicTask(std::function<PeriodicTaskResult()> workFunc, uint32_t delayTimeInS,
        uint32_t intervalTimeInS);
    static bool RemoveTask(uint64_t taskId);
};
}
}

#endif // TIME_TASK_H_
