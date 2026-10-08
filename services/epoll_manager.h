/*
 * Copyright (c) 2024-2025 Huawei Device Co., Ltd.
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

#ifndef EPOLL_MANAGER_H_
#define EPOLL_MANAGER_H_

#include <list>
#include <memory>

#include "smart_fd.h"

namespace OHOS {
namespace HiviewDFX {

constexpr uint64_t MS_PER_S = 1000;
constexpr uint64_t US_PER_MS = 1000;
constexpr uint64_t NS_PER_US = 1000;
constexpr uint64_t US_PER_S = MS_PER_S * US_PER_MS;
constexpr uint64_t NS_PER_S = NS_PER_US * US_PER_S;

enum class EventResult {
    KEEP,    // Keep the listener after event handling
    REMOVE   // Remove the listener after event handling
};

class EpollListener {
public:
    /**
     * Construct an EpollListener with timeout.
     *
     * @param fd The file descriptor to monitor.
     * @param timeoutInMs Timeout in milliseconds. Special values:
     *        -1: No timeout (permanent listener)
     *         0: Reserved (not recommended)
     *        >0: Timeout in milliseconds
     *
     * @note Kernel limitation: Although epoll_wait API accepts up to INT_MAX ms (~24 days),
     *       the kernel's schedule_timeout() implementation has practical limits:
     *       - 32-bit systems: jiffies overflow risk after ~49.7 days
     *       - Timer precision: Depends on CONFIG_HZ (typically 1-10ms granularity)
     *       - System suspend: May interfere with long timeouts
     *
     * @warning RECOMMENDATION: Do NOT exceed 600000ms (10 min) to ensure:
     *          - Reliable timeout handling across kernel versions
     *          - Better maintainability and debugging
     *          - Avoid potential jiffies overflow issues
     *          - For longer delays, use timerfd instead
     */
    explicit EpollListener(SmartFd fd, int64_t timeoutInMs = -1);
    virtual ~EpollListener() = default;
    virtual EventResult OnEventPoll() = 0;
    virtual void OnTimeOut() {}
    int64_t GetTimeOutTime() const;
    int32_t GetFd() const;
private:
    const SmartFd fd_;
    int64_t timeoutTime_{0};
};

class EpollManager {
public:
    static EpollManager& GetInstance();
    EpollManager(const EpollManager&) = delete;
    EpollManager& operator=(const EpollManager&) = delete;
    EpollManager(EpollManager&&) noexcept = delete;
    EpollManager& operator=(EpollManager&&) noexcept = delete;
    bool Init(int maxPollEvent);
    void StartEpoll(int maxConnection);
    void StopEpoll();
    bool AddListener(std::unique_ptr<EpollListener> epollListener);
    bool RemoveListener(int32_t fd);
private:
    EpollManager() = default;
    ~EpollManager();
    bool AddEpollEvent(EpollListener& epollListener) const;
    bool DelEpollEvent(int32_t fd) const;
    EpollListener* GetTargetListener(int32_t fd) const;
    int32_t GetNextWaitTime() const;
    void HandleTimeOut();
    std::list<std::unique_ptr<EpollListener>> listeners_;
    SmartFd eventFd_;
};
uint64_t GetMicroSecondsSinceBoot();
}
}

#endif // EPOLL_MANAGER_H_
