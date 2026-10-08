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

#include "epoll_manager.h"

#include <algorithm>
#include <limits>
#include <vector>

#include <unistd.h>

#include <sys/epoll.h>

#include "dfx_define.h"
#include "dfx_log.h"

#ifdef LOG_DOMAIN
#undef LOG_DOMAIN
#define LOG_DOMAIN 0xD002D11
#endif

namespace OHOS {
namespace HiviewDFX {

namespace {
constexpr const char *const EPOLL_MANAGER = "EPOLL_MANAGER";
}

uint64_t GetMicroSecondsSinceBoot()
{
    struct timespec times{};
    if (clock_gettime(CLOCK_BOOTTIME, &times) == -1) {
        DFXLOGE("%{public}s :: failed get time for %{public}d", EPOLL_MANAGER, errno);
        return 0;
    }
    return static_cast<uint64_t>(times.tv_sec * US_PER_S + times.tv_nsec / NS_PER_US);
}

EpollListener::EpollListener(SmartFd fd, int64_t timeoutInMs) : fd_(std::move(fd))
{
    if (timeoutInMs >= 0) {
        timeoutTime_ = static_cast<int64_t>(GetMicroSecondsSinceBoot()) + timeoutInMs * static_cast<int64_t>(US_PER_MS);
    } else {
        timeoutTime_ = std::numeric_limits<int64_t>::max();
    }
}

int64_t EpollListener::GetTimeOutTime() const
{
    return timeoutTime_;
}

int32_t EpollListener::GetFd() const
{
    return fd_.GetFd();
}

EpollManager &EpollManager::GetInstance()
{
    static thread_local EpollManager mainEpollManager;
    return mainEpollManager;
}

EpollManager::~EpollManager()
{
    StopEpoll();
}

bool EpollManager::AddEpollEvent(EpollListener& epollListener) const
{
    if (!eventFd_) {
        return false;
    }
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = epollListener.GetFd();
    if (epoll_ctl(eventFd_.GetFd(), EPOLL_CTL_ADD, ev.data.fd, &ev) < 0) {
        DFXLOGE("%s :: Failed to epoll ctl add fd %{public}d, errno %{public}d",
            EPOLL_MANAGER, epollListener.GetFd(), errno);
        return false;
    }
    return true;
}

bool EpollManager::DelEpollEvent(int32_t fd) const
{
    if (!eventFd_) {
        return false;
    }
    epoll_event ev{};
    ev.events = EPOLLIN;
    ev.data.fd = fd;
    if (epoll_ctl(eventFd_.GetFd(), EPOLL_CTL_DEL, fd, &ev) < 0) {
        DFXLOGW("%s :: Failed to epoll ctl delete Fd %{public}d, errno %{public}d", EPOLL_MANAGER, fd, errno);
        return false;
    }
    return true;
}

bool EpollManager::AddListener(std::unique_ptr<EpollListener> epollListener)
{
    if (!epollListener || epollListener->GetFd() < 0 || !AddEpollEvent(*epollListener)) {
        return false;
    }
    auto timeoutTime = epollListener->GetTimeOutTime();
    auto iter = std::find_if(listeners_.begin(), listeners_.end(),
        [timeoutTime](const std::unique_ptr<EpollListener>& listener) {
            return listener->GetTimeOutTime() > timeoutTime;
        });
    listeners_.insert(iter, std::move(epollListener));
    return true;
}

bool EpollManager::RemoveListener(int32_t fd)
{
    if (fd < 0 || !DelEpollEvent(fd)) {
        return false;
    }
    listeners_.remove_if([fd](const std::unique_ptr<EpollListener>& epollLister) {
        return epollLister->GetFd() == fd;
    });
    return true;
}

EpollListener* EpollManager::GetTargetListener(int32_t fd) const
{
    auto iter = std::find_if(listeners_.begin(), listeners_.end(),
        [fd](const std::unique_ptr<EpollListener>& listener) {
            return listener->GetFd() == fd;
        });
    return iter == listeners_.end() ? nullptr : iter->get();
}

int32_t EpollManager::GetNextWaitTime() const
{
    if (listeners_.empty() || listeners_.front()->GetTimeOutTime() == std::numeric_limits<int64_t>::max()) {
        return -1;
    }
    auto nextWaitTime = listeners_.front()->GetTimeOutTime() - static_cast<int64_t>(GetMicroSecondsSinceBoot());
    if (nextWaitTime < 0) {
        return 0;
    }
    constexpr auto minCheckTime = 30 * 1000;
    return std::min(static_cast<int32_t>(nextWaitTime / US_PER_MS), minCheckTime);
}

void EpollManager::HandleTimeOut()
{
    if (listeners_.empty()) {
        return;
    }
    auto listener = listeners_.front().get();
    if (static_cast<uint64_t>(listener->GetTimeOutTime()) <= GetMicroSecondsSinceBoot()) {
        listener->OnTimeOut();
        RemoveListener(listener->GetFd());
    }
}

bool EpollManager::Init(int maxPollEvent)
{
    eventFd_ = SmartFd{epoll_create(maxPollEvent)};
    if (!eventFd_) {
        DFXLOGE("%s :: Failed to create eventFd.", EPOLL_MANAGER);
        return false;
    }
    return true;
}

void EpollManager::StartEpoll(int maxConnection)
{
    std::vector<epoll_event> events(maxConnection);
    while (eventFd_) {
        int32_t timeOut = GetNextWaitTime();
        int epollNum = OHOS_TEMP_FAILURE_RETRY(epoll_wait(eventFd_.GetFd(), events.data(), maxConnection, timeOut));
        if (epollNum < 0 || !eventFd_) {
            continue;
        }
        if (epollNum == 0) {
            HandleTimeOut();
            continue;
        }
        for (int i = 0; i < epollNum; i++) {
            if (!(events[i].events & EPOLLIN)) {
                DFXLOGE("%{public}s :: client fd %{public}d disconnected", EPOLL_MANAGER, events[i].data.fd);
                RemoveListener(events[i].data.fd);
                continue;
            }
            const auto listener = GetTargetListener(events[i].data.fd);
            if (listener == nullptr) {
                DelEpollEvent(events[i].data.fd);
                continue;
            }
            EventResult result = listener->OnEventPoll();
            if (result == EventResult::REMOVE) {
                RemoveListener(events[i].data.fd);
            }
        }
    }
}

void EpollManager::StopEpoll()
{
    if (eventFd_) {
        for (const auto& listener : listeners_) {
            (void)DelEpollEvent(listener->GetFd());
        }
        eventFd_.Reset();
    }
}
}
}
