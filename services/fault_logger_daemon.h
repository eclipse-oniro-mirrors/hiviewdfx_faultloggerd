/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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
#ifndef FAULT_LOGGER_DAEMON_H_
#define FAULT_LOGGER_DAEMON_H_

#include <cstdint>
#include <memory>

#include "epoll_manager.h"
#include "temp_file_manager.h"
#include "fault_logger_server.h"

namespace OHOS {
namespace HiviewDFX {

enum class EpollManagerType {
    MAIN_SERVER,
    HELPER_SERVER,
};
class FaultLoggerDaemon {
public:
    FaultLoggerDaemon(const FaultLoggerDaemon&) = delete;
    FaultLoggerDaemon(FaultLoggerDaemon&&) = delete;

    FaultLoggerDaemon &operator=(const FaultLoggerDaemon&) = delete;
    FaultLoggerDaemon &operator=(FaultLoggerDaemon&&) = delete;

    static FaultLoggerDaemon& GetInstance();
    int32_t StartServer();
    EpollManager* GetEpollManager(EpollManagerType type);
private:
    FaultLoggerDaemon();
    ~FaultLoggerDaemon();
    EpollManager mainEpollManager_;
    EpollManager secondaryEpollManager_;
    SocketServer mainServer_;
    TempFileManager tempFileManager_;
};
} // namespace HiviewDFX
} // namespace OHOS
#endif // FAULT_LOGGER_DAEMON_H_
