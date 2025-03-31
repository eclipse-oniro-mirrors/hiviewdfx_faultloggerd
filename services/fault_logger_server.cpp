/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "fault_logger_server.h"

#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>

#include "dfx_define.h"
#include "dfx_log.h"
#include "faultloggerd_socket.h"

namespace OHOS {
namespace HiviewDFX {

namespace {
constexpr const char* const FAULTLOGGERD_SERVER_TAG = "FAULT_LOGGER_SERVER";
}

SocketServer::SocketServer(EpollManager& epollManager) : epollManager_(epollManager) {}

bool SocketServer::Init()
{
    std::unique_ptr<IFaultLoggerService> logFileDesService(new (std::nothrow) FileDesService());
    AddService(LOG_FILE_DES_CLIENT, std::move(logFileDesService));
#ifndef HISYSEVENT_DISABLE
    std::unique_ptr<IFaultLoggerService> reportExceptionService(new (std::nothrow) ExceptionReportService());
    AddService(REPORT_EXCEPTION_CLIENT, std::move(reportExceptionService));
    std::unique_ptr<IFaultLoggerService> statsClientService(new (std::nothrow) StatsService());
    AddService(DUMP_STATS_CLIENT, std::move(statsClientService));
#endif
    if (!AddServerListener(SERVER_SOCKET_NAME) || !AddServerListener(SERVER_CRASH_SOCKET_NAME)) {
        return false;
    }
#ifndef is_ohos_lite
    AddService(PIPE_FD_CLIENT, std::make_unique<PipeService>());
    AddService(SDK_DUMP_CLIENT, std::make_unique<SdkDumpService>());
    if (!AddServerListener(SERVER_SDKDUMP_SOCKET_NAME)) {
        return false;
    }
#endif
    return true;
}

void SocketServer::AddService(int32_t clientType, std::unique_ptr<IFaultLoggerService> service)
{
    if (service) {
        faultLoggerServices_.emplace_back(clientType, std::move(service));
    }
}

bool SocketServer::AddServerListener(const char* socketName)
{
    int32_t fd;
    constexpr int32_t maxConnection = 30;
    if (!StartListen(fd, socketName, maxConnection)) {
        return false;
    }
    std::unique_ptr<EpollListener> serverListener(new (std::nothrow)SocketServerListener(*this, fd, socketName));
    return epollManager_.AddListener(std::move(serverListener));
}

SocketServer::SocketServerListener::SocketServerListener(SocketServer& socketServer, int32_t fd, std::string socketName)
    : EpollListener(fd), socketServer_(socketServer), socketName_(std::move(socketName)) {}

SocketServer::ClientRequestListener::ClientRequestListener(SocketServerListener& socketServerListener, int32_t fd)
    : EpollListener(fd), socketServerListener_(socketServerListener) {}

IFaultLoggerService* SocketServer::ClientRequestListener::GetTargetService(int32_t faultLoggerClientType) const
{
    for (const auto& faultLoggerServicePair : socketServerListener_.socketServer_.faultLoggerServices_) {
        if (faultLoggerServicePair.first == faultLoggerClientType) {
            return faultLoggerServicePair.second.get();
        }
    }
    return nullptr;
}

void SocketServer::ClientRequestListener::OnEventPoll()
{
    constexpr int32_t maxBuffSize = 2048;
    std::vector<uint8_t> buf(maxBuffSize, 0);
    ssize_t nread = OHOS_TEMP_FAILURE_RETRY(read(GetFd(), buf.data(), maxBuffSize));
    if (nread >= sizeof(RequestDataHead)) {
        auto dataHead = reinterpret_cast<RequestDataHead*>(buf.data());
        DFXLOGI("%{public}s :: %{public}s receive request from pid: %{public}d, clientType: %{public}d",
                FAULTLOGGERD_SERVER_TAG, socketServerListener_.socketName_.c_str(),
                dataHead->clientPid, dataHead->clientType);
        IFaultLoggerService* service = GetTargetService(dataHead->clientType);
        int32_t retCode = service ? service->OnReceiveMsg(socketServerListener_.socketName_, GetFd(), nread, buf)
            : ResponseCode::UNKNOWN_CLIENT_TYPE;
        if (retCode != ResponseCode::REQUEST_SUCCESS) {
            SendMsgToSocket(GetFd(), &retCode, sizeof(retCode));
        }
        DFXLOGI("%{public}s :: %{public}s has processed request for pid: %{public}d, clientType: %{public}d, "
            "and retCode %{public}d", FAULTLOGGERD_SERVER_TAG, socketServerListener_.socketName_.c_str(),
            dataHead->clientPid, dataHead->clientType, retCode);
    }
    socketServerListener_.socketServer_.epollManager_.RemoveListener(GetFd());
}

void SocketServer::SocketServerListener::OnEventPoll()
{
    struct sockaddr_un clientAddr;
    socklen_t clientAddrSize = static_cast<socklen_t>(sizeof(clientAddr));
    int connectionFd =
        OHOS_TEMP_FAILURE_RETRY(accept(GetFd(), reinterpret_cast<struct sockaddr*>(&clientAddr), &clientAddrSize));
    if (connectionFd < 0) {
        DFXLOGW("%{public}s :: Failed to accept connection from %{public}s",
            FAULTLOGGERD_SERVER_TAG, socketName_.c_str());
        return;
    }
    std::unique_ptr<EpollListener> clientRequestListener(new (std::nothrow) ClientRequestListener(*this, connectionFd));
    socketServer_.epollManager_.AddListener(std::move(clientRequestListener));
}
}
}