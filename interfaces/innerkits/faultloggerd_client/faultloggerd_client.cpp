/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#include "faultloggerd_client.h"

#include <cstdint>

#include <securec.h>
#include <sys/un.h>

#include "dfx_cutil.h"
#include "dfx_define.h"
#include "dfx_log.h"
#include "dfx_socket_request.h"
#include "dfx_util.h"
#include "faultloggerd_socket.h"

namespace {
constexpr const char* const FAULTLOGGERD_CLIENT_TAG = "FAULT_LOGGERD_CLIENT";
constexpr int32_t SDKDUMP_SOCKET_TIMEOUT = 1;
constexpr int32_t CRASHDUMP_SOCKET_TIMEOUT = 3;
std::string GetSocketName()
{
    char content[NAME_BUF_LEN];
    GetProcessName(content, sizeof(content));
    return strcmp(content, "processdump") == 0 ? SERVER_CRASH_SOCKET_NAME : SERVER_SOCKET_NAME;
}

void FillRequestHeadData(RequestDataHead& head, FaultLoggerClientType clientType)
{
    head.clientType = clientType;
    head.clientPid = getpid();
}

int32_t SendRequestToServer(const char* socketName, const SocketRequestData& socketRequestData, int32_t timeout,
    SocketFdData* socketFdData = nullptr, bool signalSafely = false)
{
    FaultLoggerdSocket faultLoggerdSocket(signalSafely);
    int32_t retCode{ResponseCode::DEFAULT_ERROR_CODE};
    if (!faultLoggerdSocket.CreateSocketFileDescriptor(timeout)) {
        return ResponseCode::CONNECT_FAILED;
    }
    if (!faultLoggerdSocket.StartConnect(socketName)) {
        retCode = ResponseCode::CONNECT_FAILED;
    } else {
        retCode = socketFdData ? faultLoggerdSocket.RequestFdsFromServer(socketRequestData, *socketFdData) :
            faultLoggerdSocket.RequestServer(socketRequestData);
    }
    faultLoggerdSocket.CloseSocketFileDescriptor();
    return retCode;
}

int32_t RequestFileDescriptor(const struct FaultLoggerdRequest &request)
{
    int32_t fd{-1};
    SocketRequestData socketRequestData = {&request, sizeof(request)};
    SocketFdData socketFdData = {&fd, 1};
    switch (request.type) {
        case FFRT_CRASH_LOG:
            SendRequestToServer(SERVER_CRASH_SOCKET_NAME, socketRequestData, CRASHDUMP_SOCKET_TIMEOUT,
                &socketFdData, true);
            return fd;
        case CPP_CRASH:
        case CPP_STACKTRACE:
        case LEAK_STACKTRACE:
        case JIT_CODE_LOG:
            SendRequestToServer(SERVER_CRASH_SOCKET_NAME, socketRequestData, CRASHDUMP_SOCKET_TIMEOUT, &socketFdData);
            return fd;
        default:
            SendRequestToServer(SERVER_SOCKET_NAME, socketRequestData, CRASHDUMP_SOCKET_TIMEOUT, &socketFdData);
            return fd;
    }
}
}

int32_t RequestFileDescriptor(int32_t type)
{
    struct FaultLoggerdRequest request{};
    FillRequestHeadData(request.head, FaultLoggerClientType::LOG_FILE_DES_CLIENT);
    request.type = type;
    request.pid = request.head.clientPid;
    request.tid = gettid();
    request.time = OHOS::HiviewDFX::GetTimeMilliSeconds();
    return RequestFileDescriptor(request);
}

int32_t RequestFileDescriptorEx(struct FaultLoggerdRequest* request)
{
    if (request == nullptr) {
        DFXLOGE("%{public}s.%{public}s :: RequestFileDescriptorEx nullptr.", FAULTLOGGERD_CLIENT_TAG, __func__);
        return -1;
    }
    FillRequestHeadData(request->head, FaultLoggerClientType::LOG_FILE_DES_CLIENT);
    return RequestFileDescriptor(*request);
}

int32_t RequestSdkDump(int32_t pid, int32_t tid, int (&pipeReadFd)[2], bool isJson, int timeout)
{
#ifndef is_ohos_lite
    DFXLOGI("%{public}s.%{public}s :: pid: %{public}d, tid: %{public}d, isJson: %{public}d.",
        FAULTLOGGERD_CLIENT_TAG, __func__, pid, tid, isJson);
    if (pid <= 0 || tid < 0) {
        return ResponseCode::DEFAULT_ERROR_CODE;
    }
    struct SdkDumpRequestData request{};
    FillRequestHeadData(request.head, FaultLoggerClientType::SDK_DUMP_CLIENT);
    request.sigCode = isJson ? DUMP_TYPE_REMOTE_JSON : DUMP_TYPE_REMOTE;
    request.pid = pid;
    request.tid = tid;
    request.callerTid = gettid();
    request.time = OHOS::HiviewDFX::GetTimeMilliSeconds();
    request.endTime = GetAbsTimeMilliSeconds() + static_cast<uint64_t>(timeout);
    SocketRequestData socketRequestData = {&request, sizeof(request)};
    SocketFdData socketFdData = {pipeReadFd, PIPE_NUM_SZ};
    return SendRequestToServer(SERVER_SDKDUMP_SOCKET_NAME, socketRequestData, SDKDUMP_SOCKET_TIMEOUT, &socketFdData);
#else
    return ResponseCode::DEFAULT_ERROR_CODE;
#endif
}

int32_t RequestPipeFd(int32_t pid, int32_t pipeType, int (&pipeFd)[2])
{
#ifndef is_ohos_lite
    if (pipeType < FaultLoggerPipeType::PIPE_FD_READ || pipeType > FaultLoggerPipeType::PIPE_FD_DELETE) {
        DFXLOGE("%{public}s.%{public}s :: pipeType: %{public}d failed.", FAULTLOGGERD_CLIENT_TAG, __func__, pipeType);
        return ResponseCode::DEFAULT_ERROR_CODE;
    }
    PipFdRequestData request{};
    FillRequestHeadData(request.head, FaultLoggerClientType::PIPE_FD_CLIENT);
    request.pipeType = static_cast<int8_t>(pipeType);
    request.pid = pid;
    SocketRequestData socketRequestData = {&request, sizeof(request)};
    SocketFdData socketFdData = {pipeFd, PIPE_NUM_SZ};
    return SendRequestToServer(GetSocketName().c_str(), socketRequestData, CRASHDUMP_SOCKET_TIMEOUT, &socketFdData);
#else
    return ResponseCode::DEFAULT_ERROR_CODE;
#endif
}

int32_t RequestDelPipeFd(int32_t pid)
{
#ifndef is_ohos_lite
    PipFdRequestData request{};
    FillRequestHeadData(request.head, FaultLoggerClientType::PIPE_FD_CLIENT);
    request.pipeType = FaultLoggerPipeType::PIPE_FD_DELETE;
    request.pid = pid;
    return SendRequestToServer(GetSocketName().c_str(), {&request, sizeof(request)}, SDKDUMP_SOCKET_TIMEOUT);
#else
    return ResponseCode::DEFAULT_ERROR_CODE;
#endif
}

int32_t ReportDumpStats(struct FaultLoggerdStatsRequest *request)
{
    if (request == nullptr) {
        return ResponseCode::DEFAULT_ERROR_CODE;
    }
    int32_t retCode{ResponseCode::REQUEST_SUCCESS};
#ifndef HISYSEVENT_DISABLE
    FillRequestHeadData(request->head, FaultLoggerClientType::DUMP_STATS_CLIENT);
    FaultLoggerdSocket faultLoggerdSocket;
    if (!faultLoggerdSocket.CreateSocketFileDescriptor(SDKDUMP_SOCKET_TIMEOUT)) {
        return ResponseCode::CONNECT_FAILED;
    }
    if (!faultLoggerdSocket.StartConnect(GetSocketName().c_str())) {
        retCode = ResponseCode::CONNECT_FAILED;
    } else if (!faultLoggerdSocket.SendMsgToSocket(request, sizeof (FaultLoggerdStatsRequest))) {
        retCode = ResponseCode::SEND_DATA_FAILED;
    }
    faultLoggerdSocket.CloseSocketFileDescriptor();
#endif
    return retCode;
}