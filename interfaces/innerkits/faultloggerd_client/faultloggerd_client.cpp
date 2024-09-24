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

#include <climits>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <securec.h>
#include <unistd.h>

#include <sys/socket.h>
#include <sys/syscall.h>
#include <sys/un.h>
#include <sys/stat.h>

#include "dfx_cutil.h"
#include "dfx_define.h"
#include "dfx_log.h"
#include "dfx_util.h"
#include "faultloggerd_socket.h"

static const int32_t SOCKET_TIMEOUT = 5;

static std::string GetSocketConnectionName()
{
    char content[NAME_BUF_LEN];
    GetProcessName(content, sizeof(content));
    if (std::string(content).find("processdump") != std::string::npos) {
        return std::string(SERVER_CRASH_SOCKET_NAME);
    }
    return std::string(SERVER_SOCKET_NAME);
}

int32_t RequestFileDescriptor(int32_t type)
{
    struct FaultLoggerdRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    request.type = type;
    request.pid = getpid();
    request.tid = gettid();
    request.uid = getuid();
    request.time = OHOS::HiviewDFX::GetTimeMilliSeconds();
    return RequestFileDescriptorEx(&request);
}

int32_t RequestLogFileDescriptor(struct FaultLoggerdRequest *request)
{
    if (request == nullptr) {
        LOGERROR("nullptr request");
        return -1;
    }
    request->clientType = (int32_t)FaultLoggerClientType::LOG_FILE_DES_CLIENT;
    return RequestFileDescriptorEx(request);
}

int32_t RequestFileDescriptorEx(const struct FaultLoggerdRequest *request)
{
    if (request == nullptr) {
        LOGERROR("nullptr request");
        return -1;
    }

    int sockfd;
    std::string name = GetSocketConnectionName();
    if (!StartConnect(sockfd, name.c_str(), SOCKET_TIMEOUT)) {
        LOGERROR("StartConnect(%{public}d) failed", sockfd);
        return -1;
    }

    OHOS_TEMP_FAILURE_RETRY(write(sockfd, request, sizeof(struct FaultLoggerdRequest)));
    int fd = ReadFileDescriptorFromSocket(sockfd);
    LOGDEBUG("RequestFileDescriptorEx(%{public}d).", fd);
    close(sockfd);
    return fd;
}

static bool CheckReadResp(int sockfd)
{
    char ControlBuffer[SOCKET_BUFFER_SIZE] = {0};
    ssize_t nread = OHOS_TEMP_FAILURE_RETRY(read(sockfd, ControlBuffer, sizeof(ControlBuffer) - 1));
    if (nread != static_cast<ssize_t>(strlen(FAULTLOGGER_DAEMON_RESP))) {
        LOGERROR("nread: %{public}zd.", nread);
        return false;
    }
    return true;
}

static int32_t RequestFileDescriptorByCheck(const struct FaultLoggerdRequest *request)
{
    int32_t fd = -1;
    if (request == nullptr) {
        LOGERROR("nullptr request");
        return -1;
    }

    int sockfd = -1;
    do {
        std::string name = GetSocketConnectionName();
        if (!StartConnect(sockfd, name.c_str(), SOCKET_TIMEOUT)) {
            LOGERROR("StartConnect(%{public}d) failed", sockfd);
            break;
        }

        OHOS_TEMP_FAILURE_RETRY(write(sockfd, request, sizeof(struct FaultLoggerdRequest)));

        if (!CheckReadResp(sockfd)) {
            break;
        }

        int data = 12345;
        if (!SendMsgIovToSocket(sockfd, reinterpret_cast<void *>(&data), sizeof(data))) {
            LOGERROR("%{public}s :: Failed to sendmsg.", __func__);
            break;
        }

        fd = ReadFileDescriptorFromSocket(sockfd);
        LOGDEBUG("RequestFileDescriptorByCheck(%{public}d).", fd);
    } while (false);
    close(sockfd);
    return fd;
}

static int SendUidToServer(int sockfd)
{
    int mRsp = (int)FaultLoggerCheckPermissionResp::CHECK_PERMISSION_REJECT;

    int data = 12345;
    if (!SendMsgIovToSocket(sockfd, reinterpret_cast<void *>(&data), sizeof(data))) {
        LOGERROR("%{public}s :: Failed to sendmsg.", __func__);
        return mRsp;
    }

    char recvbuf[SOCKET_BUFFER_SIZE] = {'\0'};
    ssize_t count = OHOS_TEMP_FAILURE_RETRY(recv(sockfd, recvbuf, sizeof(recvbuf), 0));
    if (count < 0) {
        LOGERROR("%{public}s :: Failed to recv.", __func__);
        return mRsp;
    }

    mRsp = atoi(recvbuf);
    return mRsp;
}

bool CheckConnectStatus()
{
    int sockfd = -1;
    std::string name = GetSocketConnectionName();
    if (StartConnect(sockfd, name.c_str(), SOCKET_TIMEOUT)) {
        close(sockfd);
        return true;
    }
    return false;
}

static int SendRequestToServer(const FaultLoggerdRequest &request)
{
    int sockfd = -1;
    int resRsp = (int)FaultLoggerCheckPermissionResp::CHECK_PERMISSION_REJECT;
    do {
        std::string name = GetSocketConnectionName();
        if (request.clientType == FaultLoggerClientType::SDK_DUMP_CLIENT) {
            name = std::string(SERVER_SDKDUMP_SOCKET_NAME);
        }

        if (!StartConnect(sockfd, name.c_str(), SOCKET_TIMEOUT)) {
            LOGERROR("StartConnect(%{public}d) failed", sockfd);
            break;
        }
        if (OHOS_TEMP_FAILURE_RETRY(write(sockfd, &request,
            sizeof(struct FaultLoggerdRequest))) != static_cast<long>(sizeof(request))) {
            LOGERROR("write failed.");
            break;
        }

        if (!CheckReadResp(sockfd)) {
            break;
        }
        resRsp = SendUidToServer(sockfd);
    } while (false);

    close(sockfd);
    LOGINFO("SendRequestToServer :: resRsp(%{public}d).", resRsp);
    return resRsp;
}

bool RequestCheckPermission(int32_t pid)
{
    LOGINFO("RequestCheckPermission :: %{public}d.", pid);
    if (pid <= 0) {
        return false;
    }

    struct FaultLoggerdRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));

    request.pid = pid;
    request.clientType = (int32_t)FaultLoggerClientType::PERMISSION_CLIENT;

    bool ret = false;
    if (SendRequestToServer(request) == (int)FaultLoggerCheckPermissionResp::CHECK_PERMISSION_PASS) {
        ret = true;
    }
    return ret;
}

int RequestSdkDump(int32_t pid, int32_t tid, int timeout)
{
    return RequestSdkDumpJson(pid, tid, false, timeout);
}

int RequestSdkDumpJson(int32_t pid, int32_t tid, bool isJson, int timeout)
{
    LOGINFO("RequestSdkDumpJson :: pid(%{public}d), tid(%{public}d).", pid, tid);
    if (pid <= 0 || tid < 0) {
        return -1;
    }

    struct FaultLoggerdRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    request.isJson = isJson;
    request.sigCode = DUMP_TYPE_REMOTE;
    request.pid = pid;
    request.tid = tid;
    request.callerPid = getpid();
    request.callerTid = gettid();
    request.clientType = (int32_t)FaultLoggerClientType::SDK_DUMP_CLIENT;
    request.time = OHOS::HiviewDFX::GetTimeMilliSeconds();
    request.endTime = GetAbsTimeMilliSeconds() + static_cast<uint64_t>(timeout);

    return SendRequestToServer(request);
}

int RequestPrintTHilog(const char *msg, int length)
{
    if (length >= LINE_BUF_SIZE) {
        return -1;
    }

    struct FaultLoggerdRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(request));
    request.clientType = (int32_t)FaultLoggerClientType::PRINT_T_HILOG_CLIENT;
    request.pid = getpid();
    request.uid = getuid();
    int sockfd = -1;
    do {
        std::string name = GetSocketConnectionName();
        if (!StartConnect(sockfd, name.c_str(), SOCKET_TIMEOUT)) {
            LOGERROR("StartConnect(%{public}d) failed", sockfd);
            break;
        }

        if (OHOS_TEMP_FAILURE_RETRY(write(sockfd, &request,
            sizeof(struct FaultLoggerdRequest))) != static_cast<long>(sizeof(request))) {
            break;
        }

        if (!CheckReadResp(sockfd)) {
            break;
        }

        int nwrite = OHOS_TEMP_FAILURE_RETRY(write(sockfd, msg, strlen(msg)));
        if (nwrite != static_cast<long>(strlen(msg))) {
            LOGERROR("nwrite: %{public}d.", nwrite);
            break;
        }
        close(sockfd);
        return 0;
    } while (false);
    close(sockfd);
    return -1;
}

int32_t RequestPipeFd(int32_t pid, int32_t pipeType)
{
    if (pipeType < static_cast<int32_t>(FaultLoggerPipeType::PIPE_FD_READ_BUF) ||
        pipeType > static_cast<int32_t>(FaultLoggerPipeType::PIPE_FD_DELETE)) {
        LOGERROR("%{public}s :: pipeType(%{public}d) failed.", __func__, pipeType);
        return -1;
    }
    struct FaultLoggerdRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(struct FaultLoggerdRequest));

    if ((pipeType == static_cast<int32_t>(FaultLoggerPipeType::PIPE_FD_JSON_READ_BUF)) ||
        (pipeType == static_cast<int32_t>(FaultLoggerPipeType::PIPE_FD_JSON_READ_RES))) {
        request.isJson = true;
    } else {
        request.isJson = false;
    }
    request.pipeType = pipeType;
    request.pid = pid;
    request.callerPid = getpid();
    request.callerTid = gettid();
    request.clientType = (int32_t)FaultLoggerClientType::PIPE_FD_CLIENT;
    if ((pipeType == static_cast<int32_t>(FaultLoggerPipeType::PIPE_FD_READ_BUF)) ||
        (pipeType == static_cast<int32_t>(FaultLoggerPipeType::PIPE_FD_READ_RES)) ||
        (pipeType == static_cast<int32_t>(FaultLoggerPipeType::PIPE_FD_JSON_READ_BUF)) ||
        (pipeType == static_cast<int32_t>(FaultLoggerPipeType::PIPE_FD_JSON_READ_RES))) {
        return RequestFileDescriptorByCheck(&request);
    }
    return RequestFileDescriptorEx(&request);
}

int32_t RequestDelPipeFd(int32_t pid)
{
    struct FaultLoggerdRequest request;
    (void)memset_s(&request, sizeof(request), 0, sizeof(struct FaultLoggerdRequest));
    request.pipeType = FaultLoggerPipeType::PIPE_FD_DELETE;
    request.pid = pid;
    request.clientType = (int32_t)FaultLoggerClientType::PIPE_FD_CLIENT;

    int sockfd;
    std::string name = GetSocketConnectionName();
    if (!StartConnect(sockfd, name.c_str(), SOCKET_TIMEOUT)) {
        LOGERROR("StartConnect(%{public}d) failed", sockfd);
        return -1;
    }

    OHOS_TEMP_FAILURE_RETRY(write(sockfd, &request, sizeof(struct FaultLoggerdRequest)));
    close(sockfd);
    return 0;
}

int ReportDumpStats(const struct FaultLoggerdStatsRequest *request)
{
    int sockfd = -1;
    std::string name = GetSocketConnectionName();
    if (!StartConnect(sockfd, name.c_str(), SOCKET_TIMEOUT)) {
        LOGERROR("ReportDumpCatcherStats: failed to connect to faultloggerd");
        return -1;
    }

    if (OHOS_TEMP_FAILURE_RETRY(write(sockfd, request,
        sizeof(struct FaultLoggerdStatsRequest))) != static_cast<long int>(sizeof(struct FaultLoggerdStatsRequest))) {
        LOGERROR("ReportDumpCatcherStats: failed to write stats.");
        close(sockfd);
        return -1;
    }
    close(sockfd);
    return 0;
}
