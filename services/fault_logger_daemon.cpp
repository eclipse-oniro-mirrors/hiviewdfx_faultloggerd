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

#include "fault_logger_daemon.h"

#include <algorithm>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <ctime>
#include <dirent.h>
#include <fcntl.h>
#include <securec.h>
#include <sstream>
#include <unistd.h>
#include <vector>

#include <sys/epoll.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>

#include "dfx_define.h"
#include "dfx_log.h"
#include "dfx_util.h"
#include "directory_ex.h"
#include "fault_logger_config.h"
#include "fault_logger_pipe.h"
#include "faultloggerd_socket.h"

namespace OHOS {
namespace HiviewDFX {
std::shared_ptr<FaultLoggerConfig> faultLoggerConfig_;
std::shared_ptr<FaultLoggerPipeMap> faultLoggerPipeMap_;

namespace {
constexpr int32_t MAX_CONNECTION = 30;
constexpr int32_t REQUEST_BUF_SIZE = 1024;
constexpr int32_t MAX_EPOLL_EVENT = 1024;
const int32_t FAULTLOG_FILE_PROP = 0640;

static constexpr uint32_t ROOT_UID = 0;
static constexpr uint32_t BMS_UID = 1000;
static constexpr uint32_t HIVIEW_UID = 1201;
static constexpr uint32_t HIDUMPER_SERVICE_UID = 1212;
static constexpr uint32_t FOUNDATION_UID = 5523;
static const std::string FAULTLOGGERD_TAG = "FaultLoggerd";
static const std::string DAEMON_RESP = "RESP:COMPLETE";
static const int DAEMON_REMOVE_FILE_TIME_S = 60;

static std::string GetRequestTypeName(int32_t type)
{
    switch (type) {
        case (int32_t)FaultLoggerType::CPP_CRASH:
            return "cppcrash";
        case (int32_t)FaultLoggerType::CPP_STACKTRACE: // change the name to nativestack ?
            return "stacktrace";
        case (int32_t)FaultLoggerType::JS_STACKTRACE:
            return "jsstack";
        case (int32_t)FaultLoggerType::JS_HEAP_SNAPSHOT:
            return "jsheap";
        default:
            return "unsupported";
    }
}

static bool CheckCallerUID(uint32_t callerUid)
{
    // If caller's is BMS / root or caller's uid/pid is validate, just return true
    if ((callerUid == BMS_UID) ||
        (callerUid == ROOT_UID) ||
        (callerUid == HIVIEW_UID) ||
        (callerUid == HIDUMPER_SERVICE_UID) ||
        (callerUid == FOUNDATION_UID)) {
        return true;
    }
    DFXLOG_WARN("%s :: CheckCallerUID :: Caller Uid(%d) is unexpectly.\n", FAULTLOGGERD_TAG.c_str(), callerUid);
    return false;
}
}

FaultLoggerDaemon::FaultLoggerDaemon()
{
}

int32_t FaultLoggerDaemon::StartServer()
{
    if (!CreateSockets()) {
        DFXLOG_ERROR("%s :: Failed to create faultloggerd sockets.", FAULTLOGGERD_TAG.c_str());
        CleanupSockets();
        return -1;
    }

    if (!InitEnvironment()) {
        DFXLOG_ERROR("%s :: Failed to init environment.", FAULTLOGGERD_TAG.c_str());
        CleanupSockets();
        return -1;
    }

    if (!CreateEventFd()) {
        DFXLOG_ERROR("%s :: Failed to create eventFd.", FAULTLOGGERD_TAG.c_str());
        CleanupSockets();
        return -1;
    }

    // loop in WaitForRequest
    WaitForRequest();

    CleanupEventFd();
    CleanupSockets();
    return 0;
}

void FaultLoggerDaemon::HandleAccept(int32_t epollFd, int32_t socketFd)
{
    struct sockaddr_un clientAddr;
    socklen_t clientAddrSize = static_cast<socklen_t>(sizeof(clientAddr));

    int connectionFd = accept(socketFd, reinterpret_cast<struct sockaddr *>(&clientAddr), &clientAddrSize);
    if (connectionFd < 0) {
        DFXLOG_WARN("%s :: Failed to accept connection", FAULTLOGGERD_TAG.c_str());
        return;
    }

    AddEvent(eventFd_, connectionFd, EPOLLIN);
    connectionMap_.insert(std::pair<int32_t, int32_t>(connectionFd, socketFd));
}

void FaultLoggerDaemon::HandleRequest(int32_t epollFd, int32_t connectionFd)
{
    if (epollFd < 0 || connectionFd < 3) { // 3: not allow fd = 0,1,2 because they are reserved by system
        DFXLOG_ERROR("%s :: HandleRequest recieved invalid fd parmeters.", FAULTLOGGERD_TAG.c_str());
        return;
    }
    char buf[REQUEST_BUF_SIZE] = {0};

    do {
        ssize_t nread = read(connectionFd, buf, sizeof(buf));
        if (nread < 0) {
            DFXLOG_ERROR("%s :: Failed to read message", FAULTLOGGERD_TAG.c_str());
            break;
        } else if (nread == 0) {
            DFXLOG_ERROR("%s :: HandleRequest :: Read null from request socket", FAULTLOGGERD_TAG.c_str());
            break;
        } else if (nread != static_cast<long>(sizeof(FaultLoggerdRequest))) {
            DFXLOG_ERROR("%s :: Unmatched request length", FAULTLOGGERD_TAG.c_str());
            break;
        }

        auto request = reinterpret_cast<FaultLoggerdRequest *>(buf);
        if (!CheckRequestCredential(connectionFd, request)) {
            break;
        }

        DFXLOG_DEBUG("%s :: clientType(%d).\n", FAULTLOGGERD_TAG.c_str(), request->clientType);
        switch (request->clientType) {
            case static_cast<int32_t>(FaultLoggerClientType::DEFAULT_CLIENT):
                HandleDefaultClientRequest(connectionFd, request);
                break;
            case static_cast<int32_t>(FaultLoggerClientType::LOG_FILE_DES_CLIENT):
                HandleLogFileDesClientRequest(connectionFd, request);
                break;
            case static_cast<int32_t>(FaultLoggerClientType::PRINT_T_HILOG_CLIENT):
                HandlePrintTHilogClientRequest(connectionFd, request);
                break;
            case static_cast<int32_t>(FaultLoggerClientType::PERMISSION_CLIENT):
                HandlePermissionRequest(connectionFd, request);
                break;
            case static_cast<int32_t>(FaultLoggerClientType::SDK_DUMP_CLIENT):
                HandleSdkDumpRequest(connectionFd, request);
                break;
            case static_cast<int32_t>(FaultLoggerClientType::PIPE_FD_CLIENT):
                HandlePipeFdClientRequest(connectionFd, request);
                break;
            default:
                DFXLOG_ERROR("%s :: unknown clientType(%d).\n", FAULTLOGGERD_TAG.c_str(), request->clientType);
                break;
        }
    } while (false);

    DelEvent(eventFd_, connectionFd, EPOLLIN);
    connectionMap_.erase(connectionFd);
}

bool FaultLoggerDaemon::InitEnvironment()
{
    faultLoggerConfig_ = std::make_shared<FaultLoggerConfig>(LOG_FILE_NUMBER, LOG_FILE_SIZE,
        LOG_FILE_PATH, DEBUG_LOG_FILE_PATH);
    faultLoggerPipeMap_ = std::make_shared<FaultLoggerPipeMap>();

    if (!OHOS::ForceCreateDirectory(faultLoggerConfig_->GetLogFilePath())) {
        DFXLOG_ERROR("%s :: Failed to ForceCreateDirectory GetLogFilePath", FAULTLOGGERD_TAG.c_str());
        return false;
    }

    if (!OHOS::ForceCreateDirectory(faultLoggerConfig_->GetDebugLogFilePath())) {
        DFXLOG_ERROR("%s :: Failed to ForceCreateDirectory GetDebugLogFilePath", FAULTLOGGERD_TAG.c_str());
        return false;
    }

    signal(SIGCHLD, SIG_IGN);
    signal(SIGPIPE, SIG_IGN);
    return true;
}

void FaultLoggerDaemon::HandleDefaultClientRequest(int32_t connectionFd, const FaultLoggerdRequest * request)
{
    RemoveTempFileIfNeed();

    int fd = CreateFileForRequest(request->type, request->pid, request->time, false);
    if (fd < 0) {
        DFXLOG_ERROR("%s :: Failed to create log file, errno(%d)", FAULTLOGGERD_TAG.c_str(), errno);
        return;
    }
    SendFileDescriptorToSocket(connectionFd, fd);

    close(fd);
}

void FaultLoggerDaemon::HandleLogFileDesClientRequest(int32_t connectionFd, const FaultLoggerdRequest * request)
{
    int fd = CreateFileForRequest(request->type, request->pid, request->time, true);
    if (fd < 0) {
        DFXLOG_ERROR("%s :: Failed to create log file, errno(%d)", FAULTLOGGERD_TAG.c_str(), errno);
        return;
    }
    SendFileDescriptorToSocket(connectionFd, fd);

    close(fd);
}

void FaultLoggerDaemon::HandlePipeFdClientRequest(int32_t connectionFd, FaultLoggerdRequest * request)
{
    DFXLOG_DEBUG("%s :: pid(%d), pipeType(%d).\n", FAULTLOGGERD_TAG.c_str(), request->pid, request->pipeType);
    int fd = -1;

    FaultLoggerPipe2* faultLoggerPipe = faultLoggerPipeMap_->Get(request->pid);
    if (faultLoggerPipe == nullptr) {
        DFXLOG_ERROR("%s :: cannot find pipe fd for pid(%d).\n", FAULTLOGGERD_TAG.c_str(), request->pid);
        return;
    }

    switch (request->pipeType) {
        case (int32_t)FaultLoggerPipeType::PIPE_FD_READ_BUF: {
            FaultLoggerCheckPermissionResp resSecurityCheck = SecurityCheck(connectionFd, request);
            if (FaultLoggerCheckPermissionResp::CHECK_PERMISSION_PASS != resSecurityCheck) {
                return;
            }
            fd = faultLoggerPipe->faultLoggerPipeBuf_->GetReadFd();
            break;
        }
        case (int32_t)FaultLoggerPipeType::PIPE_FD_WRITE_BUF: {
            fd = faultLoggerPipe->faultLoggerPipeBuf_->GetWriteFd();
            break;
        }
        case (int32_t)FaultLoggerPipeType::PIPE_FD_READ_RES: {
            FaultLoggerCheckPermissionResp resSecurityCheck = SecurityCheck(connectionFd, request);
            if (FaultLoggerCheckPermissionResp::CHECK_PERMISSION_PASS != resSecurityCheck) {
                return;
            }
            fd = faultLoggerPipe->faultLoggerPipeRes_->GetReadFd();
            break;
        }
        case (int32_t)FaultLoggerPipeType::PIPE_FD_WRITE_RES: {
            fd = faultLoggerPipe->faultLoggerPipeRes_->GetWriteFd();
            break;
        }
        case (int32_t)FaultLoggerPipeType::PIPE_FD_DELETE: {
            faultLoggerPipeMap_->Del(request->pid);
            return;
        }
        default:
            DFXLOG_ERROR("%s :: unknown pipeType(%d).\n", FAULTLOGGERD_TAG.c_str(), request->pipeType);
            return;
    }

    if (fd < 0) {
        DFXLOG_ERROR("%s :: Failed to get pipe fd", FAULTLOGGERD_TAG.c_str());
        return;
    }
    SendFileDescriptorToSocket(connectionFd, fd);
}

void FaultLoggerDaemon::HandlePrintTHilogClientRequest(int32_t const connectionFd, FaultLoggerdRequest * request)
{
    char buf[LOG_BUF_LEN] = {0};

    if (write(connectionFd, DAEMON_RESP.c_str(), DAEMON_RESP.length()) != static_cast<ssize_t>(DAEMON_RESP.length())) {
        DFXLOG_ERROR("%s :: Failed to write DAEMON_RESP.", FAULTLOGGERD_TAG.c_str());
    }

    int nread = read(connectionFd, buf, sizeof(buf) - 1);
    if (nread < 0) {
        DFXLOG_ERROR("%s :: Failed to read message, errno(%d)", FAULTLOGGERD_TAG.c_str(), errno);
    } else if (nread == 0) {
        DFXLOG_ERROR("%s :: HandlePrintTHilogClientRequest :: Read null from request socket", FAULTLOGGERD_TAG.c_str());
    } else {
        DFXLOG_ERROR("%s", buf);
    }
}

FaultLoggerCheckPermissionResp FaultLoggerDaemon::SecurityCheck(int32_t connectionFd, FaultLoggerdRequest * request)
{
    FaultLoggerCheckPermissionResp resCheckPermission = FaultLoggerCheckPermissionResp::CHECK_PERMISSION_REJECT;

    struct ucred rcred;
    do {
        int optval = 1;
        if (setsockopt(connectionFd, SOL_SOCKET, SO_PASSCRED, &optval, sizeof(optval)) == -1) {
            DFXLOG_ERROR("%s :: setsockopt SO_PASSCRED error, errno(%d)", FAULTLOGGERD_TAG.c_str(), errno);
            break;
        }

        if (write(connectionFd, DAEMON_RESP.c_str(), DAEMON_RESP.length()) !=
            static_cast<ssize_t>(DAEMON_RESP.length())) {
            DFXLOG_ERROR("%s :: Failed to write DAEMON_RESP, errno(%d)", FAULTLOGGERD_TAG.c_str(), errno);
        }

        if (!RecvMsgCredFromSocket(connectionFd, &rcred)) {
            DFXLOG_ERROR("%s :: Recv msg ucred error.", FAULTLOGGERD_TAG.c_str());
            break;
        }

        request->uid = rcred.uid;
        request->callerPid = static_cast<int32_t>(rcred.pid);
        bool res = CheckCallerUID(request->uid);
        if (res) {
            resCheckPermission = FaultLoggerCheckPermissionResp::CHECK_PERMISSION_PASS;
        }
    } while (false);

    return resCheckPermission;
}

void FaultLoggerDaemon::HandlePermissionRequest(int32_t connectionFd, FaultLoggerdRequest * request)
{
    FaultLoggerCheckPermissionResp resSecurityCheck = SecurityCheck(connectionFd, request);
    if (FaultLoggerCheckPermissionResp::CHECK_PERMISSION_PASS == resSecurityCheck) {
        send(connectionFd, "1", strlen("1"), 0);
    }
    if (FaultLoggerCheckPermissionResp::CHECK_PERMISSION_REJECT == resSecurityCheck) {
        send(connectionFd, "2", strlen("2"), 0);
    }
}

void FaultLoggerDaemon::HandleSdkDumpRequest(int32_t connectionFd, FaultLoggerdRequest * request)
{
    DFXLOG_INFO("Receive dump request for pid:%d tid:%d.", request->pid, request->tid);
    FaultLoggerSdkDumpResp resSdkDump = FaultLoggerSdkDumpResp::SDK_DUMP_PASS;
    FaultLoggerCheckPermissionResp resSecurityCheck = SecurityCheck(connectionFd, request);

    /*
    *           all     threads my user, local pid             my user, remote pid     other user's process
    * 3rd       Y       Y(in signal_handler local)     Y(in signal_handler loacl)      N
    * system    Y       Y(in signal_handler local)     Y(in signal_handler loacl)      Y(in signal_handler remote)
    * root      Y       Y(in signal_handler local)     Y(in signal_handler loacl)      Y(in signal_handler remote)
    */

    /*
    * 1. pid != 0 && tid != 0:    means we want dump a thread, so we send signal to a thread.
        Main thread stack is tid's stack, we need ignore other thread info.
    * 2. pid != 0 && tid == 0:    means we want dump a process, so we send signal to process.
        Main thead stack is pid's stack, we need other tread info.
    */

    /*
     * in signal_handler we need to check caller pid and tid(which is send to signal handler by SYS_rt_sig.).
     * 1. caller pid == signal pid, means we do back trace in ourself process, means local backtrace.
     *      |- we do all tid back trace in signal handler's local unwind.
     * 2. pid != signal pid, means we do remote back trace.
     */

    /*
     * in local back trace, all unwind stack will save to signal_handler global var.(mutex lock in signal handler.)
     * in remote back trace, all unwind stack will save to file, and read in dump_catcher, then return.
     */

    do {
        if ((request->pid <= 0) || (FaultLoggerCheckPermissionResp::CHECK_PERMISSION_REJECT == resSecurityCheck)) {
            DFXLOG_ERROR("%s :: HandleSdkDumpRequest :: pid(%d) or resSecurityCheck(%d) fail.\n", \
                FAULTLOGGERD_TAG.c_str(), request->pid, (int)resSecurityCheck);
            resSdkDump = FaultLoggerSdkDumpResp::SDK_DUMP_REJECT;
            break;
        }

        if (faultLoggerPipeMap_->Check(request->pid, request->time)) {
            resSdkDump = FaultLoggerSdkDumpResp::SDK_DUMP_REPEAT;
            DFXLOG_ERROR("%s :: pid(%d) is dumping, break.\n", FAULTLOGGERD_TAG.c_str(), request->pid);
            break;
        }
        faultLoggerPipeMap_->Set(request->pid, request->time);

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Winitializer-overrides"
        // defined in out/hi3516dv300/obj/third_party/musl/intermidiates/linux/musl_src_ported/include/signal.h
        siginfo_t si = {
            .si_signo = SIGDUMP,
            .si_errno = 0,
            .si_code = request->sigCode,
            .si_value.sival_int = request->tid,
            .si_pid = request->callerPid,
            .si_uid = static_cast<uid_t>(request->callerTid)
        };
#pragma clang diagnostic pop
        // means we need dump all the threads in a process.
        if (request->tid == 0) {
            if (syscall(SYS_rt_sigqueueinfo, request->pid, si.si_signo, &si) != 0) {
                DFXLOG_ERROR("Failed to SYS_rt_sigqueueinfo signal(%d), errno(%d).", si.si_signo, errno);
                resSdkDump = FaultLoggerSdkDumpResp::SDK_DUMP_NOPROC;
                break;
            }
        } else {
            // means we need dump a specified thread
            if (syscall(SYS_rt_tgsigqueueinfo, request->pid, request->tid, si.si_signo, &si) != 0) {
                DFXLOG_ERROR("Failed to SYS_rt_tgsigqueueinfo signal(%d), errno(%d).", si.si_signo, errno);
                resSdkDump = FaultLoggerSdkDumpResp::SDK_DUMP_NOPROC;
                break;
            }
        }
    } while (false);

    switch (resSdkDump) {
        case FaultLoggerSdkDumpResp::SDK_DUMP_REJECT:
            send(connectionFd, "2", strlen("2"), 0);
            break;
        case FaultLoggerSdkDumpResp::SDK_DUMP_REPEAT:
            send(connectionFd, "3", strlen("3"), 0);
            break;
        case FaultLoggerSdkDumpResp::SDK_DUMP_NOPROC:
            send(connectionFd, "4", strlen("4"), 0);
            break;
        default:
            send(connectionFd, "1", strlen("1"), 0);
            break;
    }
}

int32_t FaultLoggerDaemon::CreateFileForRequest(int32_t type, int32_t pid, uint64_t time, bool debugFlag) const
{
    std::string typeStr = GetRequestTypeName(type);
    if (typeStr == "unsupported") {
        DFXLOG_ERROR("Unsupported request type(%d)", type);
        return -1;
    }

    std::string filePath = "";
    if (debugFlag == false) {
        filePath = faultLoggerConfig_->GetLogFilePath();
    } else {
        filePath = faultLoggerConfig_->GetDebugLogFilePath();
    }

    if (time == 0) {
        time = static_cast<uint64_t>(std::chrono::duration_cast<std::chrono::milliseconds>\
            (std::chrono::system_clock::now().time_since_epoch()).count());
    }

    std::stringstream crashTime;
    crashTime << "-" << time;
    const std::string path = filePath + "/" + typeStr + "-" + std::to_string(pid) + crashTime.str();
    DFXLOG_INFO("%s :: file path(%s).\n", FAULTLOGGERD_TAG.c_str(), path.c_str());
    if (!VerifyFilePath(path, VALID_FILE_PATH)) {
        DFXLOG_ERROR("%s :: Open %s fail, please check it under valid path.\n", FAULTLOGGERD_TAG.c_str(), path.c_str());
        return -1;
    }
    int32_t fd = OHOS_TEMP_FAILURE_RETRY(open(path.c_str(), O_RDWR | O_CREAT, FAULTLOG_FILE_PROP));
    if (fd != -1) {
        if (!ChangeModeFile(path, FAULTLOG_FILE_PROP)) {
            DFXLOG_ERROR("%s :: Failed to ChangeMode CreateFileForRequest", FAULTLOGGERD_TAG.c_str());
        }
    }
    return fd;
}

void FaultLoggerDaemon::RemoveTempFileIfNeed()
{
    int maxFileCount = 50;
    int currentLogCounts = 0;

    std::vector<std::string> files;
    OHOS::GetDirFiles(faultLoggerConfig_->GetLogFilePath(), files);
    currentLogCounts = (int)files.size();

    maxFileCount = faultLoggerConfig_->GetLogFileMaxNumber();
    if (currentLogCounts < maxFileCount) {
        return;
    }

    std::sort(files.begin(), files.end(),
        [](const std::string& lhs, const std::string& rhs) -> int
    {
        auto lhsSplitPos = lhs.find_last_of("-");
        auto rhsSplitPos = rhs.find_last_of("-");
        if (lhsSplitPos == std::string::npos || rhsSplitPos == std::string::npos) {
            return lhs.compare(rhs) > 0;
        }

        return lhs.substr(lhsSplitPos).compare(rhs.substr(rhsSplitPos)) > 0;
    });

    time_t currentTime = static_cast<time_t>(time(nullptr));
    if (currentTime <= 0) {
        DFXLOG_ERROR("%s :: currentTime is less than zero CreateFileForRequest", FAULTLOGGERD_TAG.c_str());
    }

    int startIndex = maxFileCount / 2;
    for (unsigned int index = (unsigned int)startIndex; index < files.size(); index++) {
        struct stat st;
        int err = stat(files[index].c_str(), &st);
        if (err != 0) {
            DFXLOG_ERROR("%s :: Get log stat failed, errno(%d).", FAULTLOGGERD_TAG.c_str(), errno);
        } else {
            if ((currentTime - st.st_mtime) <= DAEMON_REMOVE_FILE_TIME_S) {
                continue;
            }
        }

        OHOS::RemoveFile(files[index]);
        DFXLOG_DEBUG("%s :: Now we rm file(%s) as max log number exceeded.", \
            FAULTLOGGERD_TAG.c_str(), files[index].c_str());
    }
}

void FaultLoggerDaemon::AddEvent(int32_t epollFd, int32_t addFd, uint32_t event)
{
    epoll_event ev;
    ev.events = event;
    ev.data.fd = addFd;
    int ret = epoll_ctl(epollFd, EPOLL_CTL_ADD, addFd, &ev);
    if (ret < 0) {
        DFXLOG_WARN("%s :: Failed to epoll ctl add Fd(%d), errno(%d)", FAULTLOGGERD_TAG.c_str(), addFd, errno);
    }
}

void FaultLoggerDaemon::DelEvent(int32_t epollFd, int32_t delFd, uint32_t event)
{
    epoll_event ev;
    ev.events = event;
    ev.data.fd = delFd;
    int ret = epoll_ctl(epollFd, EPOLL_CTL_DEL, delFd, &ev);
    if (ret < 0) {
        DFXLOG_WARN("%s :: Failed to epoll ctl del Fd(%d), errno(%d)", FAULTLOGGERD_TAG.c_str(), delFd, errno);
    }
    close(delFd);
}

bool FaultLoggerDaemon::CheckRequestCredential(int32_t connectionFd, FaultLoggerdRequest* request)
{
    if (request == nullptr) {
        return false;
    }

    auto it = connectionMap_.find(connectionFd);
    if (it == connectionMap_.end()) {
        return false;
    }

    if (it->second == crashSocketFd_) {
        // only processdump use this socket
        return true;
    }

    struct ucred creds = {};
    socklen_t credSize = sizeof(creds);
    int err = getsockopt(connectionFd, SOL_SOCKET, SO_PEERCRED, &creds, &credSize);
    if (err != 0) {
        DFXLOG_ERROR("%s :: Failed to CheckRequestCredential, errno(%d)", FAULTLOGGERD_TAG.c_str(), errno);
        return false;
    }

    if (CheckCallerUID(creds.uid)) {
        return true;
    }

    bool isCredentialMatched = (creds.pid == request->pid);
    if (!isCredentialMatched) {
        DFXLOG_WARN("Failed to check request credential request:%d:%d cred:%d:%d",
            request->pid, request->uid, creds.pid, creds.uid);
    }
    return isCredentialMatched;
}

bool FaultLoggerDaemon::CreateSockets()
{
    if (!StartListen(defaultSocketFd_, SERVER_SOCKET_NAME, MAX_CONNECTION)) {
        return false;
    }

    if (!StartListen(crashSocketFd_, SERVER_CRASH_SOCKET_NAME, MAX_CONNECTION)) {
        close(defaultSocketFd_);
        defaultSocketFd_ = -1;
        return false;
    }

    return true;
}

void FaultLoggerDaemon::CleanupSockets()
{
    if (defaultSocketFd_ >= 0) {
        close(defaultSocketFd_);
        defaultSocketFd_ = -1;
    }

    if (crashSocketFd_ >= 0) {
        close(crashSocketFd_);
        crashSocketFd_ = -1;
    }
}

bool FaultLoggerDaemon::CreateEventFd()
{
    eventFd_ = epoll_create(MAX_EPOLL_EVENT);
    if (eventFd_ < 0) {
        return false;
    }
    return true;
}

void FaultLoggerDaemon::WaitForRequest()
{
    AddEvent(eventFd_, defaultSocketFd_, EPOLLIN);
    AddEvent(eventFd_, crashSocketFd_, EPOLLIN);
    epoll_event events[MAX_CONNECTION];
    DFXLOG_DEBUG("%s :: %s: start epoll wait.", FAULTLOGGERD_TAG.c_str(), __func__);
    do {
        int epollNum = epoll_wait(eventFd_, events, MAX_CONNECTION, -1);
        if (epollNum < 0) {
            if (errno != EINTR) {
                DFXLOG_ERROR("%s :: %s: epoll wait error, errno(%d).", FAULTLOGGERD_TAG.c_str(), __func__, errno);
            }
            continue;
        }
        for (int i = 0; i < epollNum; i++) {
            if (!(events[i].events & EPOLLIN)) {
                DFXLOG_WARN("%s :: %s: epoll event(%d) error.", FAULTLOGGERD_TAG.c_str(), __func__, events[i].events);
                continue;
            }

            int fd = events[i].data.fd;
            if (fd == defaultSocketFd_ || fd == crashSocketFd_) {
                HandleAccept(eventFd_, fd);
            } else {
                HandleRequest(eventFd_, fd);
            }
        }
    } while (true);
}

void FaultLoggerDaemon::CleanupEventFd()
{
    DelEvent(eventFd_, defaultSocketFd_, EPOLLIN);
    DelEvent(eventFd_, crashSocketFd_, EPOLLIN);

    if (eventFd_ > 0) {
        close(eventFd_);
        eventFd_ = -1;
    }
}
} // namespace HiviewDFX
} // namespace OHOS
