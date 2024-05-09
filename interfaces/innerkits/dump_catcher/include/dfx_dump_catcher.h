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

#ifndef DFX_DUMPCATCH_H
#define DFX_DUMPCATCH_H

#include <cinttypes>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unistd.h>
#include <vector>

namespace OHOS {
namespace HiviewDFX {
static const size_t DEFAULT_MAX_FRAME_NUM = 256;
class DfxDumpCatcher {
public:
    DfxDumpCatcher() {}
    ~DfxDumpCatcher() {}

    /**
     * @brief Dump native stack by specify pid and tid
     *
     * @param pid  process id
     * @param tid  thread id
     * @param msg  message of native stack
     * @param maxFrameNums the maximum number of frames to dump, if pid is not equal to caller pid then it is ignored
     * @param isJson whether message of native stack is json formatted
     * @return if succeed return true, otherwise return false
    */
    bool DumpCatch(int pid, int tid, std::string& msg, size_t maxFrameNums = DEFAULT_MAX_FRAME_NUM,
                   bool isJson = false);

    /**
     * @brief Dump native and js mixed-stack by specify pid and tid
     *
     * @param pid  process id
     * @param tid  thread id
     * @param msg  message of native and js mixed-stack
     * @return if succeed return true, otherwise return false
    */
    bool DumpCatchMix(int pid, int tid, std::string& msg);

    /**
     * @brief Dump native stack by specify pid and tid to file
     *
     * @param pid  process id
     * @param tid  thread id
     * @param fd  file descriptor
     * @param maxFrameNums the maximum number of frames to dump,
     *  if pid is not equal to caller pid then it does not support setting
     * @return if succeed return true, otherwise return false
    */
    bool DumpCatchFd(int pid, int tid, std::string& msg, int fd, size_t maxFrameNums = DEFAULT_MAX_FRAME_NUM);

    /**
     * @brief Dump native stack by multi-pid
     *
     * @param pid  process id
     * @param tid  thread id
     * @param msg  message of native stack
     * @return if succeed return true, otherwise return false
    */
    bool DumpCatchMultiPid(const std::vector<int> pidV, std::string& msg);

private:
    bool DoDumpCurrTid(const size_t skipFrameNum, std::string& msg, size_t maxFrameNums);
    bool DoDumpLocalTid(const int tid, std::string& msg, size_t maxFrameNums);
    bool DoDumpLocalPid(int pid, std::string& msg, size_t maxFrameNums);
    bool DoDumpLocalLocked(int pid, int tid, std::string& msg, size_t maxFrameNums);
    bool DoDumpRemoteLocked(int pid, int tid, std::string& msg, bool isJson = false);
    bool DoDumpCatchRemote(int pid, int tid, std::string& msg, bool isJson = false);
    int DoDumpRemotePid(int pid, std::string& msg, bool isJson = false, int32_t timeout = DUMPCATCHER_REMOTE_TIMEOUT);
    int DoDumpRemotePoll(int bufFd, int resFd, int timeout, std::string& msg, bool isJson = false);
    bool DoReadBuf(int fd, std::string& msg);
    bool DoReadRes(int fd, bool &ret, std::string& msg);
    bool IsValidJson(const std::string& json);
    void CollectKernelInfo();

private:
    static const int DUMPCATCHER_REMOTE_P90_TIMEOUT = 1000;
    static const int DUMPCATCHER_REMOTE_TIMEOUT = 10000;
    std::mutex mutex_;
    int32_t pid_ = -1;
    std::string halfProcStatus_ = "";
    std::string halfProcWchan_ = "";
    std::string halfKernelStack_ = "";
};
} // namespace HiviewDFX
} // namespace OHOS

#endif
