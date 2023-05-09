/*
 * Copyright (c) 2021-2022 Huawei Device Co., Ltd.
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

/* This files contains sdk dump catcher module. */

#ifndef DFX_DUMPCATCH_H
#define DFX_DUMPCATCH_H

#include <cinttypes>
#include <cstring>
#include <memory>
#include <mutex>
#include <string>
#include <unistd.h>
#include <vector>

#include "backtrace.h"
#include "dfx_define.h"
#include "dfx_symbols_cache.h"

// forward declaration
struct unw_addr_space;
typedef struct unw_addr_space *unw_addr_space_t;

namespace OHOS {
namespace HiviewDFX {
class DfxDumpCatcher {
public:
    DfxDumpCatcher();
    explicit DfxDumpCatcher(int32_t pid);
    ~DfxDumpCatcher();

    bool DumpCatch(int pid, int tid, std::string& msg);
    bool DumpCatchMix(int pid, int tid, std::string& msg);
    bool DumpCatchFd(int pid, int tid, std::string& msg, int fd);
    bool DumpCatchMultiPid(const std::vector<int> pidV, std::string& msg);

    bool InitFrameCatcher();
    bool ReleaseThread(int tid);
    bool CatchFrame(int tid, std::vector<NativeFrame>& frames, bool releaseThread = false);
    bool CatchFrame(std::vector<NativeFrame>& frames);
    void DestroyFrameCatcher();

private:
    bool DoDumpCurrTid(const size_t skipFrameNum, std::string& msg);
    bool DoDumpLocalTid(const int tid, std::string& msg);
    bool DoDumpLocalPid(int pid, std::string& msg);
    bool DoDumpLocalLocked(int pid, int tid, std::string& msg);
    bool DoDumpRemoteLocked(int pid, int tid, std::string& msg);
    bool DoDumpCatchRemote(const int type, int pid, int tid, std::string& msg);
    int DoDumpRemotePid(const int type, int pid, std::string& msg);
    int DoDumpRemotePoll(int bufFd, int resFd, int timeout, std::string& msg);
    bool DoReadBuf(int fd, std::string& msg);
    bool DoReadRes(int fd, bool &ret, std::string& msg);

private:
    std::mutex dumpCatcherMutex_;
    int32_t frameCatcherPid_;
    struct ProcInfo procInfo_;
    unw_addr_space_t as_ {nullptr};
    std::shared_ptr<DfxSymbolsCache> cache_ {nullptr};
};
} // namespace HiviewDFX
} // namespace OHOS

#endif
