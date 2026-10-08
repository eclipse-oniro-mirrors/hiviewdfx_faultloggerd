/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "kernel_snapshot_task.h"

#include <dlfcn.h>
#include <fcntl.h>
#include <string>

#include "dfx_log.h"
#include "parameters.h"
#include "smart_fd.h"
#include "dfx_util.h"

namespace OHOS {
namespace HiviewDFX {

namespace {
std::string ReadKernelSnapshot()
{
#ifdef FAULTLOGGERD_TEST
    constexpr auto kernelKboxSnapshot = "/data/test/resource/testdata/kernel_snapshot_execption.txt";
#else
    constexpr auto kernelKboxSnapshot = "/sys/kbox/snapshot_clear";
#endif
    SmartFd fd(open(kernelKboxSnapshot, O_RDONLY));
    if (!fd) {
        DFXLOGE("open snapshot %{public}s failed %{public}d", kernelKboxSnapshot, errno);
        return "";
    }
    constexpr int buffLength = 1024;
    char buffer[buffLength] = {0};
    std::string snapshotCont;
    ssize_t ret = 0;
    do {
        ret = read(fd.GetFd(), buffer, buffLength - 1);
        if (ret > 0) {
            snapshotCont.append(buffer, static_cast<size_t>(ret));
        }
        if (ret < 0) {
            DFXLOGE("read snapshot failed %{public}d", errno);
        }
    } while (ret > 0);
    return snapshotCont;
}
}

bool ReadKernelSnapshotTask::InitSnapShotTask()
{
    constexpr int minIntervalInSecond = 3;
    constexpr auto kernelSnapshotInterval = "kernel_snapshot_check_interval";
    // Read snapshot interval log version is 1 minute, nolog version is 5 minutes.
    int32_t defaultIntervalInSecond = (OHOS::HiviewDFX::IsDfrBetaVersion() ? 60 : 300);
    int32_t configIntervalInSecond = system::GetIntParameter(kernelSnapshotInterval, defaultIntervalInSecond);
    int32_t intervalInSecond = std::max(configIntervalInSecond, minIntervalInSecond);
    auto interval = static_cast<uint64_t>(intervalInSecond) * US_PER_MS * MS_PER_S;
#ifdef FAULTLOGGERD_TEST
    auto testDelayTime = static_cast<uint64_t>(minIntervalInSecond) * US_PER_MS * MS_PER_S;
    return TimerTaskQueue::GetInstance().AddTask(std::make_unique<ReadKernelSnapshotTask>(interval), testDelayTime) > 0;
#else
    return TimerTaskQueue::GetInstance().AddTask(std::make_unique<ReadKernelSnapshotTask>(interval), interval) > 0;
#endif
}

ReadKernelSnapshotTask::ReadKernelSnapshotTask(uint64_t interval) : interval_(interval) {}

uint64_t ReadKernelSnapshotTask::Execute()
{
    const std::string snapshotCont = ReadKernelSnapshot();
    if (snapshotCont.empty()) {
        DFXLOGD("the snapshot file does not exist or is empty.");
        return interval_;
    }
    DFXLOGI("read snapshot begin with %{public}s", snapshotCont.substr(0, 25).c_str()); // 25 : only need 25
    constexpr auto kernelSnapshotLibraryName = "libkernel_snapshot.z.so";
    void* handle = dlopen(kernelSnapshotLibraryName, RTLD_LAZY);
    if (handle == nullptr) {
        DFXLOGE("failed dlopen library %{public}s for error %{public}d", kernelSnapshotLibraryName, errno);
        return interval_;
    }
    constexpr auto methodName = "ProcessKernelSnapShot";
    auto processKernelSnapShot = reinterpret_cast<void (*)(const std::string&)>(dlsym(handle, methodName));
    if (processKernelSnapShot == nullptr) {
        DFXLOGE("can't find method %{public}s in %{public}s, just exit", methodName, kernelSnapshotLibraryName);
        dlclose(handle);
        return interval_;
    }
    processKernelSnapShot(snapshotCont);
    dlclose(handle);
    return interval_;
}
}
}