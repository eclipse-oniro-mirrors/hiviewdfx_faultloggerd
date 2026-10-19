/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include "binder_record.h"

#include <fstream>
#include <securec.h>

#include "dfx_log.h"
#include "faultloggerd_client.h"
#include "string_printf.h"

#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxBinderRecord"

namespace OHOS {
namespace HiviewDFX {
bool ParseBinderRecord(const std::string& line, BinderRecord& binderRecord)
{
    auto nsPidStart = line.find("ns:");
    if (nsPidStart == std::string::npos) {
        return false;
    }
    int nsFromPid = -1;
    int nsFromTid = -1;
    constexpr auto binderPidPairParamsSize = 2;
    if (sscanf_s(line.c_str() + nsPidStart, "ns:%d:%d", &nsFromPid, &nsFromTid) != binderPidPairParamsSize) {
        return false;
    }
    if (nsFromPid == -1 || nsFromTid == -1) {
        return false;
    }
    size_t index = 0;
    int fromPid = -1;
    int fromTid = -1;
    binderRecord.isSync = line.find("async") != 0;
    for (index = 0; index < line.size(); index++) {
        if (isdigit(static_cast<unsigned char>(line.at(index)))) {
            break;
        }
    }
    if (sscanf_s(line.c_str() + index, "%d:%d", &fromPid, &fromTid) != binderPidPairParamsSize) {
        return false;
    }
    if (fromPid == -1 || fromTid == -1) {
        return false;
    }
    ProcStatusInfo procInfo{};
    int32_t nsRet = RequestProcStatusInfo(fromPid, &procInfo);
    if (nsRet != ResponseCode::REQUEST_SUCCESS) {
        DFXLOGW("RequestProcStatusInfo for callerPid %{public}d failed, ret: %{public}d",
            fromPid, nsRet);
    }
    binderRecord.pid = fromPid;
    binderRecord.nsPid = nsFromPid;
    binderRecord.tid = fromTid;
    binderRecord.nsTid = nsFromTid;
    binderRecord.cmdLine = procInfo.name;
    return true;
}

std::vector<BinderRecord> ParseSyncBinderProcInfo(pid_t pid, pid_t tid)
{
    std::vector<BinderRecord> records;
    constexpr auto transactionProcPath = "/proc/transaction_proc";
    errno = 0;
    std::ifstream binderFile(transactionProcPath);
    if (!binderFile.is_open()) {
        DFXLOGE("Failed to open binder proc file %{public}s, errno:%{public}d", transactionProcPath, errno);
        return records;
    }
    std::string feature = StringPrintf("to %d:%d code", pid, tid);
    std::string line;
    while (std::getline(binderFile, line)) {
        if (line.find("pid") == 0) {
            break;
        }
        if (line.find(feature) == std::string::npos) {
            continue;
        }
        BinderRecord record;
        if (ParseBinderRecord(line, record)) {
            records.emplace_back(record);
        }
    }
    return records;
}

BinderRecord ParseAsyncBinderProcInfo(pid_t callerPid)
{
    BinderRecord record{};
    if (callerPid < 0) {
        return record;
    }

    ProcStatusInfo procInfo{};
    int32_t nsRet = RequestProcStatusInfo(callerPid, &procInfo);
    if (nsRet != ResponseCode::REQUEST_SUCCESS) {
        DFXLOGW("RequestProcStatusInfo for callerPid %{public}d failed, ret: %{public}d",
            callerPid, nsRet);
        return record;
    }
    record.pid = callerPid;
    record.nsPid = procInfo.nsPid;
    record.cmdLine = procInfo.name;
    return record;
}
}
}
