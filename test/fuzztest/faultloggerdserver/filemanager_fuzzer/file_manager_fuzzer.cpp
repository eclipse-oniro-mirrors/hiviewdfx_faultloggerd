/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#define FUZZ_PROJECT_NAME "filemanager_fuzzer"

#include "faultloggerd_test.h"
#include "smart_fd.h"
#include "temp_file_manager.h"

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FaultLoggerdTestServer::GetInstance();
    if (data == nullptr || size < sizeof (FaultLoggerdRequest)) {
        return 0;
    }
    const FaultLoggerdRequest& requestData = *reinterpret_cast<const FaultLoggerdRequest*>(data);
    if (requestData.head.clientType & 1) {
        OHOS::HiviewDFX::SmartFd socketFd(OHOS::HiviewDFX::TempFileManager::CreateFileDescriptor(
            FaultLoggerType::CPP_CRASH, requestData.pid, requestData.tid, requestData.time));
    } else {
        OHOS::HiviewDFX::SmartFd socketFd(OHOS::HiviewDFX::TempFileManager::CreateFileDescriptor(
            FaultLoggerType::JS_RAW_SNAPSHOT, requestData.pid, requestData.tid, requestData.time));
    }
    return 0;
}
