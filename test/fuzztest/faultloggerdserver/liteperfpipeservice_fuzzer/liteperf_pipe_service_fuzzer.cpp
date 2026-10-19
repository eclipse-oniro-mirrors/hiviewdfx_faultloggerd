/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#define FUZZ_PROJECT_NAME "liteperfpipeservice_fuzzer"

#include <unistd.h>

#include <vector>

#include "dfx_define.h"
#include "faultloggerd_test.h"
#include "faultloggerd_test_server.h"

namespace {
using OHOS::HiviewDFX::SmartFd;
using OHOS::HiviewDFX::SocketFdData;

/*
 * A successful DELETE request only replies a response code without any fd,
 * while the test socket has no receive timeout, so fd receiving is enabled
 * only for READ/WRITE requests to avoid blocking in recvmsg.
 */
void SendLitePerfRequest(const LitePerfFdRequestData& requestData, bool recvFds)
{
    if (!recvFds) {
        SendRequestToServer({&requestData, sizeof(requestData)});
        return;
    }
    int32_t fds[PIPE_NUM_SZ] = {-1, -1};
    SocketFdData fdPair = {fds, PIPE_NUM_SZ};
    SendRequestToServer({&requestData, sizeof(requestData)}, &fdPair);
    SmartFd {fds[PIPE_BUF_INDEX]};
    SmartFd {fds[PIPE_RES_INDEX]};
}

/*
 * The request length mismatches sizeof(LitePerfFdRequestData), which covers
 * the INVALID_REQUEST_DATA branch of FaultLoggerService::OnReceiveMsg.
 */
void SendMismatchedSizeRequest(const uint8_t* data, size_t size)
{
    std::vector<uint8_t> buf(data, data + size);
    auto head = reinterpret_cast<RequestDataHead*>(buf.data());
    head->clientType = FaultLoggerClientType::PIPE_FD_LITEPERF_CLIENT;
    head->clientPid = getpid();
    SendRequestToServer({buf.data(), static_cast<uint32_t>(buf.size())});
}
}

/* Fuzzer entry point */
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    FaultLoggerdTestServer::GetInstance();
    if (data == nullptr || size < sizeof(RequestDataHead)) {
        return 0;
    }
    if (size < sizeof(LitePerfFdRequestData)) {
        SendMismatchedSizeRequest(data, size);
        return 0;
    }
    LitePerfFdRequestData requestData = *reinterpret_cast<const LitePerfFdRequestData*>(data);
    FillRequestHeadData(requestData.head, FaultLoggerClientType::PIPE_FD_LITEPERF_CLIENT);
    /*
     * The raw fuzzed pipeType/uid covers the Filter reject branches
     * (invalid pipeType, uid mismatched with the peer credential).
     */
    SendLitePerfRequest(requestData, false);

    /*
     * Valid requests passing Filter, driving OnRequest through every pipeType
     * branch in a fixed order; timeout/checkLimit stay fuzzed to explore
     * negative, oversized and normal values of the READ path.
     */
    LitePerfFdRequestData validRequest = requestData;
    validRequest.uid = getuid(); // server checks it against the peer credential
    validRequest.pipeType = FaultLoggerPipeType::PIPE_FD_DELETE;
    SendLitePerfRequest(validRequest, false); // DELETE branch, also clears stale state
    validRequest.pipeType = FaultLoggerPipeType::PIPE_FD_WRITE;
    SendLitePerfRequest(validRequest, true); // WRITE without pipe pair: ABNORMAL_SERVICE
    validRequest.pipeType = FaultLoggerPipeType::PIPE_FD_READ;
    SendLitePerfRequest(validRequest, true); // READ: create pipe pair or hit perf limits
    SendLitePerfRequest(validRequest, true); // repeated READ: SDK_DUMP_REPEAT
    validRequest.pipeType = FaultLoggerPipeType::PIPE_FD_WRITE;
    SendLitePerfRequest(validRequest, true); // WRITE with pipe pair: success with fds
    validRequest.pipeType = FaultLoggerPipeType::PIPE_FD_DELETE;
    SendLitePerfRequest(validRequest, false); // clean up pipe pair for the next iteration
    return 0;
}
