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
#ifndef DFX_FAULTLOGGERD_CLIENT_H
#define DFX_FAULTLOGGERD_CLIENT_H

#include <inttypes.h>
#include "dfx_socket_request.h"

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @brief request file descriptor
 * @param type type of resqust
 * @return if succeed return file descriptor, otherwise return -1
*/
int32_t RequestFileDescriptor(int32_t type);

/**
 * @brief request pipe file descriptor
 * @param pid process id of request pipe
 * @param pipeType type of request about pipe
 * @param pipeFd pipeFd[0] to transfer call stack message and
 *               pipeFd[1] to transfer backtrace result
 * @return if succeed return 0, otherwise return -1
*/
int RequestPipeFd(int32_t pid, int32_t pipeType, int (&pipeFd)[2]);

/**
 * @brief request delete file descriptor
 * @param pid process id of request pipe
 * @return if succeed return 0, otherwise return -1
*/
int32_t RequestDelPipeFd(int32_t pid);

/**
 * @brief request file descriptor
 * @param request struct of request information
 * @return if succeed return file descriptor, otherwise return -1
*/
int RequestFileDescriptorEx(struct FaultLoggerdRequest *request);

/**
 * @brief request dump stack about process
 * @param pid process id
 * @param tid thread id, if equal 0 means dump all the threads in a process.
 * @param pipeReadFd if pass sdkdump, will get pipeReadFd[0] to read call stack message and
 *                   pipeReadFd[1] to read backtrace result
 * @param isJson if set true, will get json format result, else get string result
 * @return if succeed return 0 , otherwise return -1
*/
int RequestSdkDump(int32_t pid, int32_t tid, int (&pipeReadFd)[2],
                   bool isjson = false, int timeout = 10000); // 10000 : dump timeout ms

/**
 * @brief report sdk dump result to faultloggerd for stats collection
 * @param request dump request result
 * @return if succeed return 0 , otherwise return -1
*/
int ReportDumpStats(struct FaultLoggerdStatsRequest *request);
#ifdef __cplusplus
}
#endif
#endif
