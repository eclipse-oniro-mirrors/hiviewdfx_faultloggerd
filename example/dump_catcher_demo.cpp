/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "dump_catcher_demo.h"

#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <iostream>
#include <string>
#include <unistd.h>
#include "dfx_define.h"
#include "dfx_dump_catcher.h"
#include "dfx_json_formatter.h"
#include "elapsed_time.h"

static NOINLINE int TestFuncDump(int32_t pid, int32_t tid, bool isJson)
{
    OHOS::HiviewDFX::DfxDumpCatcher dumplog;
    std::string msg = "";
#ifdef is_ohos_lite
    isJson = false;
#endif
    OHOS::HiviewDFX::ElapsedTime counter;
    constexpr size_t defaultMaxFrameNum = 256;
    bool ret = dumplog.DumpCatch(pid, tid, msg, defaultMaxFrameNum, isJson);
    time_t elapsed1 = counter.Elapsed();
    if (ret) {
        std::cout << msg << std::endl;
        if (isJson) {
            std::string outStr = "";
            OHOS::HiviewDFX::DfxJsonFormatter::FormatJsonStack(msg, outStr);
            std::cout << outStr << std::endl;
        }
    }
    time_t elapsed2 = counter.Elapsed();
    std::cout << "elapsed1: " << elapsed1 << " ,elapsed2: " << elapsed2 << std::endl;
    return ret;
}

static NOINLINE int TestFunc10(void)
{
    return TestFuncDump(getpid(), gettid(), false);
}

// auto gen function
GEN_TEST_FUNCTION(9, 10)

static bool ParseParameters(int argc, char *argv[], int32_t &pid, int32_t &tid)
{
    switch (argc) {
        case 3:
            if (!strcmp("-p", argv[1])) {
                pid = atoi(argv[2]);
                return true;
            }
            if (!strcmp("-t", argv[1])) {
                pid = getpid();
                tid = atoi(argv[2]);
                return true;
            }
            break;
        case 5:
            if (!strcmp("-p", argv[1])) {
                pid = atoi(argv[2]);

                if (!strcmp("-t", argv[3])) {
                    tid = atoi(argv[4]);
                    return true;
                }
            } else if (!strcmp("-t", argv[1])) {
                tid = atoi(argv[2]);

                if (!strcmp("-p", argv[3])) {
                    pid = atoi(argv[4]);
                    return true;
                }
            }
            break;
        default:
            break;
    }
    return false;
}

int main(int argc, char *argv[])
{
    int32_t pid = 0;
    int32_t tid = 0;
    if (ParseParameters(argc, argv, pid, tid)) {
        TestFuncDump(pid, tid, true);
    } else {
        TestFunc0();
    }

    return 0;
}