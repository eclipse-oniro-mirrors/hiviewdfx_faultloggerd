/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <string>
#include <unistd.h>
#include <vector>

#include "dfx_buffer_writer.h"
#include "dfx_cutil.h"
#include "dfx_define.h"
#include "dfx_test_util.h"
#include "dfx_util.h"
#include "decorative_dump_info.h"

using namespace OHOS::HiviewDFX;
using namespace testing::ext;
using namespace std;

namespace OHOS {
namespace HiviewDFX {
class OpenFilesTest : public testing::Test {
public:
    static void SetUpTestCase(void);
    static void TearDownTestCase(void) {}
    void SetUp();
    void TearDown() {}
    static int WriteLogFunc(int32_t fd, const char *buf, size_t len);
    static std::string result;
};
} // namespace HiviewDFX
} // namespace OHOS

std::string OpenFilesTest::result = "";

void OpenFilesTest::SetUpTestCase(void)
{
    result = "";
}

void OpenFilesTest::SetUp(void)
{
    DfxBufferWriter::GetInstance().SetWriteFunc(OpenFilesTest::WriteLogFunc);
}

int OpenFilesTest::WriteLogFunc(int32_t fd, const char *buf, size_t len)
{
    OpenFilesTest::result.append(std::string(buf, len));
    return 0;
}
 
namespace {
/**
 * @tc.name: OpenFilesTest001
 * @tc.desc: test print open files
 * @tc.type: FUNC
 */
HWTEST_F(OpenFilesTest, OpenFilesTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "MapsTest001: start.";
    pid_t pid = fork();
    if (pid < 0) {
        GTEST_LOG_(ERROR) << "Failed to fork new test process.";
    } else if (pid == 0) {
        sleep(3); // 3 : sleep 3 seconds
        exit(0);
    }
    pid_t tid = pid;
    pid_t nsPid = pid;
    ProcessDumpRequest request = {
        .type = ProcessDumpType::DUMP_TYPE_CPP_CRASH,
        .tid = tid,
        .pid = pid,
        .nsPid = pid,
        .fdTableAddr = (uint64_t)fdsan_get_fd_table(),
    };
    DfxProcess process;
    process.InitProcessInfo(pid, nsPid, getuid(), "");
    Unwinder unwinder(pid, nsPid, request.type == ProcessDumpType::DUMP_TYPE_CPP_CRASH);
    OpenFiles openFiles;
    openFiles.Print(process, request, unwinder);
    std::vector<std::string> keyWords = {
        "OpenFiles:",
        "0->",
        "1->",
        "2->",
    };
    for (const std::string& keyWord : keyWords) {
        ASSERT_TRUE(CheckContent(result, keyWord, true));
    }
    process.Detach();
    GTEST_LOG_(INFO) << "OpenFilesTest001: end.";
}
}
 