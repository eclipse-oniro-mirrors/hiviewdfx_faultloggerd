/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <securec.h>

#include "fp_backtrace.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace HiviewDFX {

#define DEFAULT_MAX_FRAME_NUM 256
#define MIN_FRAME_NUM 2

class FpBacktraceTest : public testing::Test {};

/**
 * @tc.name: FpBacktraceTestTest001
 * @tc.desc: test get backtrace of current thread by fp
 * @tc.type: FUNC
 */
HWTEST_F(FpBacktraceTest, FpBacktraceTestTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "BacktraceLocalTest001: start.";
    auto fpBacktrace = FpBacktrace::CreateInstance();
#if is_ohos && !is_mingw
    ASSERT_NE(nullptr, fpBacktrace);
    void* pcArray[DEFAULT_MAX_FRAME_NUM]{0};
    int size = fpBacktrace->BacktraceFromFp(__builtin_frame_address(0), pcArray, DEFAULT_MAX_FRAME_NUM);
    ASSERT_GE(size, 0);
    for (int i = 0; i < size; i++) {
        ASSERT_NE(fpBacktrace->SymbolicAddress(pcArray[i]), nullptr);
    }
    for (int i = 0; i < size; i++) {
        ASSERT_NE(fpBacktrace->SymbolicAddress(pcArray[i]), nullptr);
    }
#else
    ASSERT_EQ(nullptr, fpBacktrace);
#endif
    GTEST_LOG_(INFO) << "BacktraceLocalTest001: end.";
}

/**
 * @tc.name: FpBacktraceTestTest002
 * @tc.desc: test get backtrace by a invalid fp.
 * @tc.type: FUNC
 */
HWTEST_F(FpBacktraceTest, FpBacktraceTestTest002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "BacktraceLocalTest002: start.";
    auto fpBacktrace = FpBacktrace::CreateInstance();
#if is_ohos && !is_mingw && __aarch64__
    ASSERT_NE(nullptr, fpBacktrace);
    void* pcArray[DEFAULT_MAX_FRAME_NUM]{0};
    uint64_t address = std::numeric_limits<uint64_t>::max();
    int size = fpBacktrace->BacktraceFromFp(reinterpret_cast<void*>(address), pcArray, DEFAULT_MAX_FRAME_NUM);
    ASSERT_EQ(size, 0);
#else
    ASSERT_EQ(nullptr, fpBacktrace);
#endif
    GTEST_LOG_(INFO) << "BacktraceLocalTest002: end.";
}
} // namespace HiviewDFX
} // namepsace OHOS
