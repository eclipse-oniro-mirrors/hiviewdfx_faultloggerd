/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include <dlfcn.h>

#include "async_stack.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
namespace HiviewDFX {
class AsyncStackUnsetCallbackTest : public testing::Test {};

/**
 * @tc.name: AsyncStackUnsetCallbackTest001
 * @tc.desc: test chained mode with no engine hook symbols (all dlsym miss branches)
 * @tc.type: FUNC
 */
HWTEST_F(AsyncStackUnsetCallbackTest, AsyncStackUnsetCallbackTest001, TestSize.Level2)
{
#if defined(__aarch64__)
    // This binary links neither libuv nor fake hook symbols, so every optional
    // hook dlsym misses and the unset-callback path of SetChainedModeCallbacks runs.
    ASSERT_EQ(dlsym(RTLD_DEFAULT, "EventSetReleaseAsyncStackFunc"), nullptr);
    ASSERT_EQ(dlsym(RTLD_DEFAULT, "LibuvSetReleaseAsyncContextFunc"), nullptr);
    ASSERT_EQ(dlsym(RTLD_DEFAULT, "LibuvSetAsyncStackFunc"), nullptr);
    ASSERT_EQ(dlsym(RTLD_DEFAULT, "FFRTSetAsyncStackReleaseFunc"), nullptr);

    DfxAsyncMode prev = SetAsyncStackMode(MODE_CHAINED_STACKTRACE);
    ASSERT_EQ(prev, MODE_LAST_STACKTRACE);
    ASSERT_EQ(GetAsyncStackMode(), MODE_CHAINED_STACKTRACE);

    prev = SetAsyncStackMode(MODE_LAST_STACKTRACE);
    ASSERT_EQ(prev, MODE_CHAINED_STACKTRACE);
    ASSERT_EQ(GetAsyncStackMode(), MODE_LAST_STACKTRACE);
#endif
}
} // namespace HiviewDFX
} // namespace OHOS
