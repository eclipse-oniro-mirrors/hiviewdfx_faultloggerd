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

#include <gtest/gtest.h>
#include <memory>
#include "dfx_jit_debug.h"
#include "dfx_maps.h"
#include "dfx_memory.h"

using namespace OHOS::HiviewDFX;
using namespace testing::ext;

namespace OHOS {
namespace HiviewDFX {
class DfxJitDebugTest : public testing::Test {};

HWTEST_F(DfxJitDebugTest, DfxJitDebugTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest001: start.";
    DfxJitDebug jitDebug;
    jitDebug.Clear();
    EXPECT_FALSE(jitDebug.HasJitDebugInfo());
    GTEST_LOG_(INFO) << "DfxJitDebugTest001: end.";
}

HWTEST_F(DfxJitDebugTest, DfxJitDebugTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest002: start.";
    DfxJitDebug jitDebug;
    jitDebug.Clear();
    
    auto maps = DfxMaps::Create();
    auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_LOCAL);
    
    jitDebug.SetMaps(maps);
    jitDebug.SetMemory(memory);
    jitDebug.SetPid(getpid());
    jitDebug.SetArch(ARCH_ARM64);
    
    JitSymbolInfo info;
    uint64_t pc = 0x0;
    bool result = jitDebug.GetJitSymbolInfo(pc, info);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "DfxJitDebugTest002: end.";
}

HWTEST_F(DfxJitDebugTest, DfxJitDebugTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest003: start.";
    DfxJitDebug jitDebug;
    jitDebug.Clear();
    
    auto maps = DfxMaps::Create();
    auto memory = std::make_shared<DfxMemory>(UNWIND_TYPE_LOCAL);
    
    jitDebug.SetMaps(nullptr);
    jitDebug.SetMemory(nullptr);
    jitDebug.SetPid(0);
    jitDebug.SetArch(ARCH_UNKNOWN);
    
    JitSymbolInfo info;
    bool result = jitDebug.ForEachJitElf(0, [&info](const JitSymbolInfo& jitInfo) {
        info = jitInfo;
        return true;
    });
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "DfxJitDebugTest003: end.";
}

HWTEST_F(DfxJitDebugTest, DfxJitDebugTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest004: test ForEachJitElf with nullptr callback.";
    DfxJitDebug jitDebug;
    jitDebug.Clear();
    
    bool result = jitDebug.ForEachJitElf(0, nullptr);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "DfxJitDebugTest004: end.";
}

HWTEST_F(DfxJitDebugTest, DfxJitDebugTest005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest005: test instances are independent and Clear resets state.";
    DfxJitDebug jitDebug;
    DfxJitDebug other;
    jitDebug.Clear();
    EXPECT_NE(&jitDebug, &other);
    EXPECT_FALSE(jitDebug.HasJitDebugInfo());
    EXPECT_FALSE(other.HasJitDebugInfo());
    GTEST_LOG_(INFO) << "DfxJitDebugTest005: end.";
}

HWTEST_F(DfxJitDebugTest, DfxJitDebugTest006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest006: test FindJitElf returns false with null inputs.";
    DfxJitDebug jitDebug;
    jitDebug.Clear();
    
    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    bool result = jitDebug.FindJitElf(0, elf, loadBias);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "DfxJitDebugTest006: end.";
}

HWTEST_F(DfxJitDebugTest, DfxJitDebugTest007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest007: test GetJitSymbolInfo returns false with zero pc.";
    DfxJitDebug jitDebug;
    jitDebug.Clear();
    
    JitSymbolInfo info;
    bool result = jitDebug.GetJitSymbolInfo(0, info);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "DfxJitDebugTest007: end.";
}

HWTEST_F(DfxJitDebugTest, DfxJitDebugTest008, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest008: test JitUID comparison operator.";
    JitUID uid1 = {0x1000, 1};
    JitUID uid2 = {0x1000, 2};
    JitUID uid3 = {0x2000, 1};
    
    EXPECT_TRUE(uid1 < uid2);
    EXPECT_TRUE(uid1 < uid3);
    EXPECT_TRUE(uid2 < uid3);
    EXPECT_FALSE(uid2 < uid1);
    GTEST_LOG_(INFO) << "DfxJitDebugTest008: end.";
}
} // namespace HiviewDFX
} // namespace OHOS