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

#include <gtest/gtest.h>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include "dfx_frame.h"
#include "dfx_frame_formatter.h"
#include "dfx_map.h"
#include "unwinder.h"

using namespace OHOS::HiviewDFX;
using namespace testing::ext;

namespace OHOS {
namespace HiviewDFX {
class DfxFrameFormatterTest : public testing::Test {};

/**
 * @tc.name: DfxFrameFormatterTest001
 * @tc.desc: test GetFrameStr with map name, origin so name, func name and build id
 * @tc.type: FUNC
 */
HWTEST_F(DfxFrameFormatterTest, DfxFrameFormatterTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxFrameFormatterTest001: start.";
    DfxFrame frame;
    frame.index = 0;
    frame.pc = 0x1234;
    frame.relPc = 0x2345;
    frame.mapName = "/system/lib/libunwinder.z.so";
    frame.originSoName = "libunwinder_origin.so";
    frame.funcName = "Unwind";
    frame.funcOffset = 0x20;
    frame.buildId = "0123456789abcdef";

    std::string data = DfxFrameFormatter::GetFrameStr(frame);
    // the pc field width follows the arch: 16 digits on lp64, 8 digits on 32 bit
#ifdef __LP64__
    EXPECT_NE(data.find("pc 0000000000002345"), std::string::npos);
#else
    EXPECT_NE(data.find("pc 00002345"), std::string::npos);
#endif
    EXPECT_NE(data.find("/system/lib/libunwinder.z.so:libunwinder_origin.so"), std::string::npos);
    EXPECT_NE(data.find("(Unwind+32)"), std::string::npos);
    EXPECT_NE(data.find("(0123456789abcdef)"), std::string::npos);
    EXPECT_EQ(data.find("[Unknown]"), std::string::npos);

    std::string same = DfxFrameFormatter::GetFrameStr(frame, false);
    EXPECT_EQ(data, same);
    GTEST_LOG_(INFO) << "DfxFrameFormatterTest001: end.";
}

/**
 * @tc.name: DfxFrameFormatterTest002
 * @tc.desc: test GetFrameStr prints [Unknown] without a map in both modes
 * @tc.type: FUNC
 */
HWTEST_F(DfxFrameFormatterTest, DfxFrameFormatterTest002, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxFrameFormatterTest002: start.";
    DfxFrame frame;
    frame.index = 1;
    frame.pc = 0x1000;
    EXPECT_NE(DfxFrameFormatter::GetFrameStr(frame).find(" [Unknown]"), std::string::npos);
    EXPECT_NE(DfxFrameFormatter::GetFrameStr(frame, true).find(" [Unknown]"), std::string::npos);
    GTEST_LOG_(INFO) << "DfxFrameFormatterTest002: end.";
}

/**
 * @tc.name: DfxFrameFormatterTest003
 * @tc.desc: test the container anonymous map branch
 * @tc.type: FUNC
 */
HWTEST_F(DfxFrameFormatterTest, DfxFrameFormatterTest003, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxFrameFormatterTest003: start.";
    DfxFrame frame;
    frame.index = 2;
    frame.pc = 0x2000;
    frame.map = std::make_shared<DfxMap>();
    frame.map->begin = 0x7000000;

    std::string container = DfxFrameFormatter::GetFrameStr(frame, true);
    EXPECT_NE(container.find(" <anonymous:7000000>"), std::string::npos);
    EXPECT_EQ(container.find("[Unknown]"), std::string::npos);

    std::string plain = DfxFrameFormatter::GetFrameStr(frame, false);
    EXPECT_NE(plain.find(" [Unknown]"), std::string::npos);
    EXPECT_EQ(plain.find("<anonymous"), std::string::npos);
    GTEST_LOG_(INFO) << "DfxFrameFormatterTest003: end.";
}

/**
 * @tc.name: DfxFrameFormatterTest004
 * @tc.desc: test the container elf offset branch
 * @tc.type: FUNC
 */
HWTEST_F(DfxFrameFormatterTest, DfxFrameFormatterTest004, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxFrameFormatterTest004: start.";
    DfxFrame frame;
    frame.index = 3;
    frame.pc = 0x3000;
    frame.map = std::make_shared<DfxMap>();
    frame.map->begin = 0x7100000;
    frame.map->elfOffset = 0x400000;

    std::string container = DfxFrameFormatter::GetFrameStr(frame, true);
    EXPECT_NE(container.find(" (offset 0x400000)"), std::string::npos);

    std::string plain = DfxFrameFormatter::GetFrameStr(frame, false);
    EXPECT_EQ(plain.find("(offset"), std::string::npos);

    frame.map->elfOffset = 0;
    std::string noOffset = DfxFrameFormatter::GetFrameStr(frame, true);
    EXPECT_EQ(noOffset.find("(offset"), std::string::npos);
    GTEST_LOG_(INFO) << "DfxFrameFormatterTest004: end.";
}

/**
 * @tc.name: DfxFrameFormatterTest005
 * @tc.desc: test map names are unformatted in frame output
 * @tc.type: FUNC
 */
HWTEST_F(DfxFrameFormatterTest, DfxFrameFormatterTest005, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxFrameFormatterTest005: start.";
    DfxFrame frame;
    frame.index = 4;
    frame.pc = 0x4000;
    frame.mapName = "/proc/1234/root/data/storage/el1/bundle/libs/arm64/libtest.so";
    std::string data = DfxFrameFormatter::GetFrameStr(frame);
    EXPECT_NE(data.find("/data/storage/el1/bundle/libs/arm64/libtest.so"), std::string::npos);
    EXPECT_EQ(data.find("/proc/1234/root"), std::string::npos);
    GTEST_LOG_(INFO) << "DfxFrameFormatterTest005: end.";
}

/**
 * @tc.name: DfxFrameFormatterTest006
 * @tc.desc: test GetFramesStr joins frames and matches the Unwinder overload
 * @tc.type: FUNC
 */
HWTEST_F(DfxFrameFormatterTest, DfxFrameFormatterTest006, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxFrameFormatterTest006: start.";
    std::vector<DfxFrame> frames;
    DfxFrame first;
    first.index = 0;
    first.pc = 0x1000;
    first.map = std::make_shared<DfxMap>();
    first.map->begin = 0x7000000;
    DfxFrame second;
    second.index = 1;
    second.pc = 0x2000;
    second.map = std::make_shared<DfxMap>();
    second.map->begin = 0x7100000;
    second.map->elfOffset = 0x400000;
    frames.push_back(first);
    frames.push_back(second);

    std::string joined = DfxFrameFormatter::GetFramesStr(frames, true);
    EXPECT_NE(joined.find("<anonymous:7000000>"), std::string::npos);
    EXPECT_NE(joined.find("(offset 0x400000)"), std::string::npos);

    std::string unwinderStr = Unwinder::GetFramesStr(frames, true);
    EXPECT_EQ(joined, unwinderStr);
    EXPECT_NE(Unwinder::GetFramesStr(frames).find(" [Unknown]"), std::string::npos);
    GTEST_LOG_(INFO) << "DfxFrameFormatterTest006: end.";
}

/**
 * @tc.name: DfxFrameFormatterTest007
 * @tc.desc: test GetFrameStr with a null frame pointer
 * @tc.type: FUNC
 */
HWTEST_F(DfxFrameFormatterTest, DfxFrameFormatterTest007, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "DfxFrameFormatterTest007: start.";
    std::shared_ptr<DfxFrame> nullFrame;
    EXPECT_EQ(DfxFrameFormatter::GetFrameStr(nullFrame), "");
    GTEST_LOG_(INFO) << "DfxFrameFormatterTest007: end.";
}
} // namespace HiviewDFX
} // namespace OHOS
