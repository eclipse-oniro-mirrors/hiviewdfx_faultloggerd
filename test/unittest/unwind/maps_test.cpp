/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "dfx_elf.h"
#include "dfx_maps.h"
#include <gtest/gtest.h>
#include <memory>
#include <sys/types.h>

using namespace OHOS::HiviewDFX;
using namespace std;
using namespace testing::ext;

namespace OHOS {
namespace HiviewDFX {
namespace {
const string INVALID_MAP_NAME = "/system/lib64/init/libinit_context111.z.so";
#ifdef __arm__
const string MAPS_FILE = "/data/test/resource/testdata/testmaps_32";
const string VALID_MAP_NAME = "/system/lib/init/libinit_context.z.so";
const string VALID_MAP_ITEM = "f6d83000-f6d84000 r--p 00001000 b3:07 1892 /system/lib/init/libinit_context.z.so";
const string INVALID_MAP_ITEM = "f6d83000-f6d84000 r--p 00001000 b3:07 1892 /system/lib/init/libinit_context111.z.so";
#else
const string MAPS_FILE = "/data/test/resource/testdata/testmaps_64";
const string VALID_MAP_NAME = "/system/lib64/init/libinit_context.z.so";
const string VALID_MAP_ITEM = "7f0ab40000-7f0ab41000 r--p 00000000 b3:07 1882 /system/lib64/init/libinit_context.z.so";
const string INVALID_MAP_ITEM = "7f0ab40000-7f0ab41000 r--p 00000000 b3:07 1882 \
    /system/lib64/init/libinit_context111.z.so";
#endif
}

class MapsTest : public testing::Test {
public:
    static void SetUpTestCase(void) {}
    static void TearDownTestCase(void) {}
    void SetUp() { maps_ = DfxMaps::Create(getpid(), MAPS_FILE); }
    void TearDown() {}

public:
    std::shared_ptr<DfxMaps> maps_;
};

namespace {

/**
 * @tc.name: FindMapByAddrTest001
 * @tc.desc: test FindMapByAddr functions
 * @tc.type: FUNC
 */
HWTEST_F(MapsTest, FindMapByAddrTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FindMapByAddrTest001: start.";
    maps_->Sort(true);
#ifdef __arm__
    uintptr_t validAddr = 0xf6d80000;
#else
    uintptr_t validAddr = 0x7f8b8f3001;
#endif
    const uintptr_t invalidAddr = 0xffffffff;
    std::shared_ptr<DfxMap> map = nullptr;
    EXPECT_EQ(true, maps_->FindMapByAddr(validAddr, map));
    EXPECT_EQ(false, maps_->FindMapByAddr(invalidAddr, map));
    GTEST_LOG_(INFO) << "FindMapByAddrTest001: end.";
}

/**
 * @tc.name: FindMapByFileInfoTest001
 * @tc.desc: test FindMapByFileInfo functions
 * @tc.type: FUNC
 */
HWTEST_F(MapsTest, FindMapByFileInfoTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FindMapByFileInfoTest001: start.";
    std::shared_ptr<DfxMap> map = nullptr;
    EXPECT_EQ(true, maps_->FindMapByFileInfo(VALID_MAP_NAME, 0, map));
    EXPECT_EQ(false, maps_->FindMapByFileInfo(INVALID_MAP_NAME, 0, map));
    const uint64_t invalidOffset = 0xffffffff;
    EXPECT_EQ(false, maps_->FindMapByFileInfo(VALID_MAP_NAME, invalidOffset, map));
    EXPECT_EQ(false, maps_->FindMapByFileInfo(INVALID_MAP_NAME, invalidOffset, map));
    GTEST_LOG_(INFO) << "FindMapByFileInfoTest001: end.";
}

/**
 * @tc.name: FindMapsByNameTest001
 * @tc.desc: test FindMapsByName functions
 * @tc.type: FUNC
 */
HWTEST_F(MapsTest, FindMapsByNameTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "FindMapsByNameTest001: start.";
    std::vector<std::shared_ptr<DfxMap>> mapsV;
    EXPECT_EQ(true, maps_->FindMapsByName(VALID_MAP_NAME, mapsV));
    mapsV.clear();
    EXPECT_EQ(false, maps_->FindMapsByName(INVALID_MAP_NAME, mapsV));
    GTEST_LOG_(INFO) << "FindMapsByNameTest001: end.";
}

/**
 * @tc.name: IsArkNameTest001
 * @tc.desc: test IsArkExecutable functions
 * @tc.type: FUNC
 */
HWTEST_F(MapsTest, IsArkNameTest001, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "IsArkNameTest001: start.";
    std::shared_ptr<DfxMap> map = nullptr;
    map = std::make_shared<DfxMap>(0, 0, 0, "1", "anon:ArkTS Code");
    EXPECT_EQ(false, map->IsArkExecutable());
    map = std::make_shared<DfxMap>(0, 0, 0, "1", "/dev/zero");
    EXPECT_EQ(false, map->IsArkExecutable());
    map = std::make_shared<DfxMap>(0, 0, 0, 4, "[anon:ArkTS Code]");
    EXPECT_EQ(true, map->IsArkExecutable());
    GTEST_LOG_(INFO) << "IsArkNameTest001: end.";
}

/**
 * @tc.name: GetRelPcTest
 * @tc.desc: test getRelPc no elf
 * @tc.type: FUNC
 */
HWTEST_F(MapsTest, GetRelPcTest, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "GetRelPcTest: start.";
#ifdef __arm__
    uint64_t pc = 0xf6d83001;
    const uint64_t invalidOffset = 0x1001;
#else
    uint64_t pc = 0x7f0ab40016;
    const uint64_t invalidOffset = 0x16;
#endif
    shared_ptr<DfxMap> map = DfxMap::Create(INVALID_MAP_ITEM, sizeof(INVALID_MAP_ITEM));
    EXPECT_EQ(true, ((map->GetElf() == nullptr) && (map->GetRelPc(pc) == invalidOffset)));
    GTEST_LOG_(INFO) << "GetRelPcTest: end.";
}

/**
 * @tc.name: ToStringTest
 * @tc.desc: test ToString
 * @tc.type: FUNC
 */
HWTEST_F(MapsTest, ToStringTest, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "ToStringTest: start.";
    shared_ptr<DfxMap> map = DfxMap::Create(VALID_MAP_ITEM, sizeof(VALID_MAP_ITEM));
    GTEST_LOG_(INFO) << map->ToString();
    EXPECT_EQ(true, sizeof(map->ToString()) != 0);
    GTEST_LOG_(INFO) << "ToStringTest: end.";
}

/**
 * @tc.name: CreateMapsTest
 * @tc.desc: test create maps by pid
 * @tc.type: FUNC
 */
HWTEST_F(MapsTest, CreateMapsTest, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "CreateMapsTest: start.";
    shared_ptr<DfxMaps> maps = DfxMaps::Create(getpid());
    EXPECT_NE(maps, nullptr);
    GTEST_LOG_(INFO) << "CreateMapsTest: end.";
}

/**
 * @tc.name: GetStackRangeTest
 * @tc.desc: test GetStackRange
 * @tc.type: FUNC
 */
HWTEST_F(MapsTest, GetStackRangeTest, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "GetStackRangeTest: start.";
    uintptr_t bottom, top;
    ASSERT_TRUE(maps_->GetStackRange(bottom, top));
#ifdef __arm__
    EXPECT_EQ(bottom, 0xff860000);
    EXPECT_EQ(top, 0xff881000);
#else
    EXPECT_EQ(bottom, 0x7fe37db000);
    EXPECT_EQ(top, 0x7fe37fc000);
#endif
    GTEST_LOG_(INFO) << "GetStackRangeTest: end.";
}

/**
 * @tc.name: IsArkExecutedMapTest
 * @tc.desc: test IsArkExecutedMap
 * @tc.type: FUNC
 */
HWTEST_F(MapsTest, IsArkExecutedMapTest, TestSize.Level2)
{
    GTEST_LOG_(INFO) << "IsArkExecutedMapTest: start.";
    uintptr_t addr;
#ifdef __arm__
    addr = 0xffff2001;
#else
    addr = 0x7fe37fd001;
#endif
    ASSERT_TRUE(maps_->IsArkExecutedMap(addr));
#ifdef __arm__
    addr = 0xffff1001;
#else
    addr = 0x7fe37fc001;
#endif
    ASSERT_FALSE(maps_->IsArkExecutedMap(addr));
    addr = 0x0;
    ASSERT_FALSE(maps_->IsArkExecutedMap(addr));
    maps_->Sort(false);
    GTEST_LOG_(INFO) << "IsArkExecutedMapTest: end.";
}
}
} // namespace HiviewDFX
} // namespace OHOS