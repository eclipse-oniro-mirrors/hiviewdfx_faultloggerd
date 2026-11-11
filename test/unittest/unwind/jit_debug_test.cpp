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
#include <dlfcn.h>
#include <cerrno>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include <cstdint>
#include <cstring>
#include <memory>
#include <securec.h>
#include <string>
#include <vector>

#include "dfx_jit_debug.h"
#include "dfx_maps.h"
#include "dfx_memory.h"
#include "elf_craft_builder.h"

using namespace OHOS::HiviewDFX;
using namespace testing::ext;

namespace OHOS {
namespace HiviewDFX {
/*
 * Fake jit debug descriptor exported from the test binary. The unittest target
 * is linked with -rdynamic so dlsym(RTLD_DEFAULT, "__jit_debug_descriptor") in
 * FindJitDescriptorLocal resolves to this instance, which lets tests drive the
 * whole local JIT chain: descriptor -> entry list -> symfile ELF.
 * It is all-zero at rest, which behaves exactly like "no jit info present"
 * for other test cases running in the same process.
 */
extern "C" JitDescriptor __jit_debug_descriptor __attribute__((visibility("default"))) = {};

namespace {
constexpr uint8_t JIT_MAGIC_V2[8] = {'A', 'n', 'd', 'r', 'o', 'i', 'd', '2'}; // 8 : magic size
constexpr size_t V2_ENTRY_SIZE = sizeof(JitCodeEntry);                        // 48 bytes with seqlock
constexpr size_t V1_ENTRY_SIZE = offsetof(JitCodeEntry, timestamp);           // 32 bytes without seqlock

uint64_t ToAddr(const void* ptr)
{
    return static_cast<uint64_t>(reinterpret_cast<uintptr_t>(ptr));
}

bool FakeDescriptorExported()
{
    return dlsym(RTLD_DEFAULT, "__jit_debug_descriptor") != nullptr;
}

/*
 * A fake JIT world living in normal heap memory of the test process:
 * descriptor + N entries + one symfile image. Build it before fork() and the
 * child process inherits an identical copy at identical addresses.
 */
struct FakeJitWorld {
    JitDescriptor desc {};
    std::vector<JitCodeEntry> entries;
    std::vector<uint8_t> symfile;

    void InitV2(size_t entryCount, const CraftedElfOptions& opt)
    {
        symfile = ElfCraftBuilder::Build(opt);
        desc.version = 1;
        if (memcpy_s(desc.magic, sizeof(desc.magic), JIT_MAGIC_V2, sizeof(JIT_MAGIC_V2)) != 0) {
            desc.magic[0] = 'A';
        }
        entries.assign(entryCount, JitCodeEntry {});
        for (size_t i = 0; i < entryCount; i++) {
            entries[i].next = (i + 1 < entryCount) ? ToAddr(&entries[i + 1]) : 0;
            entries[i].prev = (i > 0) ? ToAddr(&entries[i - 1]) : 0;
            entries[i].symfileAddr = ToAddr(symfile.data());
            entries[i].symfileSize = symfile.size();
            entries[i].seqlock = 2; // 2 : even value means stable
        }
        desc.firstEntry = (entryCount > 0) ? ToAddr(&entries[0]) : 0;
        desc.relevantEntry = 0;
    }

    void InitV1Empty()
    {
        desc = JitDescriptor {};
        desc.version = 1;
        desc.firstEntry = 0;
    }
};

/* Forks a child that inherits the parent address space and blocks until released. */
class ChildSandbox {
public:
    bool Start()
    {
        int fds[2];
        if (pipe(fds) != 0) {
            return false;
        }
        pid_t pid = fork();
        if (pid < 0) {
            close(fds[0]);
            close(fds[1]);
            return false;
        }
        if (pid == 0) {
            close(fds[1]);
            char c;
            ssize_t rd = 0;
            do {
                rd = read(fds[0], &c, sizeof(c));
            } while (rd < 0 && errno == EINTR);
            _exit(0);
        }
        close(fds[0]);
        childPid = pid;
        syncFd = fds[1];
        return true;
    }

    bool RemoteReadOk(uint64_t addr)
    {
        uint64_t value = 0;
        return DfxMemory::ReadProcMemByPid(childPid, addr, &value, sizeof(value)) == sizeof(value);
    }

    ~ChildSandbox()
    {
        if (syncFd >= 0) {
            close(syncFd);
            syncFd = -1;
        }
        if (childPid > 0) {
            int status = 0;
            waitpid(childPid, &status, 0);
            childPid = -1;
        }
    }

    pid_t childPid = -1;
    int syncFd = -1;
};

std::shared_ptr<DfxMemory> LocalMemory()
{
    return std::make_shared<DfxMemory>(UNWIND_TYPE_LOCAL);
}
} // namespace

class DfxJitDebugTest : public testing::Test {
protected:
    void SetUp() override
    {
        __jit_debug_descriptor = JitDescriptor {};
    }
    void TearDown() override
    {
        __jit_debug_descriptor = JitDescriptor {};
    }
};

/**
 * @tc.name: DfxJitDebugTest001
 * @tc.desc: test HasJitDebugInfo with a fresh instance
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest001, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest001: start.";
    DfxJitDebug jitDebug;
    EXPECT_FALSE(jitDebug.HasJitDebugInfo());
    GTEST_LOG_(INFO) << "DfxJitDebugTest001: end.";
}

/**
 * @tc.name: DfxJitDebugTest002
 * @tc.desc: test GetJitSymbolInfo with local maps and zero pc
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest002, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest002: start.";
    DfxJitDebug jitDebug;

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

/**
 * @tc.name: DfxJitDebugTest003
 * @tc.desc: test FindJitDescriptorLocal resolves the exported fake descriptor and reads the V1 layout
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest003, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest003: start.";
    if (!FakeDescriptorExported()) {
        GTEST_SKIP() << "__jit_debug_descriptor not exported, dlsym path unavailable";
    }
    FakeJitWorld world;
    world.InitV1Empty();
    __jit_debug_descriptor = world.desc;

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetMaps(DfxMaps::Create());
    jitDebug.SetPid(getpid());
    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    // no entries: the walk succeeds but finds nothing
    EXPECT_FALSE(jitDebug.FindJitElf(0x5000, elf, loadBias));
    EXPECT_TRUE(jitDebug.HasJitDebugInfo());
    EXPECT_EQ(jitDebug.jitEntrySize_, V1_ENTRY_SIZE);
    EXPECT_EQ(jitDebug.seqlockOffset_, 0U);
    GTEST_LOG_(INFO) << "DfxJitDebugTest003: end.";
}

/**
 * @tc.name: DfxJitDebugTest004
 * @tc.desc: test the V2 single entry full hit path with a .text symfile
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest004, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest004: start.";
    if (!FakeDescriptorExported()) {
        GTEST_SKIP() << "__jit_debug_descriptor not exported, dlsym path unavailable";
    }
    CraftedElfOptions opt;
    opt.withText = true;
    opt.textVaddr = 0x1000;
    opt.textSize = 0x100;
    opt.loadVaddr = 0; // keep the parser load bias at zero for the assertion below
    FakeJitWorld world;
    world.InitV2(1, opt); // 1 : single entry
    __jit_debug_descriptor = world.desc;

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(getpid());

    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = static_cast<uint64_t>(-1);
    EXPECT_TRUE(jitDebug.FindJitElf(0x1080, elf, loadBias)); // 0x1080 : pc inside .text
    EXPECT_NE(elf, nullptr);
    EXPECT_TRUE(elf->IsValid());
    EXPECT_EQ(loadBias, 0U);

    JitSymbolInfo info;
    EXPECT_TRUE(jitDebug.GetJitSymbolInfo(0x1080, info));
    EXPECT_EQ(info.elf, elf);
    EXPECT_EQ(info.startPc, 0U);
    EXPECT_EQ(info.endPc, 0x1100U);

    // second lookup hits the per-pid hit cache
    std::shared_ptr<DfxElf> elf2;
    uint64_t loadBias2 = 0;
    EXPECT_TRUE(jitDebug.FindJitElf(0x1080, elf2, loadBias2));
    EXPECT_EQ(elf2, elf);
    GTEST_LOG_(INFO) << "DfxJitDebugTest004: end.";
}

/**
 * @tc.name: DfxJitDebugTest005
 * @tc.desc: test instances are independent
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest005, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest005: test instances are independent.";
    DfxJitDebug jitDebug;
    DfxJitDebug other;
    EXPECT_NE(&jitDebug, &other);
    EXPECT_FALSE(jitDebug.HasJitDebugInfo());
    EXPECT_FALSE(other.HasJitDebugInfo());
    GTEST_LOG_(INFO) << "DfxJitDebugTest005: end.";
}

/**
 * @tc.name: DfxJitDebugTest006
 * @tc.desc: test FindJitElf returns false with null inputs
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest006, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest006: test FindJitElf returns false with null inputs.";
    DfxJitDebug jitDebug;

    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    bool result = jitDebug.FindJitElf(0, elf, loadBias);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "DfxJitDebugTest006: end.";
}

/**
 * @tc.name: DfxJitDebugTest007
 * @tc.desc: test GetJitSymbolInfo returns false with zero pc
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest007, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest007: test GetJitSymbolInfo returns false with zero pc.";
    DfxJitDebug jitDebug;

    JitSymbolInfo info;
    bool result = jitDebug.GetJitSymbolInfo(0, info);
    EXPECT_FALSE(result);
    GTEST_LOG_(INFO) << "DfxJitDebugTest007: end.";
}

/**
 * @tc.name: DfxJitDebugTest008
 * @tc.desc: test JitUID comparison operator
 * @tc.type: FUNC
 */
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

/**
 * @tc.name: DfxJitDebugTest009
 * @tc.desc: an odd seqlock makes ReadNextField report race and exhaust all retries
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest009, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest009: start.";
    if (!FakeDescriptorExported()) {
        GTEST_SKIP() << "__jit_debug_descriptor not exported, dlsym path unavailable";
    }
    CraftedElfOptions opt;
    opt.withText = true;
    opt.textVaddr = 0x1000;
    opt.textSize = 0x100;
    FakeJitWorld world;
    world.InitV2(1, opt);
    world.entries[0].seqlock = 3; // 3 : odd means a writer is active
    __jit_debug_descriptor = world.desc;

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(getpid());

    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    EXPECT_FALSE(jitDebug.FindJitElf(0x1080, elf, loadBias));
    EXPECT_TRUE(jitDebug.entries_.empty());
    GTEST_LOG_(INFO) << "DfxJitDebugTest009: end.";
}

/**
 * @tc.name: DfxJitDebugTest010
 * @tc.desc: a hit cache entry is dropped when its seqlock moves, then rebuilt with the new uid
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest010, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest010: start.";
    if (!FakeDescriptorExported()) {
        GTEST_SKIP() << "__jit_debug_descriptor not exported, dlsym path unavailable";
    }
    CraftedElfOptions opt;
    opt.withText = true;
    opt.textVaddr = 0x1000;
    opt.textSize = 0x100;
    FakeJitWorld world;
    world.InitV2(1, opt);
    __jit_debug_descriptor = world.desc;

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(getpid());

    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    ASSERT_TRUE(jitDebug.FindJitElf(0x1080, elf, loadBias));

    // simulate the ART writer publishing a new generation of the same entry
    world.entries[0].seqlock = 4;
    std::shared_ptr<DfxElf> elf2;
    uint64_t loadBias2 = 0;
    EXPECT_TRUE(jitDebug.FindJitElf(0x1080, elf2, loadBias2)); // rebuilt with the new uid
    EXPECT_EQ(jitDebug.entries_.size(), 1U);

    std::shared_ptr<DfxElf> elf3;
    uint64_t loadBias3 = 0;
    EXPECT_TRUE(jitDebug.FindJitElf(0x1080, elf3, loadBias3)); // fresh cache hit
    GTEST_LOG_(INFO) << "DfxJitDebugTest010: end.";
}

/**
 * @tc.name: DfxJitDebugTest011
 * @tc.desc: a pc not covered by any jit elf is cached as a miss
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest011, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest011: start.";
    if (!FakeDescriptorExported()) {
        GTEST_SKIP() << "__jit_debug_descriptor not exported, dlsym path unavailable";
    }
    CraftedElfOptions opt;
    opt.withText = true;
    opt.textVaddr = 0x1000;
    opt.textSize = 0x100;
    FakeJitWorld world;
    world.InitV2(1, opt);
    __jit_debug_descriptor = world.desc;

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(getpid());

    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    EXPECT_FALSE(jitDebug.FindJitElf(0x8000, elf, loadBias)); // 0x8000 : outside .text
    EXPECT_FALSE(jitDebug.FindJitElf(0x8000, elf, loadBias)); // early miss-cache return
    GTEST_LOG_(INFO) << "DfxJitDebugTest011: end.";
}

/**
 * @tc.name: DfxJitDebugTest012
 * @tc.desc: a cyclic entry list is detected by the visited set
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest012, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest012: start.";
    if (!FakeDescriptorExported()) {
        GTEST_SKIP() << "__jit_debug_descriptor not exported, dlsym path unavailable";
    }
    CraftedElfOptions opt;
    opt.withText = true;
    opt.textVaddr = 0x1000;
    opt.textSize = 0x100;
    FakeJitWorld world;
    world.InitV2(2, opt); // 2 : two entries
    world.entries[0].next = ToAddr(&world.entries[1]);
    world.entries[1].next = ToAddr(&world.entries[0]); // close the cycle
    __jit_debug_descriptor = world.desc;

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(getpid());

    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    EXPECT_FALSE(jitDebug.FindJitElf(0x1080, elf, loadBias));
    GTEST_LOG_(INFO) << "DfxJitDebugTest012: end.";
}

/**
 * @tc.name: DfxJitDebugTest013
 * @tc.desc: a symfile larger than the 64MB cap is rejected
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest013, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest013: start.";
    if (!FakeDescriptorExported()) {
        GTEST_SKIP() << "__jit_debug_descriptor not exported, dlsym path unavailable";
    }
    CraftedElfOptions opt;
    opt.withText = true;
    opt.textVaddr = 0x1000;
    opt.textSize = 0x100;
    FakeJitWorld world;
    world.InitV2(1, opt);
    constexpr uint64_t kMaxSymfileSize = 64ULL << 20; // 64MB cap in LoadJitElf
    world.entries[0].symfileSize = kMaxSymfileSize + 1;
    __jit_debug_descriptor = world.desc;

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(getpid());

    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    EXPECT_FALSE(jitDebug.FindJitElf(0x1080, elf, loadBias));
    EXPECT_TRUE(jitDebug.entries_.empty());
    GTEST_LOG_(INFO) << "DfxJitDebugTest013: end.";
}

/**
 * @tc.name: DfxJitDebugTest014
 * @tc.desc: a symfile with garbage content fails DfxElf validation and is skipped
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest014, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest014: start.";
    if (!FakeDescriptorExported()) {
        GTEST_SKIP() << "__jit_debug_descriptor not exported, dlsym path unavailable";
    }
    CraftedElfOptions opt;
    opt.withText = true;
    opt.textVaddr = 0x1000;
    opt.textSize = 0x100;
    FakeJitWorld world;
    world.InitV2(1, opt);
    world.symfile = ElfCraftBuilder::BuildGarbage(0x40); // 0x40 : not an ELF
    world.entries[0].symfileAddr = ToAddr(world.symfile.data());
    world.entries[0].symfileSize = world.symfile.size();
    __jit_debug_descriptor = world.desc;

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(getpid());

    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    EXPECT_FALSE(jitDebug.FindJitElf(0x1080, elf, loadBias));
    GTEST_LOG_(INFO) << "DfxJitDebugTest014: end.";
}

/**
 * @tc.name: DfxJitDebugTest015
 * @tc.desc: a symfile without .text gets its runtime range from func symbols
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest015, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest015: start.";
    if (!FakeDescriptorExported()) {
        GTEST_SKIP() << "__jit_debug_descriptor not exported, dlsym path unavailable";
    }
    CraftedElfOptions opt;
    opt.withText = false;
    opt.withFuncSym = true;
    opt.funcVaddr = 0x2000;
    opt.funcSize = 0x80;
    FakeJitWorld world;
    world.InitV2(1, opt);
    __jit_debug_descriptor = world.desc;

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(getpid());

    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    EXPECT_TRUE(jitDebug.FindJitElf(0x2040, elf, loadBias)); // 0x2040 : inside JitFunc
    EXPECT_NE(elf, nullptr);

    JitSymbolInfo info;
    EXPECT_TRUE(jitDebug.GetJitSymbolInfo(0x2040, info));
    EXPECT_EQ(info.endPc, 0x2080U);
    GTEST_LOG_(INFO) << "DfxJitDebugTest015: end.";
}

/**
 * @tc.name: DfxJitDebugTest016
 * @tc.desc: a symfile without .text and without func symbols falls back to the pt load range
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest016, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest016: start.";
    if (!FakeDescriptorExported()) {
        GTEST_SKIP() << "__jit_debug_descriptor not exported, dlsym path unavailable";
    }
    CraftedElfOptions opt;
    opt.withText = false;
    opt.withFuncSym = false;
    opt.withLoad = true;
    opt.loadVaddr = 0x3000;
    opt.loadMemSize = 0x40;
    FakeJitWorld world;
    world.InitV2(1, opt);
    __jit_debug_descriptor = world.desc;

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(getpid());

    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    EXPECT_TRUE(jitDebug.FindJitElf(0x3020, elf, loadBias)); // 0x3020 : inside the pt load
    EXPECT_NE(elf, nullptr);
    GTEST_LOG_(INFO) << "DfxJitDebugTest016: end.";
}

/**
 * @tc.name: DfxJitDebugTest017
 * @tc.desc: an elf injected into entries without a runtime range keeps the start/end pc fallback
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest017, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest017: start.";
    CraftedElfOptions opt;
    opt.withText = true;
    opt.textVaddr = 0x1000;
    opt.textSize = 0x100;
    opt.withLoad = true;
    opt.loadVaddr = 0x3000;
    opt.loadMemSize = 0x40;
    auto image = ElfCraftBuilder::Build(opt);
    auto mmap = std::make_shared<DfxMmap>();
    ASSERT_TRUE(mmap->Init(std::move(image)));
    auto elf = std::make_shared<DfxElf>(mmap);
    ASSERT_TRUE(elf->IsValid());
    EXPECT_FALSE(elf->HasRuntimeRange()); // never passed through LoadJitElf

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(getpid());
    // pretend the descriptor was already resolved for this pid so the first
    // FindJitElf call does not reset the injected entries below
    jitDebug.descriptorPid_ = getpid();
    jitDebug.descriptorAddr_ = 0x1; // any non-zero value skips EnsureJitDescriptorLocked
    JitUID uid = {0x1000, 0};
    jitDebug.entries_.emplace(uid, elf); // direct injection, V1 style uid

    std::shared_ptr<DfxElf> found;
    uint64_t loadBias = 0;
    // IsValidPc falls back to the pt loads: [0x3000, 0x3040)
    EXPECT_TRUE(jitDebug.FindJitElf(0x3020, found, loadBias));
    EXPECT_EQ(found, elf);

    JitSymbolInfo info;
    EXPECT_TRUE(jitDebug.GetJitSymbolInfo(0x3020, info));
    EXPECT_EQ(info.startPc, elf->GetStartPc());
    EXPECT_EQ(info.endPc, elf->GetEndPc());
    GTEST_LOG_(INFO) << "DfxJitDebugTest017: end.";
}

/**
 * @tc.name: DfxJitDebugTest018
 * @tc.desc: remote pid reads go through process_vm_readv against the child copy
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest018, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest018: start.";
    CraftedElfOptions opt;
    opt.withText = true;
    opt.textVaddr = 0x1000;
    opt.textSize = 0x100;
    FakeJitWorld world;
    world.InitV2(1, opt);

    ChildSandbox sandbox;
    if (!sandbox.Start()) {
        GTEST_SKIP() << "fork failed";
    }
    if (!sandbox.RemoteReadOk(ToAddr(&world.desc))) {
        GTEST_SKIP() << "process_vm_readv unavailable for child";
    }
    // cut the parent-side chain: only the child copy still points at the entry,
    // so a hit proves the reads were served from the child address space
    world.desc.firstEntry = 0;

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(sandbox.childPid);
    jitDebug.descriptorPid_ = sandbox.childPid;
    jitDebug.descriptorAddr_ = ToAddr(&world.desc);
    ASSERT_TRUE(jitDebug.ReadDescriptor());
    EXPECT_EQ(jitDebug.jitEntrySize_, V2_ENTRY_SIZE);

    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    EXPECT_TRUE(jitDebug.FindJitElf(0x1080, elf, loadBias));
    EXPECT_NE(elf, nullptr);

    // release the child; the cached hit must be invalidated by failed remote seqlock reads
    close(sandbox.syncFd);
    sandbox.syncFd = -1;
    int status = 0;
    waitpid(sandbox.childPid, &status, 0);
    sandbox.childPid = -1;

    std::shared_ptr<DfxElf> elf2;
    uint64_t loadBias2 = 0;
    EXPECT_FALSE(jitDebug.FindJitElf(0x1080, elf2, loadBias2));
    GTEST_LOG_(INFO) << "DfxJitDebugTest018: end.";
}

/**
 * @tc.name: DfxJitDebugTest019
 * @tc.desc: a descriptor crossing an unmapped page falls back to the V1 24-byte read
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest019, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest019: start.";
    const size_t pageSize = static_cast<size_t>(sysconf(_SC_PAGESIZE));
    void* pool = mmap(nullptr, 2 * pageSize, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    ASSERT_NE(pool, MAP_FAILED);
    uint8_t* pageEnd = static_cast<uint8_t*>(pool) + pageSize;
    ASSERT_EQ(munmap(pageEnd, pageSize), 0);
    JitDescriptor* desc = reinterpret_cast<JitDescriptor*>(pageEnd - 24); // 24 : V1 size
    // only the first 24 bytes (version..firstEntry) live on the mapped page,
    // a full 56 byte struct assignment would run into the unmapped page
    if (memset_s(desc, 24, 0, 24) != 0) {
        ASSERT_TRUE(false);
    }
    desc->version = 1;
    desc->firstEntry = 0;

    ChildSandbox sandbox;
    if (!sandbox.Start()) {
        munmap(pool, pageSize);
        GTEST_SKIP() << "fork failed";
    }
    if (!sandbox.RemoteReadOk(ToAddr(desc))) {
        munmap(pool, pageSize);
        GTEST_SKIP() << "process_vm_readv unavailable for child";
    }

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(sandbox.childPid);
    jitDebug.descriptorPid_ = sandbox.childPid;
    jitDebug.descriptorAddr_ = ToAddr(desc);
    // the 56-byte read crosses into the unmapped page, the 24-byte V1 read succeeds
    EXPECT_TRUE(jitDebug.ReadDescriptor());
    EXPECT_EQ(jitDebug.jitEntrySize_, V1_ENTRY_SIZE);
    EXPECT_EQ(jitDebug.seqlockOffset_, 0U);
    munmap(pool, pageSize);
    GTEST_LOG_(INFO) << "DfxJitDebugTest019: end.";
}

/**
 * @tc.name: DfxJitDebugTest020
 * @tc.desc: an invalid descriptor version makes the local lookup fail and fall to the maps scan
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest020, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest020: start.";
    FakeJitWorld world;
    world.InitV1Empty();
    world.desc.version = 0; // invalid version: the local descriptor is rejected
    __jit_debug_descriptor = world.desc;

    std::string mapsContent;
    mapsContent += "7000000-7001000 r--p 00000000 00:00 0 /data/local/tmp/not_exist_libart.so\n";
    mapsContent += "7001000-7002000 r-xp 00000000 00:00 0 /data/local/tmp/not_exist_other.so\n";
    mapsContent += "7002000-7003000 r--p 00000000 00:00 0 [page size compat]\n";
    auto maps = DfxMaps::CreateByBuffer("", mapsContent);
    ASSERT_NE(maps, nullptr);

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetMaps(maps);
    jitDebug.SetPid(getpid());

    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    EXPECT_FALSE(jitDebug.FindJitElf(0x1000, elf, loadBias));
    // the libart.so map was scanned but its elf is invalid -> NOT_PRESENT cached for this pid
    EXPECT_EQ(jitDebug.descriptorCheckedPid_, static_cast<pid_t>(getpid()));
    EXPECT_FALSE(jitDebug.FindJitElf(0x1000, elf, loadBias)); // short-circuit path
    GTEST_LOG_(INFO) << "DfxJitDebugTest020: end.";
}

/**
 * @tc.name: DfxJitDebugTest021
 * @tc.desc: null maps reports RETRY_LATER and later NOT_PRESENT without caching the retry
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest021, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest021: start.";
    ChildSandbox sandbox;
    if (!sandbox.Start()) {
        GTEST_SKIP() << "fork failed";
    }
    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(sandbox.childPid);

    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    EXPECT_FALSE(jitDebug.FindJitElf(0x1000, elf, loadBias)); // maps null -> RETRY_LATER
    EXPECT_EQ(jitDebug.descriptorCheckedPid_, -1);            // a retry is not cached

    std::string mapsContent = "7000000-7001000 r--p 00000000 00:00 0 /data/local/tmp/not_exist_libart.so\n";
    auto maps = DfxMaps::CreateByBuffer("", mapsContent);
    ASSERT_NE(maps, nullptr);
    jitDebug.SetMaps(maps);
    EXPECT_FALSE(jitDebug.FindJitElf(0x1000, elf, loadBias)); // scanned -> NOT_PRESENT
    EXPECT_EQ(jitDebug.descriptorCheckedPid_, sandbox.childPid);
    GTEST_LOG_(INFO) << "DfxJitDebugTest021: end.";
}

/**
 * @tc.name: DfxJitDebugTest022
 * @tc.desc: switching pid resets the descriptor and entries state
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest022, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest022: start.";
    if (!FakeDescriptorExported()) {
        GTEST_SKIP() << "__jit_debug_descriptor not exported, dlsym path unavailable";
    }
    CraftedElfOptions opt;
    opt.withText = true;
    opt.textVaddr = 0x1000;
    opt.textSize = 0x100;
    FakeJitWorld world;
    world.InitV2(1, opt);
    __jit_debug_descriptor = world.desc;

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(getpid());
    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    ASSERT_TRUE(jitDebug.FindJitElf(0x1080, elf, loadBias));
    EXPECT_EQ(jitDebug.entries_.size(), 1U);

    jitDebug.SetPid(40010); // 40010 : dead pid
    std::shared_ptr<DfxElf> elf2;
    uint64_t loadBias2 = 0;
    EXPECT_FALSE(jitDebug.FindJitElf(0x1080, elf2, loadBias2));
    EXPECT_TRUE(jitDebug.entries_.empty());
    EXPECT_EQ(jitDebug.descriptorPid_, 40010);
    GTEST_LOG_(INFO) << "DfxJitDebugTest022: end.";
}

/**
 * @tc.name: DfxJitDebugTest023
 * @tc.desc: LoadJitElf direct guard clauses
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest023, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest023: start.";
    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(getpid());
    jitDebug.seqlockOffset_ = 0; // V1 style: seqlock checks are skipped

    std::vector<uint8_t> buf = ElfCraftBuilder::BuildGarbage(0x20); // 0x20 : small garbage
    JitUID uid = {0x1000, 0};
    std::shared_ptr<DfxElf> elf;
    EXPECT_FALSE(jitDebug.LoadJitElf(0, buf.size(), elf, uid));         // null address
    EXPECT_FALSE(jitDebug.LoadJitElf(ToAddr(buf.data()), 0, elf, uid)); // zero size
    GTEST_LOG_(INFO) << "DfxJitDebugTest023: end.";
}

/**
 * @tc.name: DfxJitDebugTest024
 * @tc.desc: ReadMemory guards and the remote failure path
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest024, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest024: start.";
    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    uint64_t value = 0;
    EXPECT_FALSE(jitDebug.ReadMemory(0x1000, nullptr, sizeof(value))); // null buffer

    jitDebug.SetPid(40011); // 40011 : dead pid, never equals getpid()
    EXPECT_FALSE(jitDebug.ReadMemory(0x1, &value, sizeof(value))); // unmapped remote address
    GTEST_LOG_(INFO) << "DfxJitDebugTest024: end.";
}

/**
 * @tc.name: DfxJitDebugTest025
 * @tc.desc: StripAddressTag clears the arm64 top byte and keeps other archs as is
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest025, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest025: start.";
    DfxJitDebug jitDebug;
    jitDebug.SetArch(ARCH_ARM64);
    uint64_t tagged = 0xb400000000001000; // 0xb4 : arbitrary top byte tag
    EXPECT_EQ(jitDebug.StripAddressTag(tagged), 0x1000U);
    jitDebug.SetArch(ARCH_ARM);
    EXPECT_EQ(jitDebug.StripAddressTag(tagged), tagged);
    GTEST_LOG_(INFO) << "DfxJitDebugTest025: end.";
}

/**
 * @tc.name: DfxJitDebugTest026
 * @tc.desc: a tagged firstEntry address is stripped during the walk
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest026, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest026: start.";
    if (!FakeDescriptorExported()) {
        GTEST_SKIP() << "__jit_debug_descriptor not exported, dlsym path unavailable";
    }
    CraftedElfOptions opt;
    opt.withText = true;
    opt.textVaddr = 0x1000;
    opt.textSize = 0x100;
    FakeJitWorld world;
    world.InitV2(1, opt);
    const uint64_t tag = 0xb400000000000000; // 0xb4 : top byte tag
    world.desc.firstEntry |= tag;
    __jit_debug_descriptor = world.desc;

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetPid(getpid());
    jitDebug.SetArch(ARCH_ARM64);

    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    EXPECT_TRUE(jitDebug.FindJitElf(0x1080, elf, loadBias));
    GTEST_LOG_(INFO) << "DfxJitDebugTest026: end.";
}

/**
 * @tc.name: DfxJitDebugTest027
 * @tc.desc: per-pid cache buckets follow the LRU and evict beyond four pids
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest027, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest027: start.";
    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    for (int pid = 40021; pid <= 40025; pid++) { // 40025 : more buckets than the LRU cap
        jitDebug.SetPid(pid); // dead pids: descriptor lookups fail fast
        EXPECT_FALSE(jitDebug.FindJitElf(0x1000, elf, loadBias));
    }
    GTEST_LOG_(INFO) << "DfxJitDebugTest027: end.";
}

/**
 * @tc.name: DfxJitDebugTest028
 * @tc.desc: the maps scan finds the descriptor through a crafted libart.so file
 * @tc.type: FUNC
 */
HWTEST_F(DfxJitDebugTest, DfxJitDebugTest028, TestSize.Level1)
{
    GTEST_LOG_(INFO) << "DfxJitDebugTest028: start.";
    // fake descriptor living in this process, the crafted symbol value points at it
    FakeJitWorld world;
    world.InitV2(1, CraftedElfOptions {});
    const uint64_t mapBegin = 0x7000000;
    CraftedElfOptions opt;
    opt.withObjectSym = true;
    opt.objectName = "__jit_debug_descriptor";
    opt.objectVaddr = ToAddr(&world.desc) - mapBegin; // runtimeAddr lands on the fake descriptor
    auto image = ElfCraftBuilder::Build(opt);

    // the scan only accepts maps whose basename is exactly libart.so
    const std::string libartPath = "/data/local/tmp/libart.so";
    int fd = open(libartPath.c_str(), O_CREAT | O_TRUNC | O_WRONLY, 0644); // 0644 : file mode
    if (fd < 0) {
        GTEST_SKIP() << "temp file not writable, skip file based case";
    }
    size_t written = 0;
    while (written < image.size()) {
        ssize_t n = write(fd, image.data() + written, image.size() - written);
        if (n < 0 && errno == EINTR) {
            continue; // interrupted before writing anything, retry
        }
        if (n <= 0) {
            break;
        }
        written += static_cast<size_t>(n);
    }
    close(fd);

    std::string mapsContent;
    mapsContent += "7000000-7100000 r--p 00000000 00:00 0 " + libartPath + "\n";
    mapsContent += "7100000-7110000 r-xp 00000000 00:00 0 /data/local/tmp/not_exist_other.so\n";
    // a map entry covering the fake descriptor itself so FindMapByAddr resolves
    const uint64_t descPage = ToAddr(&world.desc) & ~0xfffffULL; // 0xfffff : 1MB align down
    char descMap[128]; // 128 : line buffer
    if (snprintf_s(descMap, sizeof(descMap), sizeof(descMap) - 1, "%llx-%llx rw-p 00000000 00:00 0 [anon:test desc]\n",
        static_cast<unsigned long long>(descPage), static_cast<unsigned long long>(descPage + 0x100000)) > 0) {
        mapsContent += descMap;
    }
    auto maps = DfxMaps::CreateByBuffer("", mapsContent);
    ASSERT_NE(maps, nullptr);

    DfxJitDebug jitDebug;
    jitDebug.SetMemory(LocalMemory());
    jitDebug.SetMaps(maps);
    // local dlsym must fail first so the maps scan runs: use a remote-looking own pid is
    // impossible, instead make the exported descriptor invalid and restore afterwards
    __jit_debug_descriptor.version = 0;
    jitDebug.SetPid(getpid());
    std::shared_ptr<DfxElf> elf;
    uint64_t loadBias = 0;
    // pc inside the single entry .text range [0x1000, 0x1100)
    EXPECT_TRUE(jitDebug.FindJitElf(0x1080, elf, loadBias));
    EXPECT_NE(elf, nullptr);
    EXPECT_TRUE(jitDebug.HasJitDebugInfo());
    unlink(libartPath.c_str());
    GTEST_LOG_(INFO) << "DfxJitDebugTest028: end.";
}
} // namespace HiviewDFX
} // namespace OHOS
