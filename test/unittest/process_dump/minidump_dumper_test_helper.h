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

#pragma once

#include <fcntl.h>
#include <gtest/gtest.h>
#include <memory>
#include <csignal>
#include <string>
#include <unistd.h>
#include <sys/wait.h>

#include "cppcrash_info_collector.h"
#include "dfx_buffer_writer.h"
#include "dfx_dump_request.h"
#include "dfx_maps.h"
#include "dfx_regs.h"
#include "dfx_signal.h"
#include "dfx_thread.h"
#include "dfx_util.h"
#include "dump_utils.h"
#include "lite_process_dumper.h"
#include "minidump_config.h"
#include "minidump_dumper.h"
#include "minidump_format.h"
#include "minidump_parser.h"
#include "minidump_stream_pipeline.h"
#include "procinfo.h"
#include "unwinder.h"
#include "unwinder_config.h"

namespace OHOS {
namespace HiviewDFX {

constexpr mode_t TEST_FILE_PERMISSIONS = 0644;
constexpr size_t TEST_BUFFER_SIZE = 256;

class MinidumpDumperTest : public testing::Test {
public:
    void SetUp() override
    {
        CppCrashInfoCollector::Instance().Reset();
    }
    void TearDown() override
    {
        CppCrashInfoCollector::Instance().Reset();
    }
};

inline void InitMinidumpHeader(MDRawHeader& header, size_t dirCount, size_t headerSize)
{
    header = {};
    header.signature = MINIDUMP_HEADER_SIGNATURE;
    header.version = (MINIDUMP_HEADER_VERSION & 0xffff) | 0xa7900000;
    header.numberOfStreams = dirCount;
    header.streamDirectoryRva = headerSize;
}

inline MDRawSystemInfo InitSystemInfo()
{
    MDRawSystemInfo sysInfo = {};
    sysInfo.platformId = MINIDUMP_OS_LINUX;
    sysInfo.processorArchitecture = MD_CPU_ARCH_ARM64;
    return sysInfo;
}

inline std::string BuildMDStringData(const uint16_t* name, uint32_t nameLen)
{
    MDString mdStr = {};
    mdStr.length = nameLen * 2 + 2; // 2:double of nameLen
    std::string data(reinterpret_cast<const char*>(&mdStr), sizeof(uint32_t));
    data += std::string(reinterpret_cast<const char*>(name), (nameLen + 1) * 2);
    return data;
}

inline std::string BuildFullCrashLogEsrInfo(pid_t pid)
{
    MDRawEsrRegsInfo esrInfo = {};
    esrInfo.validity = MD_BREAKPAD_INFO_VALID_DUMP_THREAD_ID | MD_BREAKPAD_INFO_VALID_ESR_REGS;
    esrInfo.dumpThreadId = static_cast<uint32_t>(pid);
    esrInfo.esrRegs = 0x92000046;
    return std::string(reinterpret_cast<const char*>(&esrInfo), sizeof(esrInfo));
}

MDRawContextARM64 InitARM64Context(uint64_t spValue, uint64_t regBase = 0x1000);
std::string BuildMinidumpWithExceptionAndContext();
std::string BuildMinidumpWithExceptionBySignal(int signal, int32_t signalCode);
std::string BuildMinidumpWithModuleList();
std::string BuildMinidumpWithThreadNameList();
std::string BuildMinidumpWithMemoryList();
std::string BuildMinidumpWithThreadList();
std::string BuildMinidumpWithMapList();
std::string BuildMinidumpWithMultiThreadNames();
std::string BuildFullCrashLogExcStream(pid_t pid, size_t excRva);
std::string BuildFullCrashLogThreadList(pid_t pid, size_t threadListRva);
std::string BuildMinidumpWithFullCrashLog();

class MockDfxRegsNoPrefix : public DfxRegs {
public:
    MockDfxRegsNoPrefix() = default;
    void SetFromUcontext(const ucontext_t& context) override {}
    void SetFromFpMiniRegs(const uintptr_t* regs, const size_t size) override {}
    void SetFromQutMiniRegs(const uintptr_t* regs, const size_t size) override {}
    std::string PrintRegs() const override
    {
        return "r0:00000000 r1:00000000\n";
    }
    bool SetPcFromReturnAddress(std::shared_ptr<DfxMemory> memory) override { return false; }
    bool StepIfSignalFrame(uintptr_t pc, std::shared_ptr<DfxMemory> memory) override { return false; }
};

} // namespace HiviewDFX
} // namespace OHOS
