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

#include "minidump_dumper_test_helper.h"

namespace OHOS {
namespace HiviewDFX {

MDRawContextARM64 InitARM64Context(uint64_t spValue, uint64_t regBase)
{
    MDRawContextARM64 context = {};
    context.contextFlags = MD_CONTEXT_ARM64;
    for (uint32_t i = 0; i < MD_CONTEXT_ARM64_GPR_COUNT; i++) {
        context.iregs[i] = regBase + i * 8; // 8:eight times
    }
    context.iregs[31] = spValue; // 31:sp reg index
    context.cpsr = 0;
    return context;
}

std::string BuildMinidumpWithExceptionAndContext()
{
    pid_t pid = getpid();
    size_t headerSize = sizeof(MDRawHeader);
    size_t dirCount = 3;
    size_t dirSize = sizeof(MDRawDirectory) * dirCount;
    size_t dataStart = headerSize + dirSize;
    MDRawContextARM64 context = InitARM64Context(0x8000);
    MDExceptionStream excStream = {};
    excStream.threadId = static_cast<uint32_t>(pid);
    excStream.unusedAlignment = 0;
    excStream.exceptionRecord.exceptionCode = SIGSEGV;
    excStream.exceptionRecord.exceptionFlags = SEGV_MAPERR;
    excStream.exceptionRecord.exceptionAddress = 0x1000;
    excStream.exceptionRecord.numberParameters = 0;
    excStream.threadContext.dataSize = sizeof(MDRawContextARM64);
    excStream.threadContext.rva = dataStart + sizeof(MDExceptionStream);
    MDRawEsrRegsInfo esrInfo = {};
    esrInfo.validity = MD_BREAKPAD_INFO_VALID_DUMP_THREAD_ID | MD_BREAKPAD_INFO_VALID_ESR_REGS;
    esrInfo.dumpThreadId = static_cast<uint32_t>(pid);
    esrInfo.esrRegs = 0x92000046;
    size_t excDataSize = sizeof(MDExceptionStream) + sizeof(MDRawContextARM64);
    size_t esrDataOffset = dataStart + excDataSize;
    MDRawHeader header = {};
    InitMinidumpHeader(header, dirCount, headerSize);
    MDRawDirectory dirExc = {};
    dirExc.streamType = MD_STREAM_EXCEPTION;
    dirExc.location.dataSize = excDataSize;
    dirExc.location.rva = dataStart;
    MDRawDirectory dirEsr = {};
    dirEsr.streamType = MD_STREAM_ESR_INFO;
    dirEsr.location.dataSize = sizeof(MDRawEsrRegsInfo);
    dirEsr.location.rva = esrDataOffset;
    MDRawDirectory dirSys = {};
    dirSys.streamType = MD_STREAM_SYSTEM_INFO;
    dirSys.location.dataSize = sizeof(MDRawSystemInfo);
    dirSys.location.rva = esrDataOffset + sizeof(MDRawEsrRegsInfo);
    MDRawSystemInfo sysInfo = InitSystemInfo();
    std::string data(reinterpret_cast<const char*>(&header), sizeof(header));
    data += std::string(reinterpret_cast<const char*>(&dirExc), sizeof(dirExc));
    data += std::string(reinterpret_cast<const char*>(&dirEsr), sizeof(dirEsr));
    data += std::string(reinterpret_cast<const char*>(&dirSys), sizeof(dirSys));
    data += std::string(reinterpret_cast<const char*>(&excStream), sizeof(excStream));
    data += std::string(reinterpret_cast<const char*>(&context), sizeof(context));
    data += std::string(reinterpret_cast<const char*>(&esrInfo), sizeof(esrInfo));
    data += std::string(reinterpret_cast<const char*>(&sysInfo), sizeof(sysInfo));
    return data;
}

std::string BuildMinidumpWithExceptionBySignal(int signal, int32_t signalCode)
{
    pid_t pid = getpid();
    size_t headerSize = sizeof(MDRawHeader);
    size_t dirCount = 3;
    size_t dirSize = sizeof(MDRawDirectory) * dirCount;
    size_t dataStart = headerSize + dirSize;
    MDRawContextARM64 context = InitARM64Context(0x8000);
    MDExceptionStream excStream = {};
    excStream.threadId = static_cast<uint32_t>(pid);
    excStream.unusedAlignment = 0;
    excStream.exceptionRecord.exceptionCode = signal;
    excStream.exceptionRecord.exceptionFlags = signalCode;
    excStream.exceptionRecord.exceptionAddress = 0x1000;
    excStream.exceptionRecord.numberParameters = 0;
    excStream.threadContext.dataSize = sizeof(MDRawContextARM64);
    excStream.threadContext.rva = dataStart + sizeof(MDExceptionStream);
    MDRawEsrRegsInfo esrInfo = {};
    esrInfo.validity = MD_BREAKPAD_INFO_VALID_DUMP_THREAD_ID | MD_BREAKPAD_INFO_VALID_ESR_REGS;
    esrInfo.dumpThreadId = static_cast<uint32_t>(pid);
    esrInfo.esrRegs = 0x92000046;
    size_t excDataSize = sizeof(MDExceptionStream) + sizeof(MDRawContextARM64);
    size_t esrDataOffset = dataStart + excDataSize;
    MDRawHeader header = {};
    InitMinidumpHeader(header, dirCount, headerSize);
    MDRawDirectory dirExc = {};
    dirExc.streamType = MD_STREAM_EXCEPTION;
    dirExc.location.dataSize = excDataSize;
    dirExc.location.rva = dataStart;
    MDRawDirectory dirEsr = {};
    dirEsr.streamType = MD_STREAM_ESR_INFO;
    dirEsr.location.dataSize = sizeof(MDRawEsrRegsInfo);
    dirEsr.location.rva = esrDataOffset;
    MDRawDirectory dirSys = {};
    dirSys.streamType = MD_STREAM_SYSTEM_INFO;
    dirSys.location.dataSize = sizeof(MDRawSystemInfo);
    dirSys.location.rva = esrDataOffset + sizeof(MDRawEsrRegsInfo);
    MDRawSystemInfo sysInfo = InitSystemInfo();
    std::string data(reinterpret_cast<const char*>(&header), sizeof(header));
    data += std::string(reinterpret_cast<const char*>(&dirExc), sizeof(dirExc));
    data += std::string(reinterpret_cast<const char*>(&dirEsr), sizeof(dirEsr));
    data += std::string(reinterpret_cast<const char*>(&dirSys), sizeof(dirSys));
    data += std::string(reinterpret_cast<const char*>(&excStream), sizeof(excStream));
    data += std::string(reinterpret_cast<const char*>(&context), sizeof(context));
    data += std::string(reinterpret_cast<const char*>(&esrInfo), sizeof(esrInfo));
    data += std::string(reinterpret_cast<const char*>(&sysInfo), sizeof(sysInfo));
    return data;
}

std::string BuildMinidumpWithModuleList()
{
    size_t headerSize = sizeof(MDRawHeader);
    size_t dirCount = 1;
    size_t dataStart = headerSize + sizeof(MDRawDirectory) * dirCount;
    uint16_t moduleName[] = {u't', u'e', u's', u't', u'.', u's', u'o', 0};
    size_t moduleNameOffset = dataStart + sizeof(MDRawModuleList) + sizeof(MDRawModule);
    std::string mdStrData = BuildMDStringData(moduleName, 7);
    MDRawModule module = {};
    module.baseOfImage = 0x1000;
    module.sizeOfImage = 0x1000;
    module.moduleNameRva = moduleNameOffset;
    MDRawModuleList moduleList = {};
    moduleList.numberOfModules = 1;
    MDRawHeader header = {};
    InitMinidumpHeader(header, dirCount, headerSize);
    MDRawDirectory dirMod = {};
    dirMod.streamType = MD_STREAM_MODULE_LIST;
    dirMod.location.dataSize = sizeof(MDRawModuleList) + sizeof(MDRawModule);
    dirMod.location.rva = dataStart;
    std::string data(reinterpret_cast<const char*>(&header), sizeof(header));
    data += std::string(reinterpret_cast<const char*>(&dirMod), sizeof(dirMod));
    data += std::string(reinterpret_cast<const char*>(&moduleList), sizeof(moduleList));
    data += std::string(reinterpret_cast<const char*>(&module), sizeof(module));
    data += mdStrData;
    return data;
}

std::string BuildMinidumpWithThreadNameList()
{
    pid_t pid = getpid();
    size_t headerSize = sizeof(MDRawHeader);
    size_t dirCount = 1;
    size_t dataStart = headerSize + sizeof(MDRawDirectory) * dirCount;
    uint16_t threadName[] = {u'm', u'a', u'i', u'n', 0};
    size_t threadNameOffset = dataStart + sizeof(MDRawThreadNameList) + sizeof(MDRawThreadName);
    std::string mdStrData = BuildMDStringData(threadName, 4);
    MDRawThreadName rawThreadName = {};
    rawThreadName.threadId = static_cast<uint32_t>(pid);
    rawThreadName.rvaOfThreadName = threadNameOffset;
    MDRawThreadNameList threadNameList = {};
    threadNameList.numberOfThreadNames = 1;
    MDRawHeader header = {};
    InitMinidumpHeader(header, dirCount, headerSize);
    MDRawDirectory dirTN = {};
    dirTN.streamType = MD_STREAM_THREAD_NAME_LIST;
    dirTN.location.dataSize = sizeof(MDRawThreadNameList) + sizeof(MDRawThreadName);
    dirTN.location.rva = dataStart;
    std::string data(reinterpret_cast<const char*>(&header), sizeof(header));
    data += std::string(reinterpret_cast<const char*>(&dirTN), sizeof(dirTN));
    data += std::string(reinterpret_cast<const char*>(&threadNameList), sizeof(threadNameList));
    data += std::string(reinterpret_cast<const char*>(&rawThreadName), sizeof(rawThreadName));
    data += mdStrData;
    return data;
}

std::string BuildMinidumpWithMemoryList()
{
    size_t headerSize = sizeof(MDRawHeader);
    size_t dirCount = 1;
    size_t dataStart = headerSize + sizeof(MDRawDirectory) * dirCount;
    uint8_t memoryData[TEST_BUFFER_SIZE] = {};
    for (int i = 0; i < TEST_BUFFER_SIZE; i++) {
        memoryData[i] = static_cast<uint8_t>(i);
    }
    MDMemoryDescriptor memDesc = {};
    memDesc.startOfMemoryRange = 0x7000;
    memDesc.memory.dataSize = TEST_BUFFER_SIZE;
    memDesc.memory.rva = dataStart + sizeof(MDRawMemoryList) + sizeof(MDMemoryDescriptor);
    MDRawMemoryList memList = {};
    memList.numberOfMemoryRanges = 1;
    MDRawHeader header = {};
    InitMinidumpHeader(header, dirCount, headerSize);
    MDRawDirectory dirMem = {};
    dirMem.streamType = MD_STREAM_MEMORY_LIST;
    dirMem.location.dataSize = sizeof(MDRawMemoryList) + sizeof(MDMemoryDescriptor);
    dirMem.location.rva = dataStart;
    std::string data(reinterpret_cast<const char*>(&header), sizeof(header));
    data += std::string(reinterpret_cast<const char*>(&dirMem), sizeof(dirMem));
    data += std::string(reinterpret_cast<const char*>(&memList), sizeof(memList));
    data += std::string(reinterpret_cast<const char*>(&memDesc), sizeof(memDesc));
    data += std::string(reinterpret_cast<const char*>(memoryData), TEST_BUFFER_SIZE);
    return data;
}

std::string BuildMinidumpWithThreadList()
{
    pid_t pid = getpid();
    size_t headerSize = sizeof(MDRawHeader);
    size_t dirCount = 1;
    size_t dataStart = headerSize + sizeof(MDRawDirectory) * dirCount;
    size_t threadListDataSize = sizeof(uint32_t) + sizeof(MDRawThread);
    size_t contextOffset = dataStart + threadListDataSize;
    size_t stackOffset = contextOffset + sizeof(MDRawContextARM64);
    MDRawContextARM64 context = InitARM64Context(0x7000);
    uint8_t stackData[TEST_BUFFER_SIZE] = {};
    for (int i = 0; i < TEST_BUFFER_SIZE; i++) {
        stackData[i] = static_cast<uint8_t>(i);
    }
    MDRawThread thread = {};
    thread.threadId = static_cast<uint32_t>(pid);
    thread.suspendCount = 0;
    thread.priorityClass = 0;
    thread.priority = 0;
    thread.teb = 0;
    thread.stack.startOfMemoryRange = 0x7000;
    thread.stack.memory.dataSize = TEST_BUFFER_SIZE;
    thread.stack.memory.rva = stackOffset;
    thread.threadContext.dataSize = sizeof(MDRawContextARM64);
    thread.threadContext.rva = contextOffset;
    uint32_t numberOfThreads = 1;
    MDRawDirectory dirThread = {};
    dirThread.streamType = MD_STREAM_THREAD_LIST;
    dirThread.location.dataSize = threadListDataSize;
    dirThread.location.rva = dataStart;
    MDRawHeader header = {};
    InitMinidumpHeader(header, dirCount, headerSize);
    std::string data(reinterpret_cast<const char*>(&header), sizeof(header));
    data += std::string(reinterpret_cast<const char*>(&dirThread), sizeof(dirThread));
    data += std::string(reinterpret_cast<const char*>(&numberOfThreads), sizeof(numberOfThreads));
    data += std::string(reinterpret_cast<const char*>(&thread), sizeof(thread));
    data += std::string(reinterpret_cast<const char*>(&context), sizeof(context));
    data += std::string(reinterpret_cast<const char*>(stackData), TEST_BUFFER_SIZE);
    return data;
}

std::string BuildMinidumpWithMapList()
{
    size_t headerSize = sizeof(MDRawHeader);
    size_t dirCount = 1;
    size_t dataStart = headerSize + sizeof(MDRawDirectory) * dirCount;
    std::string mapsContent = "1000-2000 r-xp 00000000 00:00 0 /system/lib/test.so\n";
    MDRawHeader header = {};
    InitMinidumpHeader(header, dirCount, headerSize);
    MDRawDirectory dirMap = {};
    dirMap.streamType = MD_STREAM_LINUX_MAPS;
    dirMap.location.dataSize = static_cast<uint32_t>(mapsContent.size());
    dirMap.location.rva = dataStart;
    std::string data(reinterpret_cast<const char*>(&header), sizeof(header));
    data += std::string(reinterpret_cast<const char*>(&dirMap), sizeof(dirMap));
    data += mapsContent;
    return data;
}

std::string BuildMinidumpWithMultiThreadNames()
{
    pid_t pid = getpid();
    size_t headerSize = sizeof(MDRawHeader);
    size_t dirCount = 1;
    size_t dataStart = headerSize + sizeof(MDRawDirectory) * dirCount;
    uint16_t threadName1[] = {u'm', u'a', u'i', u'n', 0};
    uint16_t threadName2[] = {u'w', u'o', u'r', u'k', u'e', u'r', 0};
    size_t threadNameListDataSize = sizeof(uint32_t) + sizeof(MDRawThreadName) * 2;
    size_t nameStr1Offset = dataStart + threadNameListDataSize;
    std::string mdStr1Data = BuildMDStringData(threadName1, 4);
    size_t nameStr2Offset = nameStr1Offset + mdStr1Data.size();
    std::string mdStr2Data = BuildMDStringData(threadName2, 6);
    MDRawThreadName rawThreadName1 = {};
    rawThreadName1.threadId = static_cast<uint32_t>(pid);
    rawThreadName1.rvaOfThreadName = nameStr1Offset;
    MDRawThreadName rawThreadName2 = {};
    rawThreadName2.threadId = 100; // 100:thread id
    rawThreadName2.rvaOfThreadName = nameStr2Offset;
    uint32_t numberOfThreadNames = 2;
    MDRawHeader header = {};
    InitMinidumpHeader(header, dirCount, headerSize);
    MDRawDirectory dirTN = {};
    dirTN.streamType = MD_STREAM_THREAD_NAME_LIST;
    dirTN.location.dataSize = threadNameListDataSize;
    dirTN.location.rva = dataStart;
    std::string data(reinterpret_cast<const char*>(&header), sizeof(header));
    data += std::string(reinterpret_cast<const char*>(&dirTN), sizeof(dirTN));
    data += std::string(reinterpret_cast<const char*>(&numberOfThreadNames), sizeof(numberOfThreadNames));
    data += std::string(reinterpret_cast<const char*>(&rawThreadName1), sizeof(rawThreadName1));
    data += std::string(reinterpret_cast<const char*>(&rawThreadName2), sizeof(rawThreadName2));
    data += mdStr1Data;
    data += mdStr2Data;
    return data;
}

std::string BuildFullCrashLogExcStream(pid_t pid, size_t excRva)
{
    MDExceptionStream excStream = {};
    excStream.threadId = static_cast<uint32_t>(pid);
    excStream.unusedAlignment = 0;
    excStream.exceptionRecord.exceptionCode = SIGSEGV;
    excStream.exceptionRecord.exceptionFlags = SEGV_MAPERR;
    excStream.exceptionRecord.exceptionAddress = 0x1000;
    excStream.exceptionRecord.numberParameters = 0;
    excStream.threadContext.dataSize = sizeof(MDRawContextARM64);
    excStream.threadContext.rva = excRva + sizeof(MDExceptionStream);
    std::string data(reinterpret_cast<const char*>(&excStream), sizeof(excStream));
    MDRawContextARM64 excContext = InitARM64Context(0x8000);
    data += std::string(reinterpret_cast<const char*>(&excContext), sizeof(excContext));
    return data;
}

std::string BuildFullCrashLogThreadList(pid_t pid, size_t threadListRva)
{
    size_t threadContextRva = threadListRva + sizeof(uint32_t) + sizeof(MDRawThread);
    size_t threadStackRva = threadContextRva + sizeof(MDRawContextARM64);
    MDRawThread threadEntry = {};
    threadEntry.threadId = static_cast<uint32_t>(pid);
    threadEntry.stack.startOfMemoryRange = 0x7000;
    threadEntry.stack.memory.dataSize = TEST_BUFFER_SIZE;
    threadEntry.stack.memory.rva = threadStackRva;
    threadEntry.threadContext.dataSize = sizeof(MDRawContextARM64);
    threadEntry.threadContext.rva = threadContextRva;
    uint32_t numberOfThreads = 1;
    std::string data(reinterpret_cast<const char*>(&numberOfThreads), sizeof(numberOfThreads));
    data += std::string(reinterpret_cast<const char*>(&threadEntry), sizeof(threadEntry));
    MDRawContextARM64 threadContext = InitARM64Context(0x7000, 0x2000);
    data += std::string(reinterpret_cast<const char*>(&threadContext), sizeof(threadContext));
    uint8_t stackData[TEST_BUFFER_SIZE] = {};
    for (int i = 0; i < TEST_BUFFER_SIZE; i++) {
        stackData[i] = static_cast<uint8_t>(i);
    }
    data += std::string(reinterpret_cast<const char*>(stackData), TEST_BUFFER_SIZE);
    return data;
}

std::string BuildMinidumpWithFullCrashLog()
{
    pid_t pid = getpid();
    size_t dirCount = 4;
    size_t headerSize = sizeof(MDRawHeader);
    size_t dataStart = headerSize + sizeof(MDRawDirectory) * dirCount;
    size_t excDataSize = sizeof(MDExceptionStream) + sizeof(MDRawContextARM64);
    size_t excRva = dataStart;
    size_t esrRva = excRva + excDataSize;
    size_t sysRva = esrRva + sizeof(MDRawEsrRegsInfo);
    size_t threadListRva = sysRva + sizeof(MDRawSystemInfo);
    size_t threadListDataSize = sizeof(uint32_t) + sizeof(MDRawThread);
    MDRawHeader header = {};
    InitMinidumpHeader(header, dirCount, headerSize);
    std::string streamData = BuildFullCrashLogExcStream(pid, excRva);
    streamData += BuildFullCrashLogEsrInfo(pid);
    MDRawSystemInfo sysInfo = InitSystemInfo();
    streamData += std::string(reinterpret_cast<const char*>(&sysInfo), sizeof(sysInfo));
    streamData += BuildFullCrashLogThreadList(pid, threadListRva);
    MDRawDirectory dirs[4] = {};
    dirs[0].streamType = MD_STREAM_EXCEPTION; // 0:index 0
    dirs[0].location.dataSize = excDataSize; // 0:index 0
    dirs[0].location.rva = excRva; // 0:index 0
    dirs[1].streamType = MD_STREAM_ESR_INFO; // 1:index 1
    dirs[1].location.dataSize = sizeof(MDRawEsrRegsInfo); // 1:index 1
    dirs[1].location.rva = esrRva; // 1:index 1
    dirs[2].streamType = MD_STREAM_SYSTEM_INFO; // 2:index 2
    dirs[2].location.dataSize = sizeof(MDRawSystemInfo); // 2:index 2
    dirs[2].location.rva = sysRva; // 2:index 2
    dirs[3].streamType = MD_STREAM_THREAD_LIST; // 3:index 3
    dirs[3].location.dataSize = threadListDataSize; // 3:index 3
    dirs[3].location.rva = threadListRva; // 3:index 3
    std::string data(reinterpret_cast<const char*>(&header), sizeof(header));
    for (size_t i = 0; i < dirCount; i++) {
        data += std::string(reinterpret_cast<const char*>(&dirs[i]), sizeof(MDRawDirectory));
    }
    data += streamData;
    return data;
}

} // namespace HiviewDFX
} // namespace OHOS
