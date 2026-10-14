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

#include "dfx_guest_state.h"

#include <algorithm>
#include <cerrno>
#include <climits>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <elf.h>
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>
#include <fstream>
#include <string>

#include <securec.h>
#include "dfx_log.h"
#include "string_printf.h"

#ifndef NT_ARM_TLS
#define NT_ARM_TLS 0x401 // aarch64 TLS register set
#endif

namespace OHOS {
namespace HiviewDFX {
namespace {
#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD002D11
#define LOG_TAG "DfxGuestState"

// bionic aarch64 tls_defines.h: slot of the native bridge guest state pointer.
constexpr size_t TLS_SLOT_NATIVE_BRIDGE_GUEST_STATE = 10;
// frameworks/libs/native_bridge_support guest_state_accessor/accessor.h.
constexpr uint64_t NATIVE_BRIDGE_GUEST_STATE_SIGNATURE = 0x5349524542524542ULL; // "BERBERIS"
constexpr uint32_t NATIVE_BRIDGE_ARCH_ARM = 1;
constexpr size_t MAX_BLOB_SCAN_BYTES = 8192;

struct GuestStateHeader {
    uint64_t signature;
    uint32_t hostArch;
    uint32_t guestArch;
    uint64_t dataPtr;
    uint64_t dataSize;
};

bool ReadWord(pid_t tid, uintptr_t addr, uint64_t& val)
{
    errno = 0;
    long word = ptrace(PTRACE_PEEKDATA, tid, reinterpret_cast<void*>(addr), nullptr);
    if (errno != 0) {
        return false;
    }
    val = static_cast<uint64_t>(static_cast<uintptr_t>(word));
    return true;
}

bool ReadMem(pid_t tid, uintptr_t addr, void* buf, size_t size)
{
    auto* out = static_cast<uint8_t*>(buf);
    size_t done = 0;
    while (done < size) {
        uint64_t word = 0;
        if (!ReadWord(tid, addr + done, word)) {
            return false;
        }
        size_t chunk = std::min(sizeof(word), size - done);
        if (memcpy_s(out + done, size - done, &word, chunk) != 0) {
            return false;
        }
        done += chunk;
    }
    return true;
}

// Guest mapping tables of the target process: the arm32 guest world lives
// below 4G, so its code pointers must fall into an executable mapping below
// 4G and its stack/data pointers into a writable one. Host pointer halves
// truncated to 32 bits (observed false positives) fail exactly these checks.
struct GuestMaps {
    std::vector<std::pair<uint64_t, uint64_t>> exec32;
    std::vector<std::pair<uint64_t, uint64_t>> rw32;
};

static GuestMaps& GetGuestMaps(pid_t tid)
{
    static GuestMaps maps;
    static bool loaded = false;
    if (loaded) {
        return maps;
    }
    loaded = true;
    std::ifstream file(StringPrintf("/proc/%d/maps", static_cast<int>(tid)));
    std::string line;
    while (std::getline(file, line)) {
        unsigned long long start = 0;
        unsigned long long end = 0;
        char perms[5] = {0}; // 5: "rwxp" + NUL
        if (sscanf(line.c_str(), "%llx-%llx %4s", &start, &end, perms) != 3) { // 3: parsed fields
            continue;
        }
        if (end > 0x100000000ULL) { // guest world only: below 4G
            continue;
        }
        if (perms[0] == 'r' && perms[3] == 'p') { // private readable mapping
            if (perms[2] == 'x') {
                maps.exec32.emplace_back(start, end);
            } else if (perms[1] == 'w') {
                maps.rw32.emplace_back(start, end);
            }
        }
    }
    return maps;
}

static bool InRangeList(uint64_t addr, const std::vector<std::pair<uint64_t, uint64_t>>& ranges)
{
    for (const auto& r : ranges) {
        if (addr >= r.first && addr < r.second) {
            return true;
        }
    }
    return false;
}

// Self-consistency check for a candidate arm32 register window. strict:
// additionally require pc/lr inside guest-executable and sp inside
// guest-writable mappings (needs the maps table of the target).
bool IsValidArm32Window(const uint32_t r[GUEST_ARM_LAST], const GuestMaps* maps = nullptr)
{
    uint32_t sp = r[GUEST_ARM_SP];
    uint32_t lr = r[GUEST_ARM_LR];
    uint32_t pc = r[GUEST_ARM_PC];
    if (sp == 0 || pc == 0 || lr == 0) {
        return false;
    }
    if ((sp & 0x3) != 0 || sp < 0x1000) {
        return false;
    }
    if (pc < 0x1000) {
        return false;
    }
    if (maps == nullptr) {
        return true;
    }
    if (!InRangeList(pc & ~1ULL, maps->exec32) || !InRangeList(lr & ~1ULL, maps->exec32)) {
        return false;
    }
    if (!InRangeList(sp, maps->rw32)) {
        return false;
    }
    if (r[GUEST_ARM_FP] != 0 && !InRangeList(r[GUEST_ARM_FP], maps->rw32) &&
        !InRangeList(r[GUEST_ARM_FP] & ~1ULL, maps->exec32)) {
        return false;
    }
    return true;
}

// The blob layout is private to the translator. The arm32 register set is
// stored as 16 consecutive u32 (NativeBridgeGuestRegsArm), preceded by an
// implementation-defined tag/version prefix; locate it by window validation.
// Strict pass (mapping-checked) first, weak pass as fallback.
bool LocateArm32Regs(const uint8_t* blob, size_t size, GuestArm32Regs& regs, const GuestMaps* maps)
{
    if (size < GUEST_ARM_LAST * sizeof(uint32_t)) {
        return false;
    }
    size_t limit = std::min(size, MAX_BLOB_SCAN_BYTES) - GUEST_ARM_LAST * sizeof(uint32_t);
    for (int pass = 0; pass < 2; pass++) { // 2: strict then weak
        const GuestMaps* useMaps = (pass == 0) ? maps : nullptr;
        for (size_t off = 0; off <= limit; off += sizeof(uint32_t)) {
            uint32_t r[GUEST_ARM_LAST];
            if (memcpy_s(r, sizeof(r), blob + off, sizeof(r)) != 0) {
                return false;
            }
            if (!IsValidArm32Window(r, useMaps)) {
                continue;
            }
            for (size_t i = 0; i < GUEST_ARM_LAST; i++) {
                regs.r[i] = r[i];
            }
            // GUESTDBG: temporary printf diagnostics, remove later
            fprintf(stderr, "GUESTDBG regs window at blob offset %zu (%s)\n", off,
                pass == 0 ? "strict" : "weak");
            return true;
        }
    }
    return false;
}
} // namespace

// ---------------------------------------------------------------------------
// GUESTDBG bring-up diagnostics (temporary, remove after the mechanism of
// this container is confirmed and folded into the fast path).
//
// Facts so far: the AOSP path (TLS slot 10) yields NULL here; the container's
// own crash_dump64 disassembly instead issues PTRACE_GETREGSET for custom
// note types NT 0x409 / 0x40A (8 bytes each) next to NT_ARM_TLS, and finally
// read()s a ~4774-byte blob whose first u32 is a 1..5 type field
// (NATIVE_BRIDGE_ARCH_*). The discovery below covers every plausible layout
// in one pass:
//   A. custom regsets -> value is header ptr / ptr-to-ptr / inline regs / fd
//   B. TLS slot 10 and the whole TLS block, chased the same way
// All decisions are printed for the first translated thread only; the blob
// head is dumped as hex so the register window can be located offline even
// if the in-tool scan misses.
// ---------------------------------------------------------------------------

static bool DumpRegsLine(pid_t tid, const GuestArm32Regs& regs, const char* via)
{
    fprintf(stderr, "GUESTDBG[%d] OK %s pc=0x%x sp=0x%x lr=0x%x fp=0x%x r0=0x%x r7=0x%x\n",
        (int)tid, via, regs.r[GUEST_ARM_PC], regs.r[GUEST_ARM_SP], regs.r[GUEST_ARM_LR],
        regs.r[GUEST_ARM_FP], regs.r[GUEST_ARM_R0], regs.r[GUEST_ARM_R7]);
    return true;
}

static void HexDumpLine(pid_t tid, const char* tag, const uint8_t* data, size_t size, size_t maxBytes)
{
    size_t lim = size < maxBytes ? size : maxBytes;
    std::string hex;
    char one[8];
    for (size_t i = 0; i < lim; i++) {
        snprintf(one, sizeof(one), "%02x", data[i]);
        hex += one;
        if ((i & 0xf) == 0xf) {
            hex += '|';
        }
    }
    fprintf(stderr, "GUESTDBG[%d] %s(%zu)=%s\n", (int)tid, tag, size, hex.c_str());
}

static bool ProbeGuestHeader(pid_t tid, uintptr_t candidate, GuestStateHeader& header)
{
    if (static_cast<uint64_t>(candidate) < 0x1000 || static_cast<uint64_t>(candidate) >= (1ULL << 48)) {
        return false;
    }
    for (uintptr_t addr : {candidate, candidate + sizeof(uintptr_t)}) {
        if (ReadMem(tid, addr, &header, sizeof(header)) &&
            header.signature == NATIVE_BRIDGE_GUEST_STATE_SIGNATURE) {
            return true;
        }
    }
    return false;
}

static bool DumpGuestRegsFromBlob(pid_t tid, const GuestStateHeader& header, GuestArm32Regs& regs,
    bool verbose, const char* via)
{
    if (header.guestArch != NATIVE_BRIDGE_ARCH_ARM) {
        if (verbose) {
            fprintf(stderr, "GUESTDBG[%d] header guestArch=%u not ARM (%s)\n",
                (int)tid, header.guestArch, via);
        }
        return false;
    }
    if (header.dataPtr == 0 || header.dataSize == 0 || header.dataSize > 64 * 1024) {
        if (verbose) {
            fprintf(stderr, "GUESTDBG[%d] invalid blob ptr=0x%llx size=%llu (%s)\n", (int)tid,
                (unsigned long long)header.dataPtr, (unsigned long long)header.dataSize, via);
        }
        return false;
    }
    size_t blobSize = static_cast<size_t>(header.dataSize);
    std::vector<uint8_t> blob(std::min(blobSize, MAX_BLOB_SCAN_BYTES));
    if (!ReadMem(tid, static_cast<uintptr_t>(header.dataPtr), blob.data(), blob.size())) {
        if (verbose) {
            fprintf(stderr, "GUESTDBG[%d] blob read failed errno=%d (%s)\n", (int)tid, errno, via);
        }
        return false;
    }
    if (verbose) {
        HexDumpLine(tid, "blob", blob.data(), blob.size(), 256);
    }
    if (!LocateArm32Regs(blob.data(), blob.size(), regs, &GetGuestMaps(tid))) {
        if (verbose) {
            fprintf(stderr, "GUESTDBG[%d] regs scan failed (blobSize=%zu, %s)\n",
                (int)tid, blob.size(), via);
        }
        return false;
    }
    return DumpRegsLine(tid, regs, via);
}

// Chase one candidate value through every plausible shape: direct header
// pointer, pointer to a structure holding the header pointer (one level),
// small integer usable as an fd of the blob, or nothing.
static bool ChaseGuestValue(pid_t tid, uint64_t v, GuestArm32Regs& regs, bool verbose, const char* via)
{
    if (v < 0x1000 || v >= (1ULL << 48)) {
        return false;
    }
    GuestStateHeader header;
    if (ProbeGuestHeader(tid, static_cast<uintptr_t>(v), header)) {
        if (verbose) {
            fprintf(stderr, "GUESTDBG[%d] FOUND header at 0x%llx (%s) host=%u guest=%u "
                "data=0x%llx size=%llu\n", (int)tid, (unsigned long long)v, via,
                header.hostArch, header.guestArch, (unsigned long long)header.dataPtr,
                (unsigned long long)header.dataSize);
        }
        return DumpGuestRegsFromBlob(tid, header, regs, verbose, via);
    }
    // one level of indirection: chase the first 8 qwords behind the pointer
    uint8_t buf[64] = {0};
    if (ReadMem(tid, static_cast<uintptr_t>(v), buf, sizeof(buf))) {
        if (verbose) {
            HexDumpLine(tid, "deref", buf, sizeof(buf), 64);
        }
        for (size_t off = 0; off + 8 <= sizeof(buf); off += 8) {
            uint64_t w;
            memcpy(&w, buf + off, sizeof(w));
            if (w < 0x1000 || w >= (1ULL << 48) || w == v) {
                continue;
            }
            if (ProbeGuestHeader(tid, static_cast<uintptr_t>(w), header)) {
                if (verbose) {
                    fprintf(stderr, "GUESTDBG[%d] FOUND header at 0x%llx via 0x%llx+%zu (%s)\n",
                        (int)tid, (unsigned long long)w, (unsigned long long)v, off, via);
                }
                return DumpGuestRegsFromBlob(tid, header, regs, verbose, via);
            }
        }
    }
    return false;
}

// Some kernels expose the full guest state inline in the custom regset.
static bool TryInlineRegs(pid_t tid, const uint8_t* buf, size_t size, GuestArm32Regs& regs,
    bool verbose, const char* via)
{
    if (size < GUEST_ARM_LAST * sizeof(uint32_t)) {
        return false;
    }
    if (LocateArm32Regs(buf, size, regs, &GetGuestMaps(tid))) {
        return DumpRegsLine(tid, regs, via);
    }
    return false;
}

// Scan a memory buffer for a strict-validated arm32 window (index of match
// returned via off).
static bool ScanWindowIn(const uint8_t* data, size_t size, const GuestMaps* maps,
    size_t& offOut, GuestArm32Regs& regs)
{
    if (size < GUEST_ARM_LAST * sizeof(uint32_t)) {
        return false;
    }
    for (size_t off = 0; off + GUEST_ARM_LAST * sizeof(uint32_t) <= size; off += sizeof(uint32_t)) {
        GuestArm32Regs probe = {};
        memcpy(probe.r, data + off, sizeof(probe.r));
        if (IsValidArm32Window(probe.r, maps)) {
            offOut = off;
            regs = probe;
            return true;
        }
    }
    return false;
}

// Read size bytes at addr and scan them for a strict window.
static bool ScanMemoryAt(pid_t tid, uintptr_t addr, size_t size, const GuestMaps* maps,
    GuestArm32Regs& regs, const char* via, bool verbose)
{
    std::vector<uint8_t> buf(size, 0);
    if (!ReadMem(tid, addr, buf.data(), size)) {
        return false;
    }
    size_t off = 0;
    if (ScanWindowIn(buf.data(), buf.size(), maps, off, regs)) {
        fprintf(stderr, "GUESTDBG[%d] window at 0x%llx+%zu via %s\n", (int)tid,
            (unsigned long long)addr, off, via);
        return DumpRegsLine(tid, regs, via);
    }
    if (verbose) {
        HexDumpLine(tid, "chase", buf.data(), buf.size(), 256);
    }
    return false;
}

static bool DiscoverGuestStateByTlsScan(pid_t tid, uintptr_t tpidr, GuestArm32Regs& regs)
{
    // Full diagnostics for the first translated thread and for the first
    // syscall-parked thread (the bulk of threads); the rest run quietly.
    static bool firstDone = false;
    static bool parkedDone = false;
    bool verbose = !firstDone;
    firstDone = true;

    const GuestMaps* maps = &GetGuestMaps(tid);

    // NT probe: custom regsets first; every plausible value is chased both as
    // a header pointer and as a pointer to memory holding the register file.
    static const int probeNts[] = {0x409, 0x40a, 0x40b, 0x40c, 0x404, 0x405, 0x406, 0x407, 0x408};
    uint32_t syscallNr = 0;
    bool isParked = false;
    for (int nt : probeNts) {
        uint8_t buf[256] = {0};
        struct iovec iov;
        iov.iov_base = buf;
        iov.iov_len = sizeof(buf);
        errno = 0;
        long rc = ptrace(PTRACE_GETREGSET, tid, nt, &iov);
        if (rc != 0) {
            if (verbose) {
                fprintf(stderr, "GUESTDBG[%d] NT 0x%x rc=%ld errno=%d\n", (int)tid, nt, rc, errno);
            }
            continue;
        }
        size_t len = iov.iov_len;
        if (len > sizeof(buf)) {
            len = sizeof(buf);
        }
        if (nt == 0x404 && len >= 4) {
            memcpy(&syscallNr, buf, sizeof(syscallNr));
        }
        if (verbose) {
            fprintf(stderr, "GUESTDBG[%d] NT 0x%x OK iovlen=%zu\n", (int)tid, nt, iov.iov_len);
            HexDumpLine(tid, "regset", buf, len, 64);
        }
        char via[32];
        snprintf(via, sizeof(via), "NT0x%x", nt);
        if (TryInlineRegs(tid, buf, len, regs, verbose, via)) {
            return true;
        }
        for (size_t off = 0; off + 8 <= (len < 32 ? len : 32); off += 8) {
            uint64_t v;
            memcpy(&v, buf + off, sizeof(v));
            if (ChaseGuestValue(tid, v, regs, verbose, via)) {
                return true;
            }
            if (v >= 0x1000 && v < (1ULL << 48) &&
                ScanMemoryAt(tid, static_cast<uintptr_t>(v), 512, maps, regs, via, false)) {
                return true;
            }
        }
    }
    isParked = (syscallNr == 22 || syscallNr == 98 || syscallNr == 220 || syscallNr == 281); // futex/wait family
    if (isParked && !parkedDone) {
        parkedDone = true;
        verbose = true;
        fprintf(stderr, "GUESTDBG[%d] parked thread (syscall %u), verbose\n", (int)tid, syscallNr);
    }

    // Fast path: the qword index inside the tpidr structure whose target held
    // the register file on an earlier thread.
    static int64_t regfileField = INT64_MIN;
    if (regfileField != INT64_MIN) {
        uint64_t v = 0;
        if (ReadWord(tid, tpidr + static_cast<int64_t>(regfileField), v) &&
            v >= 0x1000 && v < (1ULL << 48) &&
            ScanMemoryAt(tid, static_cast<uintptr_t>(v), 512, maps, regs, "fieldcached", false)) {
            return true;
        }
        regfileField = INT64_MIN;
    }

    // Host stack around sp: strict window only (weak matches are logged by
    // the caller when everything failed; they never produce frames).
    uint64_t hostRegs[36] = {0}; // 36: covers arm64 user_pt_regs (x31+sp+pc)
    struct iovec prIov;
    prIov.iov_base = hostRegs;
    prIov.iov_len = sizeof(hostRegs);
    if (ptrace(PTRACE_GETREGSET, tid, NT_PRSTATUS, &prIov) == 0 &&
        prIov.iov_len >= 33 * sizeof(uint64_t)) { // 33: x[31] + sp + pc
        uintptr_t hostSp = static_cast<uintptr_t>(hostRegs[31]);
        uintptr_t hostPc = static_cast<uintptr_t>(hostRegs[32]);
        static constexpr int64_t STACK_BACK = 0x2000;
        static constexpr int64_t STACK_FWD = 0x1000;
        std::vector<uint8_t> mem(static_cast<size_t>(STACK_BACK + STACK_FWD), 0);
        size_t got = 0;
        while (got < mem.size()) {
            uint64_t w = 0;
            if (!ReadWord(tid, hostSp - STACK_BACK + static_cast<int64_t>(got), w)) {
                break;
            }
            memcpy(mem.data() + got, &w, sizeof(w));
            got += sizeof(w);
        }
        if (verbose) {
            fprintf(stderr, "GUESTDBG[%d] stackscan hostPc=0x%llx hostSp=0x%llx got %zu/%zu\n",
                (int)tid, (unsigned long long)hostPc, (unsigned long long)hostSp, got, mem.size());
            for (size_t off = 0; off + 64 <= got; off += 64) {
                bool nonzero = false;
                for (size_t i = off; i < off + 64; i++) {
                    if (mem[i] != 0) {
                        nonzero = true;
                        break;
                    }
                }
                if (nonzero) {
                    char head[40];
                    snprintf(head, sizeof(head), "stk[%lld]",
                        static_cast<long long>(off) - static_cast<long long>(STACK_BACK));
                    HexDumpLine(tid, head, mem.data() + off, 64, 64);
                }
            }
        }
        size_t winOff = 0;
        if (ScanWindowIn(mem.data(), got, maps, winOff, regs)) {
            fprintf(stderr, "GUESTDBG[%d] stackscan window at hostSp%+lld (strict)\n", (int)tid,
                static_cast<long long>(winOff) - static_cast<long long>(STACK_BACK));
            return DumpRegsLine(tid, regs, "stackscan");
        }
        // every plausible stack pointer is also chased (register files are
        // often heap allocated and referenced from wrapper frames)
        for (size_t off = 0; off + 8 <= got; off += 8) {
            uint64_t v;
            memcpy(&v, mem.data() + off, sizeof(v));
            if (v < 0x1000 || v >= (1ULL << 48)) {
                continue;
            }
            char via[32];
            snprintf(via, sizeof(via), "stkptr%+lld",
                static_cast<long long>(off) - static_cast<long long>(STACK_BACK));
            if (ChaseGuestValue(tid, v, regs, verbose, via)) {
                return true;
            }
            if (ScanMemoryAt(tid, static_cast<uintptr_t>(v), 512, maps, regs, via,
                verbose && off < 0x400)) {
                return true;
            }
        }
    }

    // Translator per-thread structure at tpidr: window scan plus a chase of
    // every pointer field; a hit also records which field pointed at the
    // register file for the fast path of the remaining threads.
    static constexpr int64_t SCAN_BACK = 0x1000;
    static constexpr int64_t SCAN_FWD = 0x8000;
    {
        std::vector<uint8_t> mem(static_cast<size_t>(SCAN_BACK + SCAN_FWD), 0);
        size_t got = 0;
        while (got < mem.size()) {
            uint64_t w = 0;
            if (!ReadWord(tid, tpidr - SCAN_BACK + static_cast<int64_t>(got), w)) {
                break;
            }
            memcpy(mem.data() + got, &w, sizeof(w));
            got += sizeof(w);
        }
        if (verbose) {
            fprintf(stderr, "GUESTDBG[%d] memscan got %zu/%zu bytes around tpidr\n",
                (int)tid, got, mem.size());
            for (size_t off = 0; off + 64 <= got; off += 64) {
                bool nonzero = false;
                for (size_t i = off; i < off + 64; i++) {
                    if (mem[i] != 0) {
                        nonzero = true;
                        break;
                    }
                }
                if (nonzero) {
                    char head[40];
                    snprintf(head, sizeof(head), "mem[%lld]",
                        static_cast<long long>(off) - static_cast<long long>(SCAN_BACK));
                    HexDumpLine(tid, head, mem.data() + off, 64, 64);
                }
            }
        }
        if (got >= GUEST_ARM_LAST * sizeof(uint32_t)) {
            size_t winOff = 0;
            if (ScanWindowIn(mem.data(), got, maps, winOff, regs)) {
                fprintf(stderr, "GUESTDBG[%d] memscan window at tpidr%+lld (strict)\n", (int)tid,
                    static_cast<long long>(winOff) - static_cast<long long>(SCAN_BACK));
                return DumpRegsLine(tid, regs, "memscan");
            }
            int chased = 0;
            for (size_t off = 0; off + 8 <= got; off += 8) {
                uint64_t v;
                memcpy(&v, mem.data() + off, sizeof(v));
                if (v < 0x1000 || v >= (1ULL << 48)) {
                    continue;
                }
                char via[40];
                snprintf(via, sizeof(via), "field%+lld",
                    static_cast<long long>(off) - static_cast<long long>(SCAN_BACK));
                bool dumpThis = verbose && chased < 12;
                if (ScanMemoryAt(tid, static_cast<uintptr_t>(v), 512, maps, regs, via, dumpThis)) {
                    regfileField = static_cast<int64_t>(off) - SCAN_BACK;
                    fprintf(stderr, "GUESTDBG[%d] regfile field index %lld cached\n",
                        (int)tid, (long long)regfileField);
                    return true;
                }
                if (ChaseGuestValue(tid, v, regs, verbose, via)) {
                    return true;
                }
                chased++;
            }
            // BERBERIS header embedded anywhere in the region
            for (size_t off = 0; off + sizeof(GuestStateHeader) <= got; off += 8) {
                uint64_t sig;
                memcpy(&sig, mem.data() + off, sizeof(sig));
                if (sig == NATIVE_BRIDGE_GUEST_STATE_SIGNATURE) {
                    GuestStateHeader header;
                    memcpy(&header, mem.data() + off, sizeof(header));
                    if (verbose) {
                        fprintf(stderr, "GUESTDBG[%d] memscan header at tpidr%+lld "
                            "host=%u guest=%u data=0x%llx size=%llu\n", (int)tid,
                            static_cast<long long>(off) - static_cast<long long>(SCAN_BACK),
                            header.hostArch, header.guestArch,
                            (unsigned long long)header.dataPtr,
                            (unsigned long long)header.dataSize);
                    }
                    if (DumpGuestRegsFromBlob(tid, header, regs, verbose, "memhdr")) {
                        return true;
                    }
                }
            }
        }
    }

    if (verbose) {
        fprintf(stderr, "GUESTDBG[%d] discovery exhausted, no strict guest state found\n", (int)tid);
    }
    return false;
}

bool DfxGuestState::IsTranslatedThread(pid_t tid)
{
    std::string exePath = StringPrintf("/proc/%d/exe", static_cast<int>(tid));
    char buf[PATH_MAX] = {0};
    ssize_t len = readlink(exePath.c_str(), buf, sizeof(buf) - 1);
    if (len <= 0) {
        return false;
    }
    buf[len] = '\0';
    std::string name(buf);
    bool translated = name.find("ubt_") != std::string::npos;
    // GUESTDBG: temporary printf diagnostics for bring-up, remove later
    fprintf(stderr, "GUESTDBG[%d] exe=%s translated=%d\n", (int)tid, buf, (int)translated);
    return translated;
}

bool DfxGuestState::ReadGuestArm32Regs(pid_t tid, GuestArm32Regs& regs)
{
    uint64_t tpidr = 0;
    struct iovec iov;
    iov.iov_base = &tpidr;
    iov.iov_len = sizeof(tpidr);
    if (ptrace(PTRACE_GETREGSET, tid, NT_ARM_TLS, &iov) != 0) {
        // GUESTDBG: temporary printf diagnostics for bring-up, remove later
        fprintf(stderr, "GUESTDBG[%d] NT_ARM_TLS failed errno=%d\n", (int)tid, errno);
        DFXLOGI("GuestState: read NT_ARM_TLS failed, tid=%{public}d, errno=%{public}d",
            static_cast<int>(tid), errno);
        return false;
    }
    fprintf(stderr, "GUESTDBG[%d] tpidr=0x%llx\n", (int)tid, (unsigned long long)tpidr);
    uint64_t headerPtr = 0;
    if (!ReadWord(tid, static_cast<uintptr_t>(tpidr) +
        TLS_SLOT_NATIVE_BRIDGE_GUEST_STATE * sizeof(uintptr_t), headerPtr)) {
        fprintf(stderr, "GUESTDBG[%d] TLS slot10 read failed errno=%d\n", (int)tid, errno);
        DFXLOGI("GuestState: read TLS slot failed, tid=%{public}d", static_cast<int>(tid));
        return false;
    }
    if (headerPtr == 0) {
        fprintf(stderr, "GUESTDBG[%d] TLS slot10 is NULL, discovering...\n", (int)tid);
        return DiscoverGuestStateByTlsScan(tid, static_cast<uintptr_t>(tpidr), regs);
    }
    GuestStateHeader header;
    if (!ReadMem(tid, static_cast<uintptr_t>(headerPtr), &header, sizeof(header))) {
        fprintf(stderr, "GUESTDBG[%d] header read failed at 0x%llx errno=%d\n",
            (int)tid, (unsigned long long)headerPtr, errno);
        DFXLOGI("GuestState: read header failed, tid=%{public}d", static_cast<int>(tid));
        return false;
    }
    fprintf(stderr, "GUESTDBG[%d] hdr@0x%llx sig=0x%llx host=%u guest=%u data=0x%llx size=%llu\n",
        (int)tid, (unsigned long long)headerPtr, (unsigned long long)header.signature,
        header.hostArch, header.guestArch, (unsigned long long)header.dataPtr,
        (unsigned long long)header.dataSize);
    if (header.signature != NATIVE_BRIDGE_GUEST_STATE_SIGNATURE ||
        header.guestArch != NATIVE_BRIDGE_ARCH_ARM) {
        DFXLOGI("GuestState: header mismatch, sig=0x%{public}" PRIx64 ", guestArch=%{public}u",
            header.signature, header.guestArch);
        return false;
    }
    if (header.dataPtr == 0 || header.dataSize == 0 ||
        header.dataSize > 64 * 1024) { // 64 * 1024: sanity bound of the guest state blob
        DFXLOGI("GuestState: invalid blob, ptr=0x%{public}" PRIx64 ", size=%{public}zu",
            header.dataPtr, static_cast<size_t>(header.dataSize));
        return false;
    }

    size_t blobSize = static_cast<size_t>(header.dataSize);
    std::vector<uint8_t> blob(std::min(blobSize, MAX_BLOB_SCAN_BYTES));
    if (!ReadMem(tid, static_cast<uintptr_t>(header.dataPtr), blob.data(), blob.size())) {
        fprintf(stderr, "GUESTDBG[%d] blob read failed errno=%d\n", (int)tid, errno);
        DFXLOGI("GuestState: read blob failed, tid=%{public}d", static_cast<int>(tid));
        return false;
    }
    {
        char hex[32 * 3 + 8];
        size_t n = 0;
        for (size_t i = 0; i < 32 && i < blob.size(); i++) {
            n += (size_t)snprintf(hex + n, sizeof(hex) - n, "%02x ", blob[i]);
        }
        fprintf(stderr, "GUESTDBG[%d] blob[0..32)=%s\n", (int)tid, hex);
    }
    if (!LocateArm32Regs(blob.data(), blob.size(), regs, &GetGuestMaps(tid))) {
        fprintf(stderr, "GUESTDBG[%d] regs scan failed (blobSize=%zu)\n", (int)tid, blob.size());
        DFXLOGI("GuestState: arm32 regs not found in blob, tid=%{public}d", static_cast<int>(tid));
        return false;
    }
    fprintf(stderr, "GUESTDBG[%d] guest pc=0x%x sp=0x%x lr=0x%x\n",
        (int)tid, regs.r[GUEST_ARM_PC], regs.r[GUEST_ARM_SP], regs.r[GUEST_ARM_LR]);
    return true;
}
} // namespace HiviewDFX
} // namespace OHOS
