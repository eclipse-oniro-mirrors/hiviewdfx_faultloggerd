/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#ifndef DFX_MUSL_CUTIL_H
#define DFX_MUSL_CUTIL_H

#include <stddef.h>
#include <stdint.h>
#include "stdbool.h"
#include "dfx_define.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ENABLE_MUSL_CUTIL
int GetProcStatus(struct ProcInfo* procInfo)
{
    procInfo->pid = getpid();
    procInfo->tid = gettid();
    procInfo->ppid = getppid();
    procInfo->ns = false;

    char buf[STATUS_LINE_SIZE];
    FILE *fp = fopen(PROC_SELF_STATUS_PATH, "r");
    if (fp == NULL) {
        return -1;
    }

    int p = 0, pp = 0, t = 0;
    while (!feof(fp)) {
        if (fgets(buf, STATUS_LINE_SIZE, fp) == NULL) {
            fclose(fp);
            return -1;
        }

        if (strncmp(buf, PID_STR_NAME, strlen(PID_STR_NAME)) == 0) {
            // Pid:    1892
            (void)sscanf(buf, "%*[^0-9]%d", &p);
            procInfo->pid = p;
            if (procInfo->pid == getpid()) {
                procInfo->ns = false;
                break;
            }
            procInfo->ns = true;
            continue;
        }

        if (strncmp(buf, PPID_STR_NAME, strlen(PPID_STR_NAME)) == 0) {
            // PPid:   240
            (void)sscanf(buf, "%*[^0-9]%d", &pp);
            procInfo->ppid = pp;
            continue;
        }

        // NSpid:  1892    1
        if (strncmp(buf, NSPID_STR_NAME, strlen(NSPID_STR_NAME)) == 0) {
            (void)sscanf(buf, "%*[^0-9]%d%*[^0-9]%d", &p, &t);
            procInfo->tid = t;
            break;
        }
    }
    (void)fclose(fp);
    return 0;
}

bool ReadStringFromFile(const char* path, char* dst, size_t dstSz)
{
    char name[NAME_LEN];
    char nameFilter[NAME_LEN];
    memset(name, 0, sizeof(name));
    memset(nameFilter, 0, sizeof(nameFilter));

    int fd = -1;
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        return false;
    }

    if (read(fd, name, NAME_LEN -1) == -1) {
        close(fd);
        return false;
    }

    char* p = name;
    int i = 0;
    while (*p != '\0') {
        if ((*p == '\n') || (i == NAME_LEN)) {
            break;
        }
        nameFilter[i] = *p;
        p++, i++;
    }
    nameFilter[NAME_LEN - 1] = '\0';

    size_t cpyLen = strlen(nameFilter) + 1;
    if (cpyLen > dstSz) {
        cpyLen = dstSz;
    }
    memcpy(dst, nameFilter, cpyLen);
    close(fd);
    return true;
}

bool GetThreadName(char* buffer, size_t bufferSz)
{
    char path[NAME_LEN];
    memset(path, '\0', sizeof(path));
    if (snprintf(path, sizeof(path) - 1, "/proc/%d/comm", getpid()) <= 0) {
        return false;
    }
    return ReadStringFromFile(path, buffer, bufferSz);
}

bool GetProcessName(char* buffer, size_t bufferSz)
{
    char path[NAME_LEN];
    memset(path, '\0', sizeof(path));
    if (snprintf(path, sizeof(path) - 1, "/proc/%d/cmdline", getpid()) <= 0) {
        return false;
    }
    return ReadStringFromFile(path, buffer, bufferSz);
}

uint64_t GetTimeMilliseconds(void)
{
    struct timeval time;
    gettimeofday(&time, NULL);
    return ((uint64_t)time.tv_sec * 1000) + // 1000 : second to millisecond convert ratio
        (((uint64_t)time.tv_usec) / 1000); // 1000 : microsecond to millisecond convert ratio
}

#endif
#ifdef __cplusplus
}
#endif
#endif