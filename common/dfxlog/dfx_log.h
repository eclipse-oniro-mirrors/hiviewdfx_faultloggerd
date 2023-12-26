/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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
#ifndef DFX_LOG_H
#define DFX_LOG_H

#ifndef DFX_NO_PRINT_LOG
#ifdef DFX_LOG_HILOG_BASE
#include <hilog_base/log_base.h>
#else
#include <hilog/log.h>
#endif
#include "dfx_log_define.h"
#endif

#ifdef __cplusplus
extern "C" {
#endif

#ifndef DFX_NO_PRINT_LOG

bool CheckDebugLevel(void);
void InitDebugFd(int fd);
void SetLogLevel(const LogLevel logLevel);
LogLevel GetLogLevel(void);

int DfxLogPrint(const LogLevel logLevel, const unsigned int domain, const char* tag,
                const char *fmt, ...) __attribute__((format(printf, 4, 5)));
int DfxLogPrintV(const LogLevel logLevel, const unsigned int domain, const char* tag, const char *fmt, va_list ap);

#define DFXLOG_PRINT(prio, domain, tag, ...) DfxLogPrint(prio, domain, tag, ##__VA_ARGS__)
#define DFXLOG_PRINTV(prio, domain, tag, fmt, args) DfxLogPrintV(prio, domain, tag, fmt, args)

#define DFXLOG_DEBUG(...) DFXLOG_PRINT(LOG_DEBUG, LOG_DOMAIN, LOG_TAG, ##__VA_ARGS__)
#define DFXLOG_INFO(...) DFXLOG_PRINT(LOG_INFO, LOG_DOMAIN, LOG_TAG, ##__VA_ARGS__)
#define DFXLOG_WARN(...) DFXLOG_PRINT(LOG_WARN, LOG_DOMAIN, LOG_TAG, ##__VA_ARGS__)
#define DFXLOG_ERROR(...) DFXLOG_PRINT(LOG_ERROR, LOG_DOMAIN, LOG_TAG, ##__VA_ARGS__)
#define DFXLOG_FATAL(...) DFXLOG_PRINT(LOG_FATAL, LOG_DOMAIN, LOG_TAG, ##__VA_ARGS__)

#define LOGD(fmt, ...) \
    DFXLOG_PRINT(LOG_DEBUG, LOG_DOMAIN, LOG_TAG, "[%s:%d]" fmt, (FILENAME_), (__LINE__), ##__VA_ARGS__)
#define LOGI(fmt, ...) \
    DFXLOG_PRINT(LOG_INFO, LOG_DOMAIN, LOG_TAG, "[%s:%d]" fmt, (FILENAME_), (__LINE__), ##__VA_ARGS__)
#define LOGW(fmt, ...) \
    DFXLOG_PRINT(LOG_WARN, LOG_DOMAIN, LOG_TAG, "[%s:%d]" fmt, (FILENAME_), (__LINE__), ##__VA_ARGS__)
#define LOGE(fmt, ...) \
    DFXLOG_PRINT(LOG_ERROR, LOG_DOMAIN, LOG_TAG, "[%s:%d]" fmt, (FILENAME_), (__LINE__), ##__VA_ARGS__)
#define LOGF(fmt, ...) \
    DFXLOG_PRINT(LOG_FATAL, LOG_DOMAIN, LOG_TAG, "[%s:%d]" fmt, (FILENAME_), (__LINE__), ##__VA_ARGS__)

#else
#define DFXLOG_PRINT(prio, domain, tag, ...)
#define DFXLOG_PRINTV(prio, domain, tag, fmt, args)

#define DFXLOG_DEBUG(...)
#define DFXLOG_INFO(...)
#define DFXLOG_WARN(...)
#define DFXLOG_ERROR(...)
#define DFXLOG_FATAL(...)

#define LOGD(fmt, ...)
#define LOGI(fmt, ...)
#define LOGW(fmt, ...)
#define LOGE(fmt, ...)
#define LOGF(fmt, ...)
#endif

#ifndef LOG_CHECK_MSG
#define LOG_CHECK_MSG(condition, fmt,  ...) \
    if (__builtin_expect(!(condition), false)) { \
        DFXLOG_PRINT(LOG_ERROR, LOG_DOMAIN, LOG_TAG, " check failed: %s" fmt, #condition, ##__VA_ARGS__); \
    }
#endif

#ifndef LOG_CHECK
#define LOG_CHECK(condition) LOG_CHECK_MSG(condition, "")
#endif

#ifndef LOG_CHECK_ABORT
#define LOG_CHECK_ABORT(condition) \
    if (__builtin_expect(!(condition), false)) { \
        LOGF(" check abort: %s", #condition); \
        abort(); \
    }
#endif

#ifdef DFX_LOG_UNWIND
#define LOGU(fmt, ...) \
    DFXLOG_PRINT(LOG_INFO, LOG_DOMAIN, LOG_TAG, "[%s:%d]" fmt, (FILENAME_), (__LINE__), ##__VA_ARGS__)
#else
#define LOGU(fmt, ...)
#endif

#ifdef __cplusplus
}
#endif
#endif
