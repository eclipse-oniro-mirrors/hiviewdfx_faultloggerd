/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef DUMPREQUEST_WAITPID_TEST_H
#define DUMPREQUEST_WAITPID_TEST_H

#ifndef __cplusplus
#include <stdbool.h>
#endif
#include <sys/types.h>

/*
 * Mirror of enum PROCESS_EXIT_STATUS in dfx_dumprequest.c, used by the gtest
 * layer which cannot see the static enum defined inside the .c file.
 */
#define DFX_TEST_PROCESS_NORMAL_EXIT 0
#define DFX_TEST_PROCESS_ABNORMAL_EXIT 1
#define DFX_TEST_PROCESS_ALARM_EXIT 2

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Thin wrappers around the static helpers in dfx_dumprequest.c. The wrappers
 * live in a C translation unit that #includes dfx_dumprequest.c, so they can
 * call the static functions; the gtest layer reaches them through these
 * extern "C" declarations.
 */
int DfxTestWaitProcessExitTimeout(pid_t pid, int timeoutMs, bool isPrvi);

#ifdef __cplusplus
}
#endif

#endif /* DUMPREQUEST_WAITPID_TEST_H */
