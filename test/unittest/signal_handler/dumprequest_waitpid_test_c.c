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

#include "dumprequest_waitpid_test.h"

/*
 * Pull the whole production translation unit in so the static waitpid helpers
 * become visible to the wrappers below. Compiled as C (this is a .c file),
 * therefore C99 designated initializers used by the production code remain
 * valid and no production source file is modified.
 */
#include "dfx_dumprequest.c"

int DfxTestWaitProcessExitTimeout(pid_t pid, int timeoutMs, bool isPrvi)
{
    return WaitProcessExitTimeout(pid, timeoutMs, isPrvi);
}
