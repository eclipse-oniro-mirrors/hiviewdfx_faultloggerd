/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef MULTITHREAD_CONSTRUCTOR_H
#define MULTITHREAD_CONSTRUCTOR_H
#include <sys/types.h>
#ifdef __cplusplus
extern "C" {
#endif
int MultiThreadConstructor(const int threadNum);
int MultiThreadConstructorForThreadCrash(const int threadNum);
pid_t CreateMultiThreadProcess(int threadNum);
pid_t CreateMultiThreadForThreadCrashWithOpen(int threadNum, int openNum);
pid_t CreateMultiThreadForThreadCrash(int threadNum);
#ifdef __cplusplus
}
#endif
#endif // MULTITHREAD_CONSTRUCTOR_H
