/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef DFX_SIGDUMPHANDLER_H
#define DFX_SIGDUMPHANDLER_H

#ifdef _cpluscplus
extern "C" {
#endif
/**
 * @brief Init process SIGDUMP thread
 * It will create thread for process signal 35
 * others thread in process will block sig 35
 * @return true -- success , false -- fail
 */
bool InitSigDumpHandler(void);

/**
 * @brief Deinit process SIGDUMP thread
 * It will end thread which process signal 35
 * but it will not recover block 35
 */
void DeinitSigDumpHandler(void);
#ifdef _cpluscplus
}
#endif
#endif
