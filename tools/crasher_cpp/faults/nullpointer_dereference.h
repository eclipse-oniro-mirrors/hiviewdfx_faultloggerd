/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef DFX_FAULTS_NULL_POINTER_DEREFERENCE_H
#define DFX_FAULTS_NULL_POINTER_DEREFERENCE_H

#include <cinttypes>

int TestNullPointerDereferenceCrash0(void);
int TestNullPointerDereferenceCrash1(void);
int TestNullPointerDereferenceCrash2(void);
int TestNullPointerDereferenceCrash3(void);

namespace OHOS {
namespace HiviewDFX {
class NullPointerDereference {
public:
    NullPointerDereference() {};
    ~NullPointerDereference() {};

    void Print() const;
    void PrintMemberValue() const;

private:
    int intTypeValue0_ = 666;
    int intTypeValue_ = 666;
};
} // namespace HiviewDFX
} // namespace OHOS
#endif
