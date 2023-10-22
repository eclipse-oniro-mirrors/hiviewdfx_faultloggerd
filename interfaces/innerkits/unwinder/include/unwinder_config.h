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
#ifndef UNWINDER_CONFIG_H
#define UNWINDER_CONFIG_H

#include <memory>
#include "unwind_context.h"

namespace OHOS {
namespace HiviewDFX {
class UnwinderConfig final {
public:
    static inline void SetByteOrder(int bigEndian) { bigEndian_ = bigEndian; }
    static inline int GetByteOrder() { return bigEndian_; }

    static inline void SetCachePolicy(UnwindCachePolicy policy) { cachingPolicy_ = policy; }
    static inline UnwindCachePolicy GetCachePolicy() { return cachingPolicy_; }

private:
    static int bigEndian_ = UNWIND_BYTE_ORDER;
    static UnwindCachingPolicy cachingPolicy_ = UNWIND_CACHE_NONE;
};
} // namespace HiviewDFX
} // namespace OHOS
#endif