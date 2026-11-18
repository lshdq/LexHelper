#pragma once
#include "lexhelper/core.hpp"

namespace lexhelper::detail {
// 内部测试入口，不属于公开 API。与 save_lex 共用全部保存实现，仅显式调用才执行观察者。
// 在所有父目录对象验证完成后、新建文件前，同步调用一次；可抛异常以安全中止。
// 回调/上下文仅存于本次调用栈，无全局注册、环境开关或跨线程共享状态；回调负责其自身同步。
// 不暴露/转移任何目录句柄。生产 save_lex 始终使用空观察者。
void save_lex_with_parent_observer(const std::filesystem::path&,const Table&,
    void(*after_parent_verified)(void*),void* context);
}
