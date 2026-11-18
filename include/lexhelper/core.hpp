#pragma once
#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace lexhelper {
struct Entry {
    std::string code;
    std::u16string text;
    std::uint16_t weight{}; // lex 候选代价：越小越靠前；相同值保持输入顺序。
    bool operator==(const Entry&) const = default;
};
using Table = std::vector<Entry>;
struct ImportResult { Table entries; std::string source; };
ImportResult import_file(const std::filesystem::path&);
Table read_lex(std::span<const std::byte>);
std::vector<std::byte> write_lex(const Table&);
// 相对已验证的父目录对象原子 FILE_CREATE（CREATE_NEW），不覆盖文件、目录、链接或输入。
// 祖先名字/重解析属性并发改变时拒绝或仍只作用于已绑定对象；失败按拥有句柄尽力删除本次制品。
void save_lex(const std::filesystem::path&, const Table&);
// 补充内存接口，供可复用测试和不落盘预览使用；所有输入有大小上限。
Table read_wbc3(std::span<const std::byte>);
Table read_cwb(std::span<const std::byte>);
Table read_text(std::span<const std::byte>);
}
