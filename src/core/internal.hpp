#pragma once
#include "lexhelper/core.hpp"
#include <algorithm>
#include <limits>
#include <stdexcept>
#include <string_view>

namespace lexhelper::detail {
inline constexpr std::size_t max_file = 128u * 1024u * 1024u;
inline constexpr std::size_t max_wbc = 64u * 1024u * 1024u;
inline constexpr std::size_t max_entries = 1'000'000;
[[noreturn]] inline void fail(const char* s) { throw std::runtime_error(s); }
inline void need(bool ok, const char* s) { if (!ok) fail(s); }
inline void range(std::span<const std::byte> b, std::size_t p, std::size_t n) {
    need(p <= b.size() && n <= b.size() - p, "输入截断或偏移越界");
}
inline std::uint16_t u16(std::span<const std::byte> b, std::size_t p) {
    range(b,p,2); return std::to_integer<std::uint16_t>(b[p]) |
        static_cast<std::uint16_t>(std::to_integer<std::uint16_t>(b[p+1]) << 8);
}
inline std::uint32_t u32(std::span<const std::byte> b, std::size_t p) {
    return static_cast<std::uint32_t>(u16(b,p)) | (static_cast<std::uint32_t>(u16(b,p+2)) << 16);
}
inline bool magic(std::span<const std::byte> b, std::size_t p, std::string_view s) {
    if (p > b.size() || s.size() > b.size()-p) return false;
    for (std::size_t i=0;i<s.size();++i) if (std::to_integer<unsigned char>(b[p+i]) != static_cast<unsigned char>(s[i])) return false;
    return true;
}
inline void put16(std::vector<std::byte>& b, std::size_t p, std::uint16_t v) {
    range(b,p,2); b[p]=std::byte(v & 255); b[p+1]=std::byte(v >> 8);
}
inline void put32(std::vector<std::byte>& b, std::size_t p, std::uint32_t v) {
    put16(b,p,static_cast<std::uint16_t>(v)); put16(b,p+2,static_cast<std::uint16_t>(v >> 16));
}
inline bool code_ok(std::string_view s, char last='z') {
    return !s.empty() && s.size()<=4 && std::all_of(s.begin(),s.end(),[last](char c){ return c>='a' && c<=last; });
}
inline void valid_text(std::u16string_view s) {
    need(!s.empty() && s.size() <= (65535-16)/2, "词条为空或超过 lex 单条长度上限");
    for (std::size_t i=0;i<s.size();++i) {
        const auto c=s[i]; need(c>=32 && c!=127, "词条含 NUL 或控制字符");
        if (c>=0xd800 && c<=0xdbff) { need(i+1<s.size() && s[i+1]>=0xdc00 && s[i+1]<=0xdfff,"非法 UTF-16 代理对"); ++i; }
        else need(c<0xdc00 || c>0xdfff,"非法 UTF-16 孤立代理项");
    }
}
inline std::u16string utf16(std::span<const std::byte> b, std::size_t p, std::size_t n) {
    range(b,p,n); need(n%2==0,"UTF-16 字节长度为奇数"); std::u16string s; s.reserve(n/2);
    for (std::size_t i=0;i<n;i+=2) s.push_back(static_cast<char16_t>(u16(b,p+i)));
    return s;
}
Table canonical(const Table&);
void rank_in_order(Table&);
enum class TextDialect { tabular, multicandidate };
struct TextParseResult {
    Table entries;
    TextDialect dialect=TextDialect::tabular;
    std::size_t excluded_dynamic_rows=0;
};
TextParseResult parse_text(std::span<const std::byte>);
}
